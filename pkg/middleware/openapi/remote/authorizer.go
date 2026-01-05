/*
Copyright 2022-2024 EscherCloud.
Copyright 2024-2025 the Unikorn Authors.
Copyright 2026 Nscale.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package authorizer

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/getkin/kin-openapi/openapi3filter"
	"golang.org/x/oauth2"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"

	"k8s.io/apimachinery/pkg/util/cache"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Authorizer provides OpenAPI based authorization middleware.
type Authorizer struct {
	client        client.Client
	options       *identityclient.Options
	clientOptions *coreclient.HTTPClientOptions
	httpClient    *http.Client
	// tokenCache is used to enhance interaction as the validation is a
	// very expensive operation.
	tokenCache *cache.LRUExpireCache
}

var _ openapi.Authorizer = &Authorizer{}

// NewAuthorizer returns a new authorizer with required parameters.
func NewAuthorizer(client client.Client, options *identityclient.Options, clientOptions *coreclient.HTTPClientOptions) (*Authorizer, error) {
	httpClient, err := getIdentityHTTPClient(client, options, clientOptions)
	if err != nil {
		return nil, err
	}

	a := &Authorizer{
		httpClient:    httpClient,
		client:        client,
		options:       options,
		clientOptions: clientOptions,
		// TODO: make this configurable, possibly even a shared flag with the
		// authorizer to maintain consistency.
		tokenCache: cache.NewLRUExpireCache(4096),
	}

	return a, nil
}

// getHTTPAuthenticationScheme grabs the scheme and token from the HTTP
// Authorization header.
func getHTTPAuthenticationScheme(r *http.Request) (string, string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", "", errors.OAuth2InvalidRequest("authorization header missing")
	}

	parts := strings.Split(header, " ")
	if len(parts) != 2 {
		return "", "", errors.OAuth2InvalidRequest("authorization header malformed")
	}

	return parts[0], parts[1], nil
}

// oidcErrorIsUnauthorized tries to convert the error returned by the OIDC library
// into a proper status code, as it doesn't wrap anything useful.
// The error looks like "{code} {text code}: {body}".
func oidcErrorIsUnauthorized(err error) bool {
	// Does it look like it contains the colon?
	fields := strings.Split(err.Error(), ":")
	if len(fields) < 2 {
		return false
	}

	// What about a number followed by a string?
	fields = strings.Split(fields[0], " ")
	if len(fields) < 2 {
		return false
	}

	code, err := strconv.Atoi(fields[0])
	if err != nil {
		return false
	}

	// Is the number a 403?
	return code == http.StatusUnauthorized
}

type requestMutatingTransport struct {
	base    http.RoundTripper
	mutator func(r *http.Request) error
}

func (t *requestMutatingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.mutator(req); err != nil {
		return nil, err
	}

	return t.base.RoundTrip(req)
}

// getIdentityHTTPClient returns a raw HTTP client for the identity service
// that handles TLS, trace context and client certificate propagation.
func getIdentityHTTPClient(client client.Client, options *identityclient.Options, clientOptions *coreclient.HTTPClientOptions) (*http.Client, error) {
	ctx := context.TODO()

	// The identity client neatly wraps up TLS...
	identity := identityclient.New(client, options, clientOptions)

	baseClient, err := identity.HTTPClient(ctx)
	if err != nil {
		return nil, err
	}

	// Whe need to mutate the request to do trace context propagation and
	// client certificate propagation if it's a token bound to an X.509
	// certificate.
	mutator := func(req *http.Request) error {
		if err := identityclient.TraceContextRequestMutator(req.Context(), req); err != nil {
			return err
		}

		if err := identityclient.CertificateRequestMutator(req.Context(), req); err != nil {
			return err
		}

		return nil
	}

	// But it doesn't do request mutation, so we have to slightly hack it by
	// making a nested transport.
	httpClient := &http.Client{
		Transport: &requestMutatingTransport{
			base:    baseClient.Transport,
			mutator: mutator,
		},
	}

	return httpClient, nil
}

// authorizeOAuth2 checks APIs that require and oauth2 bearer token.
func (a *Authorizer) authorizeOAuth2(r *http.Request) (*authorization.Info, error) {
	ctx := r.Context()

	authorizationScheme, rawToken, err := getHTTPAuthenticationScheme(r)
	if err != nil {
		return nil, err
	}

	if !strings.EqualFold(authorizationScheme, "bearer") {
		return nil, errors.OAuth2InvalidRequest("authorization scheme not allowed").WithValues("scheme", authorizationScheme)
	}

	if value, ok := a.tokenCache.Get(rawToken); ok {
		claims, ok := value.(*identityapi.Userinfo)
		if !ok {
			return nil, errors.OAuth2ServerError("invalid token cache data")
		}

		info := &authorization.Info{
			Token:    rawToken,
			Userinfo: claims,
		}

		return info, nil
	}

	ctx = oidc.ClientContext(ctx, a.httpClient)

	// Perform userinfo call against the identity service that will validate the token
	// and also return some information about the user that we can use for audit logging.
	provider, err := oidc.NewProvider(ctx, a.options.Host())
	if err != nil {
		return nil, errors.OAuth2ServerError("oidc service discovery failed").WithError(err)
	}

	token := &oauth2.Token{
		AccessToken: rawToken,
		TokenType:   authorizationScheme,
	}

	ui, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		if oidcErrorIsUnauthorized(err) {
			return nil, errors.OAuth2AccessDenied("token validation failed").WithError(err)
		}

		return nil, err
	}

	claims := &identityapi.Userinfo{}

	if err := ui.Claims(claims); err != nil {
		return nil, errors.OAuth2ServerError("failed to extrac user information").WithError(err)
	}

	// The cache entry needs a timeout as a federated user may have had their rights
	// recinded and we don't know about it, and long lived tokens e.g. service accounts,
	// could still be valid for months...
	a.tokenCache.Add(rawToken, claims, time.Hour)

	out := &authorization.Info{
		Token:    rawToken,
		Userinfo: claims,
	}

	return out, nil
}

// Authorize checks the request against the OpenAPI security scheme.
func (a *Authorizer) Authorize(authentication *openapi3filter.AuthenticationInput) (*authorization.Info, error) {
	if authentication.SecurityScheme.Type == "oauth2" {
		return a.authorizeOAuth2(authentication.RequestValidationInput.Request)
	}

	return nil, errors.OAuth2InvalidRequest("authorization scheme unsupported").WithValues("scheme", authentication.SecurityScheme.Type)
}

type Getter string

func (a Getter) Get(_ context.Context) (string, error) {
	return string(a), nil
}

// GetACL retrieves access control information from the subject identified
// by the Authorize call.
func (a *Authorizer) GetACL(ctx context.Context, organizationID string) (*identityapi.Acl, error) {
	info, err := authorization.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Trace context and TLS are handled by the cached client.
	// TODO: a nicer way to inject a token per call would be prefereable.
	options := []identityapi.ClientOption{
		identityapi.WithHTTPClient(a.httpClient),
		identityapi.WithRequestEditorFn(identityclient.AccessTokenRequestMutator(Getter(info.Token))),
		identityapi.WithRequestEditorFn(principal.Injector(a.client, a.clientOptions)),
	}

	client, err := identityapi.NewClientWithResponses(a.options.Host(), options...)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create identity client").WithError(err)
	}

	if organizationID == "" {
		response, err := client.GetApiV1AclWithResponse(ctx)
		if err != nil {
			return nil, errors.OAuth2ServerError("failed to perform ACL get call").WithError(err)
		}

		if response.StatusCode() != http.StatusOK {
			return nil, errors.OAuth2ServerError("ACL get call didn't succeed")
		}

		return response.JSON200, nil
	}

	response, err := client.GetApiV1OrganizationsOrganizationIDAclWithResponse(ctx, organizationID)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to perform ACL get call").WithError(err)
	}

	if response.StatusCode() != http.StatusOK {
		return nil, errors.OAuth2ServerError("ACL get call didn't succeed")
	}

	return response.JSON200, nil
}
