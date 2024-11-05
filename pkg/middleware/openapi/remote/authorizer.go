/*
Copyright 2022-2024 EscherCloud.
Copyright 2024 the Unikorn Authors.

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
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/accesstoken"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"

	"k8s.io/apimachinery/pkg/util/cache"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Authorizer provides OpenAPI based authorization middleware.
type Authorizer struct {
	client        client.Client
	options       *identityclient.Options
	clientOptions *coreclient.HTTPClientOptions
	// tokenCache is used to enhance interaction as the validation is a
	// very expensive operation.
	tokenCache *cache.LRUExpireCache
}

var _ openapi.Authorizer = &Authorizer{}

// NewAuthorizer returns a new authorizer with required parameters.
func NewAuthorizer(client client.Client, options *identityclient.Options, clientOptions *coreclient.HTTPClientOptions) *Authorizer {
	return &Authorizer{
		client:        client,
		options:       options,
		clientOptions: clientOptions,
		// TODO: make this configurable, possibly even a shared flag with the
		// authorizer to maintain consistency.
		tokenCache: cache.NewLRUExpireCache(4096),
	}
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

// authorizeOAuth2 checks APIs that require and oauth2 bearer token.
func (a *Authorizer) authorizeOAuth2(r *http.Request) (string, *identityapi.Userinfo, error) {
	ctx := r.Context()

	authorizationScheme, rawToken, err := getHTTPAuthenticationScheme(r)
	if err != nil {
		return "", nil, err
	}

	if !strings.EqualFold(authorizationScheme, "bearer") {
		return "", nil, errors.OAuth2InvalidRequest("authorization scheme not allowed").WithValues("scheme", authorizationScheme)
	}

	if value, ok := a.tokenCache.Get(rawToken); ok {
		claims, ok := value.(*identityapi.Userinfo)
		if !ok {
			return "", nil, errors.OAuth2ServerError("invalid token cache data")
		}

		return rawToken, claims, nil
	}

	// The identity client neatly wraps up TLS...
	identity := identityclient.New(a.client, a.options, a.clientOptions)

	client, err := identity.HTTPClient(ctx)
	if err != nil {
		return "", nil, err
	}

	// NOTE: The mutation is required to do trace context propagation.
	mutator := func(req *http.Request) error {
		mutator := identityclient.RequestMutator(nil)

		return mutator(ctx, req)
	}

	// But it doesn't do request mutation, so we have to slightly hack it by
	// making a nested transport.
	client = &http.Client{
		Transport: &requestMutatingTransport{
			base:    client.Transport,
			mutator: mutator,
		},
	}

	ctx = oidc.ClientContext(ctx, client)

	// Perform userinfo call against the identity service that will validate the token
	// and also return some information about the user that we can use for audit logging.
	provider, err := oidc.NewProvider(ctx, a.options.Host())
	if err != nil {
		return "", nil, errors.OAuth2ServerError("oidc service discovery failed").WithError(err)
	}

	token := &oauth2.Token{
		AccessToken: rawToken,
		TokenType:   authorizationScheme,
	}

	ui, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		if oidcErrorIsUnauthorized(err) {
			return "", nil, errors.OAuth2AccessDenied("token validation failed").WithError(err)
		}

		return "", nil, err
	}

	claims := &identityapi.Userinfo{}

	if err := ui.Claims(claims); err != nil {
		return "", nil, errors.OAuth2ServerError("failed to extrac user information").WithError(err)
	}

	a.tokenCache.Add(rawToken, claims, time.Until(time.Unix(int64(*claims.Exp), 0)))

	return rawToken, claims, nil
}

// Authorize checks the request against the OpenAPI security scheme.
func (a *Authorizer) Authorize(authentication *openapi3filter.AuthenticationInput) (string, *identityapi.Userinfo, error) {
	if authentication.SecurityScheme.Type == "oauth2" {
		return a.authorizeOAuth2(authentication.RequestValidationInput.Request)
	}

	return "", nil, errors.OAuth2InvalidRequest("authorization scheme unsupported").WithValues("scheme", authentication.SecurityScheme.Type)
}

// GetACL retrieves access control information from the subject identified
// by the Authorize call.
func (a *Authorizer) GetACL(ctx context.Context, organizationID, subject string) (*identityapi.Acl, error) {
	accessToken, err := accesstoken.NewGetter(ctx)
	if err != nil {
		return nil, err
	}

	client, err := identityclient.New(a.client, a.options, a.clientOptions).Client(ctx, accessToken)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to create identity client").WithError(err)
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
