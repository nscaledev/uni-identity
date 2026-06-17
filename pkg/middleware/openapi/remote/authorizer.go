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
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/util/cache"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/oauth2/bearer"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	tokenCacheSize = 4096

	// userinfoCacheTTL bounds how long a Unikorn-token userinfo result is
	// trusted without re-checking. The userinfo call is the service-token
	// revocation point, so this is the staleness budget: a revoked or expired
	// token continues to authenticate from cache for at most this long. It is
	// short for that reason, and the path fails closed — once the entry
	// expires, a request cannot proceed unless identity confirms the token
	// afresh. The third-party (local JWKS) path is not cached at all; it is a
	// cheap local check run on every request.
	userinfoCacheTTL = 60 * time.Second
)

// Authorizer provides OpenAPI based authorization middleware. It authenticates
// bearer tokens locally — third-party (Auth0) tokens against the issuer JWKS,
// and Unikorn-issued tokens via the identity userinfo endpoint — and resolves
// ACLs back from identity.
type Authorizer struct {
	client        client.Client
	options       *identityclient.Options
	clientOptions *coreclient.HTTPClientOptions
	httpClient    *http.Client
	auth          *AuthenticationInfo
	tokenCache    *cache.LRUExpireCache[string, *identityapi.Userinfo]
}

var _ openapi.Authorizer = &Authorizer{}

// NewAuthorizer returns a new authorizer with required parameters.
func NewAuthorizer(client client.Client, options *identityclient.Options, clientOptions *coreclient.HTTPClientOptions, auth *AuthenticationInfo) (*Authorizer, error) {
	httpClient, err := getIdentityHTTPClient(client, options, clientOptions)
	if err != nil {
		return nil, err
	}

	a := &Authorizer{
		httpClient:    httpClient,
		client:        client,
		options:       options,
		clientOptions: clientOptions,
		auth:          auth,
		tokenCache:    cache.NewLRUExpireCache[string, *identityapi.Userinfo](tokenCacheSize),
	}

	return a, nil
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

	identity := identityclient.New(client, options, clientOptions)

	baseClient, err := identity.HTTPClient(ctx)
	if err != nil {
		return nil, err
	}

	mutator := func(req *http.Request) error {
		if err := identityclient.TraceContextRequestMutator(req.Context(), req); err != nil {
			return err
		}

		if err := identityclient.CertificateRequestMutator(req.Context(), req); err != nil {
			return err
		}

		return nil
	}

	httpClient := &http.Client{
		Transport: &requestMutatingTransport{
			base:    baseClient.Transport,
			mutator: mutator,
		},
	}

	return httpClient, nil
}

// authorizeOAuth2 resolves a bearer token into the Userinfo-compatible identity
// shape consumed by handlers. It authenticates the token locally, routing on
// the JOSE header: a JWS is a third-party (Auth0) access token validated
// against the issuer JWKS, and a JWE is a Unikorn access token resolved via the
// identity userinfo endpoint. A bearer that is neither is rejected.
func (a *Authorizer) authorizeOAuth2(r *http.Request) (*authorization.Info, error) {
	authorizationScheme, rawToken, err := authorization.GetHTTPAuthenticationScheme(r)
	if err != nil {
		return nil, err
	}

	if !strings.EqualFold(authorizationScheme, "bearer") {
		return nil, errors.AccessDenied(r, "authorization scheme not allowed").WithValues("scheme", authorizationScheme)
	}

	isJWE, err := bearer.IsJWE(rawToken)
	if err != nil {
		return nil, errors.AccessDenied(r, "unrecognized bearer token format").WithError(err)
	}

	// A JWS is a third-party access token: validate it fully locally against
	// the issuer JWKS when a third-party IdP is configured. When it is not, a
	// JWS falls through to the Unikorn userinfo path, which rejects it — a
	// Unikorn access token is a JWE.
	if !isJWE && a.auth != nil && a.auth.thirdParty != nil {
		return a.authorizeThirdParty(r, rawToken)
	}

	return a.authorizeUnikorn(r, rawToken)
}

// authorizeThirdParty validates a federated user token locally and projects it
// onto the handler-facing identity shape. Authentication yields the subject
// only: organisation membership and RBAC are resolved later against our own
// graph via GetACL, never read from the foreign token, so no OrgIds are set
// here.
func (a *Authorizer) authorizeThirdParty(r *http.Request, token string) (*authorization.Info, error) {
	user, err := a.auth.thirdParty.Validate(r.Context(), token)
	if err != nil {
		return nil, errors.AccessDenied(r, "token validation failed").WithError(err)
	}

	verified := true
	email := user.Email

	return &authorization.Info{
		Token: token,
		Userinfo: &identityapi.Userinfo{
			Sub:           user.Email,
			Email:         &email,
			EmailVerified: &verified,
			HttpsunikornCloudOrgauthz: &identityapi.AuthClaims{
				Acctype: identityapi.User,
			},
		},
	}, nil
}

// authorizeUnikorn resolves a Unikorn-issued token (user or service account)
// via the identity userinfo endpoint. The result is cached for a short
// staleness budget because the call is a network round-trip plus a JWE decrypt
// at identity; the path fails closed once the entry expires.
func (a *Authorizer) authorizeUnikorn(r *http.Request, token string) (*authorization.Info, error) {
	if userinfo, ok := a.tokenCache.Get(token); ok {
		return &authorization.Info{
			Token:    token,
			Userinfo: userinfo,
		}, nil
	}

	userinfo, err := a.fetchUserinfo(r, token)
	if err != nil {
		return nil, err
	}

	a.tokenCache.Add(token, userinfo, userinfoCacheTTL)

	return &authorization.Info{
		Token:    token,
		Userinfo: userinfo,
	}, nil
}

// fetchUserinfo introspects a Unikorn token at the identity userinfo endpoint.
// It fails closed: any non-200 outcome, including transport failure, denies the
// request rather than letting it through on an ambiguous response.
func (a *Authorizer) fetchUserinfo(r *http.Request, token string) (*identityapi.Userinfo, error) {
	ctx := r.Context()

	options := []identityapi.ClientOption{
		identityapi.WithHTTPClient(a.httpClient),
		identityapi.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "bearer "+token)

			return nil
		}),
	}

	rawClient, err := identityapi.NewClientWithResponses(a.options.Host(), options...)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create identity client", err)
	}

	response, err := rawClient.GetOauth2V2UserinfoWithResponse(ctx)
	if err != nil {
		// A transport or upstream failure must not let the request through.
		return nil, errors.AccessDenied(r, "token validation unavailable").WithError(err)
	}

	if response.StatusCode() != http.StatusOK {
		return nil, errors.AccessDenied(r, "token is invalid or has expired").WithValues("status", response.StatusCode())
	}

	return response.JSON200, nil
}

// Authorize checks the request against the OpenAPI security scheme.
func (a *Authorizer) Authorize(authentication *openapi3filter.AuthenticationInput) (*authorization.Info, error) {
	if authentication.SecurityScheme.Type == "oauth2" {
		return a.authorizeOAuth2(authentication.RequestValidationInput.Request)
	}

	return nil, errors.OAuth2InvalidRequest("authorization scheme unsupported").WithValues("scheme", authentication.SecurityScheme.Type)
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
		identityapi.WithRequestEditorFn(principal.Injector(a.client, a.clientOptions)),
	}

	if info.Token != "" {
		options = append(options, identityapi.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "bearer "+info.Token)

			return nil
		}))
	}

	rawClient, err := identityapi.NewClientWithResponses(a.options.Host(), options...)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create identity client", err)
	}

	if organizationID == "" {
		response, err := rawClient.GetApiV1AclWithResponse(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to perform ACL get call", err)
		}

		if response.StatusCode() != http.StatusOK {
			return nil, errors.PropagateError(response.HTTPResponse, response)
		}

		return response.JSON200, nil
	}

	orgID, err := ids.ParseOrganizationID(organizationID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid organization ID %q", err, organizationID)
	}

	response, err := rawClient.GetApiV1OrganizationsOrganizationIDAclWithResponse(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to perform ACL get call", err)
	}

	if response.StatusCode() != http.StatusOK {
		return nil, errors.PropagateError(response.HTTPResponse, response)
	}

	return response.JSON200, nil
}
