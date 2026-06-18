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
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/bearer"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/idp"
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
	auth          *openapi.AuthenticationInfo
	tokenCache    *cache.LRUExpireCache[string, *identityapi.Userinfo]
}

var _ openapi.Authorizer = &Authorizer{}

// NewAuthorizer returns a new authorizer with required parameters.
func NewAuthorizer(client client.Client, options *identityclient.Options, clientOptions *coreclient.HTTPClientOptions, auth *openapi.AuthenticationInfo) (*Authorizer, error) {
	httpClient, err := getIdentityHTTPClient(client, options, clientOptions)
	if err != nil {
		return nil, err
	}

	// The resolver verifies a UNI JWS against the platform issuer's published
	// JWKS, which lives on the identity service. Give that issuer the same
	// CA/mTLS-aware transport we use for userinfo/GetACL so the JWKS can be
	// fetched when identity is behind a private CA; third-party issuers keep the
	// default (public-CA) transport.
	if auth != nil && auth.Resolver() != nil {
		auth.Resolver().SetIssuerTransport(auth.UNIIssuer(), httpClient.Transport)
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

// authorizeOAuth2 authenticates a bearer token. It routes on shape and issuer:
// a JWE is a legacy Unikorn access token (introspected at identity, opaque to
// us); a JWS is verified locally against its issuer's JWKS — fail fast, the
// principal comes from the token — and, when it is one of ours, additionally
// session-checked at identity.
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

	// A legacy Unikorn JWE is opaque to us: introspect it at identity. These age
	// out as sessions rotate to JWS.
	if isJWE {
		return a.authorizeUnikornLegacy(r, rawToken)
	}

	// A JWS carries a readable issuer; verify it locally against that issuer's
	// JWKS and build the principal from the token claims.
	issuer, err := bearer.UnverifiedIssuer(rawToken)
	if err != nil {
		return nil, errors.AccessDenied(r, "unrecognized bearer token format").WithError(err)
	}

	principal, err := a.resolve(r, rawToken)
	if err != nil {
		return nil, err
	}

	// Our own tokens additionally get the session/revocation check at identity:
	// required for (long-lived) service accounts, applied to all UNI tokens for
	// now. External tokens carry no UNI session.
	if issuer == a.auth.UNIIssuer() {
		if err := a.checkSession(r, rawToken); err != nil {
			return nil, err
		}
	}

	return openapi.InfoFromPrincipal(rawToken, principal), nil
}

// resolve verifies a JWS locally against the trusted issuer's JWKS and maps it
// to a principal, failing fast (no network call) on a bad signature, an
// untrusted issuer, or invalid claims.
func (a *Authorizer) resolve(r *http.Request, token string) (*idp.Principal, error) {
	if a.auth == nil || a.auth.Resolver() == nil {
		return nil, errors.AccessDenied(r, "no trusted token issuers are configured")
	}

	principal, err := a.auth.Resolver().Resolve(r.Context(), token)
	if err != nil {
		return nil, errors.AccessDenied(r, "token validation failed").WithError(err)
	}

	return principal, nil
}

// infoFromUserinfo builds the authentication identity from a legacy JWE's
// userinfo introspection. The token is opaque to us, so unlike the JWS path —
// where the account type comes from the verified token claims — the type is read
// from identity's introspection response (the only channel that can recover it).
// An introspection with no account type is rejected rather than defaulted: the
// account type is always definite by the time it reaches a handler.
func (a *Authorizer) infoFromUserinfo(r *http.Request, token string, userinfo *identityapi.Userinfo) (*authorization.Info, error) {
	if userinfo.Acctype == nil {
		return nil, errors.AccessDenied(r, "token introspection returned no account type")
	}

	p := &principal.Principal{
		Subject: userinfo.Sub,
		Type:    *userinfo.Acctype,
		// A JWE is UNI by construction and introspection cannot return `iss`, so
		// the issuer is the platform issuer.
		Issuer: a.auth.UNIIssuer(),
	}

	return &authorization.Info{Principal: p, Token: token}, nil
}

// checkSession confirms a Unikorn token is a live, un-revoked session by
// introspecting it at identity's userinfo endpoint (cached, fails closed). The
// principal is already established locally from the token; this is purely the
// session/revocation gate (required for long-lived service accounts).
func (a *Authorizer) checkSession(r *http.Request, token string) error {
	if _, ok := a.tokenCache.Get(token); ok {
		return nil
	}

	userinfo, err := a.fetchUserinfo(r, token)
	if err != nil {
		return err
	}

	a.tokenCache.Add(token, userinfo, userinfoCacheTTL)

	return nil
}

// authorizeUnikornLegacy resolves a legacy Unikorn JWE access token via the
// identity userinfo endpoint. The result is cached for a short staleness budget
// because the call is a network round-trip plus a JWE decrypt at identity; the
// path fails closed once the entry expires.
func (a *Authorizer) authorizeUnikornLegacy(r *http.Request, token string) (*authorization.Info, error) {
	if userinfo, ok := a.tokenCache.Get(token); ok {
		return a.infoFromUserinfo(r, token, userinfo)
	}

	userinfo, err := a.fetchUserinfo(r, token)
	if err != nil {
		return nil, err
	}

	a.tokenCache.Add(token, userinfo, userinfoCacheTTL)

	return a.infoFromUserinfo(r, token, userinfo)
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
