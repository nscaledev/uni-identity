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
	goerrors "errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/util/cache"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	tokenCacheSize = 4096

	// cacheTTLFudge absorbs clock skew between identity and this middleware
	// when deriving cache TTLs from passport expiry.
	cacheTTLFudge = 10 * time.Second
)

// Authorizer provides OpenAPI based authorization middleware backed by remote
// identity token exchange and ACL lookup.
type Authorizer struct {
	client        client.Client
	options       *identityclient.Options
	clientOptions *coreclient.HTTPClientOptions
	httpClient    *http.Client
	exchange      TokenExchange
	tokenCache    *cache.LRUExpireCache[tokenCacheKey, *oauth2.PassportClaims]
}

var _ openapi.Authorizer = &Authorizer{}

type tokenCacheKey struct {
	sourceToken    string
	organizationID string
	projectID      string
}

func newTokenCacheKey(sourceToken string, scope tokenExchangeOptions) tokenCacheKey {
	return tokenCacheKey{
		sourceToken:    sourceToken,
		organizationID: scope.organizationID,
		projectID:      scope.projectID,
	}
}

// NewAuthorizer returns a new authorizer with required parameters.
func NewAuthorizer(client client.Client, options *identityclient.Options, clientOptions *coreclient.HTTPClientOptions) (*Authorizer, error) {
	httpClient, err := getIdentityHTTPClient(client, options, clientOptions)
	if err != nil {
		return nil, err
	}

	tokenCache := cache.NewLRUExpireCache[tokenCacheKey, *oauth2.PassportClaims](tokenCacheSize)

	a := &Authorizer{
		httpClient:    httpClient,
		client:        client,
		options:       options,
		clientOptions: clientOptions,
		exchange:      NewHTTPTokenExchange(httpClient, TokenExchangeURL(options.Host())),
		tokenCache:    tokenCache,
	}

	return a, nil
}

func getHTTPAuthenticationScheme(r *http.Request) (string, string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", "", errors.AccessDenied(r, "authorization header missing")
	}

	parts := strings.Split(header, " ")
	if len(parts) != 2 {
		return "", "", errors.AccessDenied(r, "authorization header malformed")
	}

	return parts[0], parts[1], nil
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

// authorizeOAuth2 resolves a bearer token into the Userinfo-compatible
// identity shape consumed by handlers.
func (a *Authorizer) authorizeOAuth2(r *http.Request, scope tokenExchangeOptions) (*authorization.Info, error) {
	ctx := r.Context()

	authorizationScheme, rawToken, err := getHTTPAuthenticationScheme(r)
	if err != nil {
		return nil, err
	}

	if !strings.EqualFold(authorizationScheme, "bearer") {
		return nil, errors.AccessDenied(r, "authorization scheme not allowed").WithValues("scheme", authorizationScheme)
	}

	cacheKey := newTokenCacheKey(rawToken, scope)
	if claims, ok := a.tokenCache.Get(cacheKey); ok {
		return &authorization.Info{
			Token:    rawToken,
			Userinfo: passportToUserinfo(claims),
		}, nil
	}

	exchangeOptions := scope

	passport, err := a.exchange.Exchange(ctx, rawToken, &exchangeOptions)
	if err != nil {
		if goerrors.Is(err, ErrTokenExchangeUnauthorized) {
			return nil, errors.AccessDenied(r, "token is invalid or has expired")
		}

		// Scope refusal is authz; surface as 403 so callers do not retry
		// as if the token had expired.
		if goerrors.Is(err, ErrTokenExchangeForbidden) {
			return nil, errors.HTTPForbidden("not authorized for the requested scope")
		}

		return nil, errors.AccessDenied(r, "token exchange failed").WithError(err)
	}

	claims, err := decodePassportClaims(passport)
	if err != nil {
		// A malformed passport after a successful exchange is identity/middleware
		// producing invalid output, not a user authorization decision. Surface it
		// as a plain wrapped error so the top-level handler renders a 500.
		return nil, fmt.Errorf("failed to decode exchange passport: %w", err)
	}

	userinfo := passportToUserinfo(claims)

	if ttl := cacheTTL(claims, time.Now()); ttl > 0 {
		a.tokenCache.Add(cacheKey, claims, ttl)
	}

	return &authorization.Info{
		Token:    rawToken,
		Userinfo: userinfo,
	}, nil
}

// decodePassportClaims parses exchange output and enforces the identity claims
// needed to build authorization context.
//
// UnsafeClaimsWithoutVerification is intentional: the passport is consumed as
// exchange output over the trusted identity service channel, not accepted as
// an independently presented bearer credential, so downstream JWKS verification
// would only re-prove what the transport already guarantees. The structural and
// temporal checks below still apply because identity may legitimately produce
// claims this middleware cannot use.
func decodePassportClaims(passport string) (*oauth2.PassportClaims, error) {
	token, err := jwt.ParseSigned(passport, []jose.SignatureAlgorithm{jose.ES512})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPassportInvalid, err)
	}

	claims := &oauth2.PassportClaims{}
	if err := token.UnsafeClaimsWithoutVerification(claims); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPassportInvalid, err)
	}

	if claims.Type != oauth2.PassportType {
		return nil, fmt.Errorf("%w: unexpected token type %q", ErrPassportInvalid, claims.Type)
	}

	if claims.Subject == "" || claims.Expiry == nil {
		return nil, fmt.Errorf("%w: passport missing required claims", ErrPassportInvalid)
	}

	// Acctype selects RBAC behavior; source preserves the token-family audit trail.
	if claims.Acctype == "" || claims.Source == "" {
		return nil, fmt.Errorf("%w: passport missing required identity metadata", ErrPassportInvalid)
	}

	if err := validatePassportTemporalClaims(claims, time.Now()); err != nil {
		return nil, err
	}

	return claims, nil
}

// validatePassportTemporalClaims rejects both stale and premature exchange
// output. exp ≤ now and nbf > now must both fail closed.
func validatePassportTemporalClaims(claims *oauth2.PassportClaims, now time.Time) error {
	if !claims.Expiry.Time().After(now) {
		return fmt.Errorf("%w: passport has expired", ErrPassportInvalid)
	}

	if claims.NotBefore != nil && claims.NotBefore.Time().After(now) {
		return fmt.Errorf("%w: passport is not yet valid", ErrPassportInvalid)
	}

	return nil
}

// passportToUserinfo projects passport claims onto the existing handler-facing
// identity shape.
func passportToUserinfo(claims *oauth2.PassportClaims) *identityapi.Userinfo {
	userinfo := &identityapi.Userinfo{
		Sub: claims.Subject,
		HttpsunikornCloudOrgauthz: &identityapi.AuthClaims{
			Acctype: claims.Acctype,
			OrgIds:  claims.OrgIDs,
		},
	}

	if claims.Email != "" {
		email := claims.Email
		userinfo.Email = &email
	}

	return userinfo
}

// cacheTTL keeps cached identity within the passport expiry set by identity,
// leaving a small margin for clock skew.
func cacheTTL(claims *oauth2.PassportClaims, now time.Time) time.Duration {
	return claims.Expiry.Time().Sub(now) - cacheTTLFudge
}

// Authorize checks the request against the OpenAPI security scheme.
func (a *Authorizer) Authorize(authentication *openapi3filter.AuthenticationInput) (*authorization.Info, error) {
	if authentication.SecurityScheme.Type == "oauth2" {
		return a.authorizeOAuth2(authentication.RequestValidationInput.Request, scopeFromPathParams(authentication.RequestValidationInput.PathParams))
	}

	return nil, errors.OAuth2InvalidRequest("authorization scheme unsupported").WithValues("scheme", authentication.SecurityScheme.Type)
}

func scopeFromPathParams(params map[string]string) tokenExchangeOptions {
	return tokenExchangeOptions{
		organizationID: params["organizationID"],
		projectID:      params["projectID"],
	}
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
		identityapi.WithRequestEditorFn(principal.Injector(a.client, a.clientOptions)),
	}

	if info.Token != "" {
		options = append(options, identityapi.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "bearer "+info.Token)

			return nil
		}))
	}

	client, err := identityapi.NewClientWithResponses(a.options.Host(), options...)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create identity client", err)
	}

	if organizationID == "" {
		response, err := client.GetApiV1AclWithResponse(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to perform ACL get call", err)
		}

		if response.StatusCode() != http.StatusOK {
			return nil, errors.PropagateError(response.HTTPResponse, response)
		}

		return response.JSON200, nil
	}

	response, err := client.GetApiV1OrganizationsOrganizationIDAclWithResponse(ctx, organizationID)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to perform ACL get call", err)
	}

	if response.StatusCode() != http.StatusOK {
		return nil, errors.PropagateError(response.HTTPResponse, response)
	}

	return response.JSON200, nil
}
