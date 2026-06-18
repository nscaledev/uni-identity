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

package local

import (
	"context"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3filter"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	middleware "github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/bearer"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// Authorizer provides OpenAPI based authorization middleware for the identity
// service itself. It authenticates bearer tokens in-process — Unikorn-issued
// tokens (a JWS verified against our in-cluster keys, or a legacy JWE decrypted
// in-process) and third-party tokens (a JWS verified against the issuer JWKS) —
// and resolves ACLs directly against rbac. The principal (subject + account
// type) comes from the verified token; organization membership is resolved by
// rbac.
type Authorizer struct {
	authenticator *oauth2.Authenticator
	rbac          *rbac.RBAC
	auth          *middleware.AuthenticationInfo

	// unroutableTokens counts bearer tokens that are neither a UNI access token
	// (JWE) nor a JWS from a trusted issuer, e.g. after an upstream token-format
	// change or a token from an unconfigured issuer.
	unroutableTokens metric.Int64Counter
}

var _ middleware.Authorizer = &Authorizer{}

// NewAuthorizer returns a new authorizer with required parameters.
func NewAuthorizer(authenticator *oauth2.Authenticator, rbac *rbac.RBAC, auth *middleware.AuthenticationInfo) *Authorizer {
	// The error only reports an invalid instrument configuration; the API
	// returns a usable no-op counter regardless, so there is nothing actionable
	// to handle.
	unroutableTokens, _ := otel.Meter(constants.Application).Int64Counter(
		"unikorn_identity_bearer_tokens_unroutable",
		metric.WithDescription("Bearer tokens that are neither a UNI access token (JWE) nor a JWS."),
		metric.WithUnit("{token}"),
	)

	return &Authorizer{
		authenticator:    authenticator,
		rbac:             rbac,
		auth:             auth,
		unroutableTokens: unroutableTokens,
	}
}

// authorizeOAuth2 authenticates an oauth2 bearer token. It routes on shape and
// issuer: a JWE is a legacy Unikorn access token, decrypted in-process; a JWS is
// routed on its (unverified) issuer — one of ours is verified against our
// in-cluster keys, a trusted third-party issuer against its JWKS via the
// resolver. A token that is neither, or one from an unconfigured issuer, is
// rejected and counted.
func (a *Authorizer) authorizeOAuth2(r *http.Request) (*authorization.Info, error) {
	authorizationScheme, token, err := authorization.GetHTTPAuthenticationScheme(r)
	if err != nil {
		return nil, err
	}

	if !strings.EqualFold(authorizationScheme, "bearer") {
		return nil, errors.AccessDenied(r, "authorization scheme not allowed").WithValues("scheme", authorizationScheme)
	}

	isJWE, err := bearer.IsJWE(token)
	if err != nil {
		a.unroutableTokens.Add(r.Context(), 1)

		return nil, errors.AccessDenied(r, "unrecognized bearer token format").WithError(err)
	}

	// A legacy Unikorn JWE is opaque and ours by construction: decrypt and verify
	// it in-process. These age out as sessions rotate to JWS.
	if isJWE {
		return a.authorizeUnikorn(r, token)
	}

	issuer, err := bearer.UnverifiedIssuer(token)
	if err != nil {
		a.unroutableTokens.Add(r.Context(), 1)

		return nil, errors.AccessDenied(r, "unrecognized bearer token format").WithError(err)
	}

	// Our own JWS: verify against our in-cluster keys (and the session check).
	if a.auth != nil && issuer == a.auth.UNIIssuer() {
		return a.authorizeUnikorn(r, token)
	}

	// A JWS from a configured third-party issuer: verify against its JWKS.
	if a.auth != nil && a.auth.Resolver().Trusts(issuer) {
		return a.authorizeThirdParty(r, token)
	}

	a.unroutableTokens.Add(r.Context(), 1)

	return nil, errors.AccessDenied(r, "bearer token issuer is not trusted").WithValues("issuer", issuer)
}

// authorizeThirdParty verifies a third-party JWS locally against its issuer's
// JWKS and maps it to a principal via that issuer's claim transform. It carries
// identity only; organization membership and RBAC are resolved by rbac from the
// subject, never read from the foreign token.
func (a *Authorizer) authorizeThirdParty(r *http.Request, token string) (*authorization.Info, error) {
	p, err := a.auth.Resolver().Resolve(r.Context(), token)
	if err != nil {
		return nil, errors.AccessDenied(r, "token validation failed").WithError(err)
	}

	return middleware.InfoFromPrincipal(token, p), nil
}

// authorizeUnikorn resolves a Unikorn-issued token (user or service account) by
// in-process verification — a JWS against our in-cluster keys, a legacy JWE by
// decryption — including the live-session check. The principal comes from the
// verified token claims.
func (a *Authorizer) authorizeUnikorn(r *http.Request, token string) (*authorization.Info, error) {
	claims, err := a.authenticator.VerifyAccessToken(r.Context(), r, token)
	if err != nil {
		return nil, err
	}

	p := &principal.Principal{Subject: claims.Subject, Issuer: claims.Issuer}

	switch claims.Type {
	case oauth2.TokenTypeFederated:
		p.Type = openapi.User
	case oauth2.TokenTypeServiceAccount:
		p.Type = openapi.Service
	default:
		return nil, errors.AccessDenied(r, "token has an unrecognised account type").WithValues("type", string(claims.Type))
	}

	return &authorization.Info{Principal: p, Token: token}, nil
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
func (a *Authorizer) GetACL(ctx context.Context, organizationID string) (*openapi.Acl, error) {
	return a.rbac.GetACL(ctx, organizationID)
}
