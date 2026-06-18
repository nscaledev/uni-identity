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
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// Authorizer provides OpenAPI based authorization middleware for the identity
// service itself. It authenticates bearer tokens in-process — third-party
// (Auth0) tokens against the issuer JWKS, Unikorn-issued tokens by local
// decryption — and resolves ACLs directly against rbac. It produces a subject
// and account type only; organization membership is resolved by rbac.
type Authorizer struct {
	authenticator *oauth2.Authenticator
	rbac          *rbac.RBAC
	auth          *middleware.AuthenticationInfo

	// unroutableTokens counts bearer tokens that are neither a UNI access token
	// (JWE) nor a JWS, e.g. after an upstream token-format change.
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

// authorizeOAuth2 authenticates an oauth2 bearer token, routing on the JOSE
// header: a JWS is a third-party (Auth0) access token validated locally against
// the issuer JWKS; a JWE is a Unikorn access token decrypted in-process. A
// bearer that is neither is rejected and counted.
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

	// A JWS is a third-party access token: validate it locally against the
	// issuer JWKS when a third-party IdP is configured. Without one, a JWS falls
	// through to the UNI path, which rejects it (a UNI token is a JWE).
	if !isJWE && a.auth != nil && a.auth.ThirdParty() != nil {
		return a.authorizeThirdParty(r, token)
	}

	return a.authorizeUnikorn(r, token)
}

// authorizeThirdParty validates a federated user token locally. It yields the
// subject only; organization membership and RBAC are resolved by rbac from the
// subject, never read from the foreign token.
func (a *Authorizer) authorizeThirdParty(r *http.Request, token string) (*authorization.Info, error) {
	user, err := a.auth.ThirdParty().Validate(r.Context(), token)
	if err != nil {
		return nil, errors.AccessDenied(r, "token validation failed").WithError(err)
	}

	verified := true
	email := user.Email

	return &authorization.Info{
		Token: token,
		Userinfo: &openapi.Userinfo{
			Sub:           user.Email,
			Email:         &email,
			EmailVerified: &verified,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.User,
			},
		},
	}, nil
}

// authorizeUnikorn resolves a Unikorn-issued token (user or service account) by
// in-process decryption and verification.
func (a *Authorizer) authorizeUnikorn(r *http.Request, token string) (*authorization.Info, error) {
	userinfo, claims, err := a.authenticator.GetUserinfo(r.Context(), r, token)
	if err != nil {
		return nil, err
	}

	info := &authorization.Info{
		Token:    token,
		Userinfo: userinfo,
	}

	switch claims.Type {
	case oauth2.TokenTypeFederated:
		info.ClientID = claims.Federated.ClientID
	case oauth2.TokenTypeServiceAccount:
		info.ServiceAccount = true
	}

	return info, nil
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
