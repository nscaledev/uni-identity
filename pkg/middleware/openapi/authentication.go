/*
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

package openapi

import (
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/idp"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
)

const (
	// uniTypeFederated and uniTypeServiceAccount are the platform access-token
	// "typ" claim values. They mirror oauth2.TokenType but are duplicated here so
	// this package (and the lean remote middleware) need not import the heavy
	// oauth2 package.
	uniTypeFederated      = "fed"
	uniTypeServiceAccount = "sa"

	// uniJWKSPath is where the identity service publishes its signing keys.
	uniJWKSPath = "/oauth2/v2/jwks"

	// uniAccessTokenType is the RFC 9068 `typ` header our access tokens carry
	// (mirrors jose.TokenTypeAccessToken; duplicated to keep this package free of
	// the heavy jose import that remote consumers would otherwise inherit).
	uniAccessTokenType = "at+jwt"
)

// AuthenticationInfo describes how a resource server authenticates bearer
// tokens. A token is a JWS verified by the resolver against its issuer's JWKS
// and mapped to a principal; `uniIssuer` is the platform's own issuer, the
// routing key that distinguishes our tokens (which also get a session check)
// from external ones. Legacy UNI JWEs are routed by shape and handled out of
// band (in-process introspection at identity, userinfo RPC at the edge).
type AuthenticationInfo struct {
	resolver  *idp.Resolver
	uniIssuer string
}

// NewAuthenticationInfo builds the authentication info. uniIssuer is the
// platform's own issuer; issuers are the JWS issuers the resolver verifies
// locally — always the external OIDC issuer when configured, plus the platform
// issuer itself on the remote edge (where UNI JWS are verified locally rather
// than in-cluster). When no issuers are given the resolver is nil.
func NewAuthenticationInfo(uniIssuer string, issuers ...idp.IssuerConfig) (*AuthenticationInfo, error) {
	info := &AuthenticationInfo{uniIssuer: uniIssuer}

	if len(issuers) > 0 {
		resolver, err := idp.NewResolver(nil, issuers...)
		if err != nil {
			return nil, err
		}

		info.resolver = resolver
	}

	return info, nil
}

// NewRemoteAuthenticationInfo builds the authentication info for a resource
// server's remote authorizer. It always trusts the platform issuer at
// identityURL — verifying UNI JWS locally against identity's published,
// unauthenticated JWKS — plus any external issuers. This is the constructor
// downstream services should use: it removes the footgun of having to assemble
// the platform issuer config by hand (and silently failing closed on every UNI
// token if it is forgotten). The UNI audience is the hostname of identityURL —
// the port-stripped host — exactly as identity derives it (common.IssuerValue
// uses url.Hostname(), and getAudience stamps that on every token); using the
// host with its port would fail audience validation for any ported URL.
func NewRemoteAuthenticationInfo(identityURL string, issuers ...idp.IssuerConfig) (*AuthenticationInfo, error) {
	u, err := url.Parse(identityURL)
	if err != nil {
		return nil, err
	}

	all := make([]idp.IssuerConfig, 0, len(issuers)+1)
	all = append(all, UNIIssuerConfig(identityURL, u.Hostname()))
	all = append(all, issuers...)

	return NewAuthenticationInfo(identityURL, all...)
}

// Resolver returns the JWS resolver (nil when no issuers are configured).
func (a *AuthenticationInfo) Resolver() *idp.Resolver {
	return a.resolver
}

// UNIIssuer returns the platform's own issuer (the routing key for our tokens).
func (a *AuthenticationInfo) UNIIssuer() string {
	return a.uniIssuer
}

// InfoFromPrincipal projects a verified token's principal onto the internal
// authentication identity. It carries identity only — the actor's subject and
// account type; organisation membership and RBAC are resolved later from the
// actor against our own graph via GetACL, never read from a token.
func InfoFromPrincipal(token string, p *idp.Principal) *authorization.Info {
	return &authorization.Info{
		Principal: &principal.Principal{
			Subject: p.Subject,
			Type:    p.Type,
			Issuer:  p.Issuer,
		},
		Token: token,
	}
}

// UNIIssuerConfig builds the resolver config for the platform's own issuer, used
// by edges that verify UNI JWS locally against the identity JWKS: subject = the
// standard `sub` claim, account type from the "typ" claim, ES512.
func UNIIssuerConfig(issuer, audience string) idp.IssuerConfig {
	return idp.IssuerConfig{
		Issuer:    issuer,
		Audience:  audience,
		Algorithm: jose.ES512,
		TokenType: uniAccessTokenType,
		JWKSURL:   strings.TrimRight(issuer, "/") + uniJWKSPath,
		Mapper: idp.SubjectTypeMapper("typ", map[string]identityapi.AuthClaimsAcctype{
			uniTypeFederated:      identityapi.User,
			uniTypeServiceAccount: identityapi.Service,
		}),
	}
}
