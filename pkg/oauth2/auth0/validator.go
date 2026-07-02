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

package auth0

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"go.opentelemetry.io/otel"

	"github.com/unikorn-cloud/identity/pkg/constants"
)

// DefaultJWKSMinRefreshInterval is the default minimum interval between
// requests to the upstream JWKS endpoint. It bounds the worst-case JWKS
// fetch rate to one request per interval per process, which is well under
// Auth0's documented per-tenant JWKS rate limit while still allowing
// legitimate key rotations to be picked up promptly.
const DefaultJWKSMinRefreshInterval = 60 * time.Second

// jwksFetchTimeout bounds a single upstream JWKS fetch. go-oidc runs the
// fetch in a goroutine detached from the per-request context and frees its
// deduplication slot only when the fetch returns, so a fetch without a
// deadline that hangs would wedge the key set permanently.
const jwksFetchTimeout = 10 * time.Second

const (
	// AuthzClaimName is the UNI authorization context claim emitted by the
	// Auth0 post-login Action.
	AuthzClaimName = "https://unikorn-cloud.org/authz"

	accountTypeUser = "user"
)

var (
	ErrDisabled          = errors.New("auth0 exchange validation is disabled")
	ErrInvalidConfig     = errors.New("invalid auth0 exchange config")
	ErrInvalidToken      = errors.New("invalid auth0 token")
	ErrEmailUnverified   = errors.New("auth0 email is not verified")
	ErrMissingEmail      = errors.New("auth0 email is missing")
	ErrInvalidAuthzClaim = errors.New("invalid auth0 authz claim")
)

// Options configures Auth0 access-token validation for passport exchange.
type Options struct {
	Issuer                  string
	Audience                string
	TokenVerificationLeeway time.Duration

	// SupportedSigningAlgorithms is the list of asymmetric signing algorithms
	// accepted when verifying the token signature. When empty, defaults to
	// ["RS256"]. Every entry must be an asymmetric algorithm; symmetric
	// algorithms (e.g. HS256) and "none" are rejected at construction time.
	SupportedSigningAlgorithms []string

	// SkipEmailVerification disables the email_verified check. When false
	// (the default) tokens with an unverified or missing email_verified claim
	// are rejected. Set to true only for providers that do not emit the claim.
	SkipEmailVerification bool

	// RequireAuthzClaim gates the UNI authorization-context checks. When
	// false (the default) the https://unikorn-cloud.org/authz claim is
	// tolerated as missing or zero-valued and acctype defaults to "user".
	// When true the claim must be present with acctype=="user" and at least
	// one orgId.
	RequireAuthzClaim bool

	// JWKSMinRefreshInterval is the minimum interval between requests to
	// the upstream JWKS endpoint. go-oidc refetches the JWKS whenever no
	// cached key verifies a token's signature, so without a bound, forged
	// or unknown-kid tokens would drive one fetch per token and exhaust
	// the tenant rate limit. Tokens demanding a refetch inside the
	// interval are rejected without contacting Auth0. When zero,
	// DefaultJWKSMinRefreshInterval is used.
	JWKSMinRefreshInterval time.Duration
}

// Enabled reports whether Auth0 exchange validation has enough configuration
// to run.
func (o Options) Enabled() bool {
	return o.Issuer != "" || o.Audience != ""
}

type authzClaims struct {
	Acctype string   `json:"acctype"`
	OrgIDs  []string `json:"orgIds"`
}

type tokenClaims struct {
	jwt.Claims

	// Auth0 only emits the standard email claims on the ID token, and a
	// PostLogin action cannot set bare (non-namespaced) claims on the access
	// token, so the enrich-token-claims action surfaces them under the
	// unikorn-cloud.org namespace where this access-token validator reads them.
	//nolint:tagliatelle
	Email string `json:"https://unikorn-cloud.org/email"`
	//nolint:tagliatelle
	EmailVerified *bool `json:"https://unikorn-cloud.org/email_verified"`
	//nolint:tagliatelle
	Authz authzClaims `json:"https://unikorn-cloud.org/authz"`
}

// User is the validated identity extracted from an Auth0 access token.
//
// UNI membership is authoritative for organization scope, so the claimed
// orgIds from the Auth0 token are intentionally not surfaced here — they are
// only validated as a non-empty signal that the post-login Action ran.
type User struct {
	Email  string
	Expiry time.Time
}

// Validator validates Auth0 JWT access tokens using the tenant JWKS.
type Validator struct {
	options Options
	now     func() time.Time

	mu       sync.Mutex
	verifier *gooidc.IDTokenVerifier
}

// isAsymmetricAlg reports whether alg is one of the accepted asymmetric
// signing algorithms. Symmetric algorithms (e.g. HS256) and the "none"
// pseudo-algorithm are not permitted for external-token validation.
func isAsymmetricAlg(alg string) bool {
	switch jose.SignatureAlgorithm(alg) {
	case jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512:
		return true
	case jose.EdDSA, jose.HS256, jose.HS384, jose.HS512:
		return false
	}

	return false
}

// NewValidator returns a validator using the Auth0 tenant JWKS endpoint.
// It returns ErrDisabled when no Auth0 exchange configuration is supplied.
func NewValidator(options Options) (*Validator, error) {
	if !options.Enabled() {
		return nil, ErrDisabled
	}

	if options.Issuer == "" || options.Audience == "" {
		return nil, fmt.Errorf("%w: issuer and audience must both be specified", ErrInvalidConfig)
	}

	if len(options.SupportedSigningAlgorithms) == 0 {
		options.SupportedSigningAlgorithms = []string{"RS256"}
	}

	for _, alg := range options.SupportedSigningAlgorithms {
		if !isAsymmetricAlg(alg) {
			return nil, fmt.Errorf("%w: signing algorithm %q is not asymmetric", ErrInvalidConfig, alg)
		}
	}

	if options.JWKSMinRefreshInterval <= 0 {
		options.JWKSMinRefreshInterval = DefaultJWKSMinRefreshInterval
	}

	return &Validator{
		options: options,
		now:     time.Now,
	}, nil
}

// validateEmail checks the email claim is present and, unless
// SkipEmailVerification is set, that the address is verified.
func (v *Validator) validateEmail(claims *tokenClaims) (string, error) {
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" {
		return "", ErrMissingEmail
	}

	if !v.options.SkipEmailVerification {
		if claims.EmailVerified == nil || !*claims.EmailVerified {
			return "", ErrEmailUnverified
		}
	}

	return email, nil
}

// validateAuthzClaim checks the UNI authorization context claim when
// RequireAuthzClaim is enabled.
func (v *Validator) validateAuthzClaim(claims *tokenClaims) error {
	if !v.options.RequireAuthzClaim {
		return nil
	}

	if claims.Authz.Acctype != accountTypeUser {
		return fmt.Errorf("%w: acctype must be %q", ErrInvalidAuthzClaim, accountTypeUser)
	}

	if len(claims.Authz.OrgIDs) == 0 {
		return fmt.Errorf("%w: orgIds must not be empty", ErrInvalidAuthzClaim)
	}

	return nil
}

// Validate verifies the token signature, issuer, audience, temporal claims,
// verified email, and UNI authorization context emitted by Auth0.
func (v *Validator) Validate(ctx context.Context, token string) (*User, error) {
	if v == nil {
		return nil, ErrDisabled
	}

	// getVerifier intentionally does not receive ctx: the keyset it builds is
	// long-lived and must use a background context for JWKS refreshes. The
	// per-request ctx is still applied to the Verify call below.
	//nolint:contextcheck
	idToken, err := v.getVerifier().Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	claims := &tokenClaims{}
	if err := idToken.Claims(claims); err != nil {
		return nil, fmt.Errorf("%w: failed to parse claims: %w", ErrInvalidToken, err)
	}

	expected := jwt.Expected{
		Issuer: v.options.Issuer,
		AnyAudience: jwt.Audience{
			v.options.Audience,
		},
		Time: v.now(),
	}

	if err := claims.ValidateWithLeeway(expected, v.options.TokenVerificationLeeway); err != nil {
		return nil, fmt.Errorf("%w: failed to validate claims: %w", ErrInvalidToken, err)
	}

	email, err := v.validateEmail(claims)
	if err != nil {
		return nil, err
	}

	if err := v.validateAuthzClaim(claims); err != nil {
		return nil, err
	}

	return &User{
		Email:  email,
		Expiry: claims.Expiry.Time(),
	}, nil
}

func (v *Validator) getVerifier() *gooidc.IDTokenVerifier {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.verifier != nil {
		return v.verifier
	}

	// The keyset outlives any single request and must refresh its JWKS cache
	// when Auth0 rotates signing keys, so it gets a background context. The
	// ctx passed to Verify only bounds how long a caller waits on an
	// in-flight fetch; the fetch itself is bounded by the client timeout.
	// TrimRight so a trailing-slash issuer (Auth0 emits `iss` with one) doesn't
	// produce a "…//.well-known/jwks.json" URL.
	jwksURL := strings.TrimRight(v.options.Issuer, "/") + "/.well-known/jwks.json"

	// Throttle JWKS fetches at the HTTP layer so invalid tokens cannot
	// drive one upstream request per token. See throttledTransport for
	// the rationale. The keyset picks this client up from its context.
	client := &http.Client{
		Timeout:   jwksFetchTimeout,
		Transport: newThrottledTransport(http.DefaultTransport, v.options.JWKSMinRefreshInterval, v.now, otel.Meter(constants.Application)),
	}

	keySet := gooidc.NewRemoteKeySet(gooidc.ClientContext(context.Background(), client), jwksURL)

	v.verifier = gooidc.NewVerifier(v.options.Issuer, keySet, &gooidc.Config{
		ClientID:             v.options.Audience,
		SupportedSigningAlgs: v.options.SupportedSigningAlgorithms,
		SkipExpiryCheck:      true,
	})

	return v.verifier
}
