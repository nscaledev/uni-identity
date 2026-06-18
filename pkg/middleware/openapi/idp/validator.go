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

package idp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spf13/pflag"
	"go.opentelemetry.io/otel"

	"github.com/unikorn-cloud/identity/pkg/constants"
)

// DefaultJWKSMinRefreshInterval is the default minimum interval between
// requests to the upstream JWKS endpoint. It bounds the worst-case JWKS
// fetch rate to one request per interval per process, which is well under
// Auth0's documented per-tenant JWKS rate limit while still allowing
// legitimate key rotations to be picked up promptly.
const DefaultJWKSMinRefreshInterval = 60 * time.Second

// jwksFetchTimeout bounds a single upstream JWKS fetch so a hung endpoint
// cannot wedge token validation.
const jwksFetchTimeout = 10 * time.Second

// DefaultSigningAlgorithm is the signature algorithm Auth0 uses for RS256
// tenants. It is pinned explicitly; the algorithm named in a token header is
// never trusted to select the verification method (alg-substitution defence).
const DefaultSigningAlgorithm = "RS256"

// grantTypeClientCredentials is the Auth0 `gty` claim value for the OAuth2
// client-credentials grant — i.e. a machine principal. We discriminate
// principal type on this claim, never on the subject string (token resolution
// note §6).
const grantTypeClientCredentials = "client-credentials"

var (
	ErrDisabled        = errors.New("third-party OIDC validation is disabled")
	ErrInvalidConfig   = errors.New("invalid OIDC config")
	ErrInvalidToken    = errors.New("invalid OIDC token")
	ErrEmailUnverified = errors.New("OIDC email is not verified")
	ErrMissingEmail    = errors.New("OIDC email is missing")
	// ErrNotAUser is returned for a third-party token that is not a human
	// user. The optional third-party IdP is for users only; machine principals
	// are issued by the Unikorn identity service, not federated in.
	ErrNotAUser = errors.New("third-party token is not a user")
)

// Options configures local validation of third-party OIDC access tokens.
type Options struct {
	Issuer                    string
	Audience                  string
	TokenVerificationLeeway   time.Duration
	SupportedSigningAlgorithm string

	// JWKSMinRefreshInterval is the minimum interval between requests to the
	// upstream JWKS endpoint. Without a bound, forged or unknown-kid tokens
	// would drive one fetch per token and exhaust the tenant rate limit;
	// tokens demanding a refetch inside the interval are rejected without
	// contacting the issuer. When zero, DefaultJWKSMinRefreshInterval is used.
	JWKSMinRefreshInterval time.Duration
}

// AddFlags registers the third-party OIDC configuration flags. The names are
// shared by the identity service and by the remote middleware in downstream
// resource servers, so both validate the same issuer/audience.
func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.StringVar(&o.Issuer, "oidc-issuer", "", "Third-party OIDC issuer accepted for local validation of federated user access tokens.")
	f.StringVar(&o.Audience, "oidc-audience", "", "Third-party OIDC API audience asserted when validating federated user access tokens.")
}

// Enabled reports whether third-party OIDC validation has enough configuration
// to run.
func (o *Options) Enabled() bool {
	return o.Issuer != "" || o.Audience != ""
}

// tokenClaims models the subset of the access token we consume. Authorization
// data (organisation membership, RBAC) is deliberately absent: we own that
// graph and resolve it against our own directory keyed on the verified
// subject, never read it from a foreign token.
type tokenClaims struct {
	jwt.Claims

	// GrantType is Auth0's `gty` claim; client-credentials marks a machine
	// principal.
	GrantType string `json:"gty"`

	// Auth0 only emits the standard email claims on the ID token, and a
	// PostLogin action cannot set bare (non-namespaced) claims on the access
	// token, so the enrich-token-claims action surfaces them under the
	// unikorn-cloud.org namespace where this access-token validator reads them.
	//nolint:tagliatelle
	Email string `json:"https://unikorn-cloud.org/email"`
	//nolint:tagliatelle
	EmailVerified *bool `json:"https://unikorn-cloud.org/email_verified"`
}

// User is the validated identity extracted from a third-party access token.
type User struct {
	Email  string
	Expiry time.Time
}

// Validator validates third-party (Auth0) JWT access tokens locally against
// the tenant JWKS, using go-jose for signature and claim verification.
//
// Verification is done with go-jose directly — not an OIDC ID-token verifier —
// because OIDC verifiers carry ID-token defaults (notably audience handling)
// that do not match access-token validation. The accepted algorithm, expected
// issuer, and expected audience are all asserted explicitly here. The OIDC
// ecosystem is used only for JWKS discovery (see keySet).
//
// The external IdP must be configured to issue transparent, signed (JWS) access
// tokens — for Auth0, by registering each resource server as an Auth0 API so
// tokens carry its identifier as the audience. Opaque access tokens must never
// be used: a JWS is verified locally against cached JWKS with no per-request
// call to the IdP and an invalid one is rejected locally, whereas an opaque
// token can only be validated by an introspection call on every request, making
// the IdP a synchronous dependency of every request and a DoS amplifier (a flood
// of plausible-but-invalid tokens drives one introspection call each). This
// validator accordingly accepts only a JWS and has no opaque/introspection path.
type Validator struct {
	options Options
	now     func() time.Time

	mu     sync.Mutex
	keySet *keySet
}

// NewValidator returns a validator using the issuer's JWKS endpoint.
// It returns ErrDisabled when no configuration is supplied.
func NewValidator(options Options) (*Validator, error) {
	if !options.Enabled() {
		return nil, ErrDisabled
	}

	if options.Issuer == "" || options.Audience == "" {
		return nil, fmt.Errorf("%w: issuer and audience must both be specified", ErrInvalidConfig)
	}

	if options.SupportedSigningAlgorithm == "" {
		options.SupportedSigningAlgorithm = DefaultSigningAlgorithm
	}

	if options.JWKSMinRefreshInterval <= 0 {
		options.JWKSMinRefreshInterval = DefaultJWKSMinRefreshInterval
	}

	return &Validator{
		options: options,
		now:     time.Now,
	}, nil
}

// NewValidatorOrNil builds a validator, returning a nil validator (not an
// error) when no third-party OIDC config is supplied. This is the constructor
// callers use when third-party validation is optional: a nil *Validator is
// safe to hold and reports ErrDisabled if ever invoked. A partially-specified
// config (e.g. issuer without audience) still returns an error.
func NewValidatorOrNil(options Options) (*Validator, error) {
	validator, err := NewValidator(options)
	if err != nil {
		if errors.Is(err, ErrDisabled) {
			// A nil validator is the valid "disabled" state: it is safe to
			// hold and reports ErrDisabled if ever invoked.
			//nolint:nilnil
			return nil, nil
		}

		return nil, err
	}

	return validator, nil
}

// Validate verifies the token signature against the tenant JWKS and checks the
// issuer, audience, algorithm, expiry, verified email, and that the principal
// is a user. It returns the verified subject only; organisation/authorisation
// data is resolved elsewhere against our own graph.
func (v *Validator) Validate(ctx context.Context, token string) (*User, error) {
	if v == nil {
		return nil, ErrDisabled
	}

	claims, err := v.verify(ctx, token)
	if err != nil {
		return nil, err
	}

	// The third-party IdP is for users only. A client-credentials token is a
	// machine principal and must not be federated in; reject it on the grant
	// type rather than letting it masquerade as a user.
	if claims.GrantType == grantTypeClientCredentials {
		return nil, ErrNotAUser
	}

	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" {
		return nil, ErrMissingEmail
	}

	if claims.EmailVerified == nil || !*claims.EmailVerified {
		return nil, ErrEmailUnverified
	}

	return &User{
		Email:  email,
		Expiry: claims.Expiry.Time(),
	}, nil
}

// verify pins the accepted algorithm, verifies the signature against the tenant
// JWKS, and validates the issuer, audience, and temporal claims, returning the
// verified claims. The algorithm allowlist is applied at parse time, before any
// key lookup, so the token header alg cannot select the verification method
// ("none" / asymmetric→HMAC substitution defence).
func (v *Validator) verify(ctx context.Context, token string) (*tokenClaims, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{
		jose.SignatureAlgorithm(v.options.SupportedSigningAlgorithm),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	if len(parsed.Headers) != 1 {
		return nil, fmt.Errorf("%w: expected exactly one signature", ErrInvalidToken)
	}

	key, err := v.keys().key(ctx, parsed.Headers[0].KeyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	claims := &tokenClaims{}
	if err := parsed.Claims(key, claims); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
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

	return claims, nil
}

// keys lazily builds the JWKS cache. The HTTP client wraps the default
// transport with the refresh throttle so invalid tokens cannot drive one
// upstream request per token.
func (v *Validator) keys() *keySet {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.keySet != nil {
		return v.keySet
	}

	jwksURL := strings.TrimRight(v.options.Issuer, "/") + "/.well-known/jwks.json"

	client := &http.Client{
		Timeout:   jwksFetchTimeout,
		Transport: newThrottledTransport(http.DefaultTransport, v.options.JWKSMinRefreshInterval, v.now, otel.Meter(constants.Application)),
	}

	v.keySet = newKeySet(jwksURL, client)

	return v.keySet
}
