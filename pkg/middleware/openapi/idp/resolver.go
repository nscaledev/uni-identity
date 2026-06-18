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

// Package idp resolves a signed bearer token (JWS) into a normalised internal
// principal. A token is just a JWS: it is verified against its issuer's
// published JWKS (algorithm pinned per issuer), and a per-issuer claim mapper
// transforms the verified claims into a principal (subject + account type).
// There is nothing provider-specific in the resolver — each trusted issuer
// (the platform's own issuer, an external OIDC provider, ...) is a configuration
// entry with its own claim mapper.
package idp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"go.opentelemetry.io/otel"

	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/bearer"
	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// DefaultJWKSMinRefreshInterval bounds the worst-case JWKS fetch rate to one
// request per interval per process, well under a typical tenant's JWKS rate
// limit while still picking up legitimate key rotations promptly.
const DefaultJWKSMinRefreshInterval = 60 * time.Second

// jwksFetchTimeout bounds a single upstream JWKS fetch so a hung endpoint
// cannot wedge token validation.
const jwksFetchTimeout = 10 * time.Second

var (
	// ErrUntrustedIssuer is returned when a token's issuer is not configured.
	ErrUntrustedIssuer = errors.New("token issuer is not trusted")
	// ErrInvalidToken is returned when a token fails verification.
	ErrInvalidToken = errors.New("invalid token")
	// ErrInvalidConfig is returned for an incomplete issuer configuration.
	ErrInvalidConfig = errors.New("invalid issuer config")
)

// Principal is the normalised identity extracted from a verified token,
// independent of the issuer that produced it. It carries identity only —
// organisation membership and RBAC are resolved downstream against our own
// graph, never read from a token.
type Principal struct {
	Issuer  string
	Subject string
	Type    openapi.AuthClaimsAcctype
	Expiry  time.Time
}

// Mapper enforces an issuer's claim requirements and extracts the principal
// identity from a verified token. It receives the validated standard claims and
// the raw verified payload (so it can read issuer-specific claims). Returning an
// error rejects the token.
type Mapper func(standard jwt.Claims, payload []byte) (*Principal, error)

// IssuerConfig describes a trusted JWS issuer and how to verify and map it.
type IssuerConfig struct {
	// Issuer is the expected `iss` claim and the routing key.
	Issuer string
	// Audience is asserted against the token's `aud`.
	Audience string
	// Algorithm is the single accepted signature algorithm (the token header
	// alg is never trusted to select the verification method).
	Algorithm jose.SignatureAlgorithm
	// TokenType, when set, is the required JOSE `typ` header (RFC 9068, e.g.
	// "at+jwt"), asserted before the token is trusted — mirroring the
	// long-standing type check on encrypted (JWE) tokens. An issuer whose `typ`
	// is not dependable leaves it empty to skip.
	TokenType string
	// Mapper transforms this issuer's verified claims into a principal.
	Mapper Mapper
	// JWKSURL defaults to Issuer + /.well-known/jwks.json when empty.
	JWKSURL string
	// JWKSMinRefreshInterval bounds upstream JWKS fetches; defaults to
	// DefaultJWKSMinRefreshInterval.
	JWKSMinRefreshInterval time.Duration
	// TokenVerificationLeeway absorbs clock skew on temporal claims.
	TokenVerificationLeeway time.Duration
}

type issuerVerifier struct {
	config IssuerConfig
	keySet *keySet
}

// Resolver verifies tokens against a set of trusted issuers and maps them to a
// principal. It routes on the (unverified) issuer claim, then verifies against
// that issuer's pinned algorithm and JWKS before any claim is trusted.
type Resolver struct {
	now     func() time.Time
	issuers map[string]*issuerVerifier
}

// NewResolver builds a resolver over the given trusted issuers. now may be nil
// (defaults to time.Now); it is injectable for tests and is shared with the
// JWKS refresh throttle.
func NewResolver(now func() time.Time, configs ...IssuerConfig) (*Resolver, error) {
	if now == nil {
		now = time.Now
	}

	r := &Resolver{
		now:     now,
		issuers: make(map[string]*issuerVerifier, len(configs)),
	}

	for i := range configs {
		config := configs[i]

		if config.Issuer == "" || config.Audience == "" || config.Algorithm == "" || config.Mapper == nil {
			return nil, fmt.Errorf("%w: issuer, audience, algorithm and mapper are all required", ErrInvalidConfig)
		}

		if config.JWKSURL == "" {
			config.JWKSURL = strings.TrimRight(config.Issuer, "/") + "/.well-known/jwks.json"
		}

		if config.JWKSMinRefreshInterval <= 0 {
			config.JWKSMinRefreshInterval = DefaultJWKSMinRefreshInterval
		}

		client := &http.Client{
			Timeout:   jwksFetchTimeout,
			Transport: newThrottledTransport(http.DefaultTransport, config.JWKSMinRefreshInterval, now, otel.Meter(constants.Application)),
		}

		r.issuers[config.Issuer] = &issuerVerifier{
			config: config,
			keySet: newKeySet(config.JWKSURL, client),
		}
	}

	return r, nil
}

// SetIssuerTransport overrides the base HTTP transport used to fetch the named
// issuer's JWKS, preserving the refresh throttle. The remote authorizer uses
// this to give the platform issuer the same CA/mTLS-aware transport it uses to
// reach identity, so a JWKS served behind a private CA (e.g. a dev environment)
// can be fetched — the resolver's own default transport trusts only system CAs.
// It is a no-op for an unconfigured issuer, and must be called at construction,
// before the resolver is used concurrently.
func (r *Resolver) SetIssuerTransport(issuer string, base http.RoundTripper) {
	if r == nil || base == nil {
		return
	}

	verifier, ok := r.issuers[issuer]
	if !ok {
		return
	}

	client := &http.Client{
		Timeout:   jwksFetchTimeout,
		Transport: newThrottledTransport(base, verifier.config.JWKSMinRefreshInterval, r.now, otel.Meter(constants.Application)),
	}

	verifier.keySet = newKeySet(verifier.config.JWKSURL, client)
}

// Trusts reports whether the resolver is configured for the given issuer. It
// lets callers decide whether a JWS is one they can resolve before committing
// to it (without verifying).
func (r *Resolver) Trusts(issuer string) bool {
	if r == nil {
		return false
	}

	_, ok := r.issuers[issuer]

	return ok
}

// Resolve verifies a JWS against its issuer's JWKS and returns the principal.
// It rejects a token whose issuer is not configured before any key fetch.
func (r *Resolver) Resolve(ctx context.Context, token string) (*Principal, error) {
	if r == nil {
		return nil, ErrUntrustedIssuer
	}

	issuer, err := bearer.UnverifiedIssuer(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	verifier, ok := r.issuers[issuer]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUntrustedIssuer, issuer)
	}

	return verifier.resolve(ctx, r.now, token)
}

func (v *issuerVerifier) resolve(ctx context.Context, now func() time.Time, token string) (*Principal, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{v.config.Algorithm})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	if len(parsed.Headers) != 1 {
		return nil, fmt.Errorf("%w: expected exactly one signature", ErrInvalidToken)
	}

	if err := v.assertTokenType(parsed.Headers[0]); err != nil {
		return nil, err
	}

	key, err := v.keySet.key(ctx, parsed.Headers[0].KeyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	return v.verifyAndMap(now, parsed, key)
}

// assertTokenType enforces the issuer's pinned JOSE `typ` header (RFC 9068) when
// set, so a JWS of another type (e.g. an id_token) minted by the same issuer and
// key cannot be replayed as an access token. It mirrors the long-standing type
// check on encrypted tokens.
func (v *issuerVerifier) assertTokenType(header jose.Header) error {
	if v.config.TokenType == "" {
		return nil
	}

	typ, _ := header.ExtraHeaders["typ"].(string)
	if typ != v.config.TokenType {
		return fmt.Errorf("%w: unexpected token type %q", ErrInvalidToken, typ)
	}

	return nil
}

// verifyAndMap verifies the signature, validates the standard claims against the
// issuer's expectations, and maps the verified payload to a principal.
func (v *issuerVerifier) verifyAndMap(now func() time.Time, parsed *jwt.JSONWebToken, key *jose.JSONWebKey) (*Principal, error) {
	// Verify the signature and capture the raw verified payload so the mapper
	// can read issuer-specific claims.
	var payload json.RawMessage
	if err := parsed.Claims(key, &payload); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	standard := jwt.Claims{}
	if err := json.Unmarshal(payload, &standard); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	expected := jwt.Expected{
		Issuer:      v.config.Issuer,
		AnyAudience: jwt.Audience{v.config.Audience},
		Time:        now(),
	}

	if err := standard.ValidateWithLeeway(expected, v.config.TokenVerificationLeeway); err != nil {
		return nil, fmt.Errorf("%w: failed to validate claims: %w", ErrInvalidToken, err)
	}

	principal, err := v.config.Mapper(standard, payload)
	if err != nil {
		return nil, err
	}

	principal.Issuer = v.config.Issuer

	if principal.Expiry.IsZero() && standard.Expiry != nil {
		principal.Expiry = standard.Expiry.Time()
	}

	return principal, nil
}
