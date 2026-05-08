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
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// supportedAlgorithms enumerates the JWT signing algorithms accepted from Auth0.
// RS256 is Auth0's default; tenants configured for asymmetric keys typically use it.
//
//nolint:gochecknoglobals
var supportedAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.ES512}

// Claims is the verified Auth0 access token claim set extracted by the verifier.
// Only fields downstream callers (passport minting, source detection) need are
// surfaced — Auth0 emits many more.
type Claims struct {
	jwt.Claims `json:",inline"`

	// Permissions is Auth0's RBAC claim — populated when the API has RBAC enabled
	// and "Add Permissions in the Access Token" is on.
	Permissions []string `json:"permissions,omitempty"`

	// Scope is the OAuth 2.0 scope string (space-delimited).
	Scope string `json:"scope,omitempty"`

	// Email is the user's email when the access token includes it. Optional —
	// Auth0 only puts email on access tokens when explicitly configured to.
	Email string `json:"email,omitempty"`
}

// Verifier validates Auth0 access tokens locally using cached JWKS public keys.
type Verifier struct {
	keySource     KeySource
	issuer        string
	audience      string
	requiredScope string
	leeway        time.Duration
	clock         func() time.Time
	allowedAlgos  []jose.SignatureAlgorithm
}

// NewVerifier returns a Verifier configured from operator options. Returns
// ErrNotConfigured when issuer or audience is missing — both are required for
// a meaningful aud/iss check.
func NewVerifier(keySource KeySource, options *Options) (*Verifier, error) {
	if keySource == nil {
		return nil, fmt.Errorf("%w: key source is required", ErrNotConfigured)
	}

	if options == nil {
		return nil, fmt.Errorf("%w: options are required", ErrNotConfigured)
	}

	issuer := strings.TrimSpace(options.Issuer)
	audience := strings.TrimSpace(options.Audience)

	if issuer == "" {
		return nil, fmt.Errorf("%w: issuer is required", ErrNotConfigured)
	}

	if audience == "" {
		return nil, fmt.Errorf("%w: audience is required", ErrNotConfigured)
	}

	return &Verifier{
		keySource:     keySource,
		issuer:        issuer,
		audience:      audience,
		requiredScope: options.EffectiveRequiredScope(),
		clock:         time.Now,
		allowedAlgos:  supportedAlgorithms,
	}, nil
}

// Issuer returns the configured Auth0 issuer.
func (v *Verifier) Issuer() string {
	return v.issuer
}

// Verify parses, signature-verifies, and claim-validates the supplied access token.
// On success it returns the extracted claims; downstream callers can map them
// into the normalized passport identity.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (*Claims, error) {
	token, err := jwt.ParseSigned(rawToken, v.allowedAlgos)
	if err != nil {
		return nil, fmt.Errorf("%w: parse failed: %w", ErrInvalidToken, err)
	}

	if len(token.Headers) == 0 {
		return nil, fmt.Errorf("%w: JWT has no headers", ErrInvalidToken)
	}

	kid := token.Headers[0].KeyID
	if kid == "" {
		return nil, fmt.Errorf("%w: JWT header missing kid", ErrInvalidToken)
	}

	publicKey, err := v.keySource.Get(ctx, kid)
	if err != nil {
		if errors.Is(err, ErrJWKSUnavailable) {
			return nil, err
		}

		return nil, fmt.Errorf("%w: JWKS lookup failed: %w", ErrJWKSUnavailable, err)
	}

	var claims Claims
	if err := token.Claims(publicKey, &claims); err != nil {
		return nil, fmt.Errorf("%w: signature/claim decode failed: %w", ErrInvalidToken, err)
	}

	if err := v.validateStandardClaims(&claims); err != nil {
		return nil, err
	}

	if err := v.validateScope(&claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

func (v *Verifier) validateStandardClaims(claims *Claims) error {
	expected := jwt.Expected{
		Issuer:      v.issuer,
		AnyAudience: jwt.Audience{v.audience},
		Time:        v.clock(),
	}

	if err := claims.ValidateWithLeeway(expected, v.leeway); err != nil {
		switch {
		case errors.Is(err, jwt.ErrExpired), errors.Is(err, jwt.ErrNotValidYet):
			return fmt.Errorf("%w: %w", ErrTokenExpired, err)

		default:
			return fmt.Errorf("%w: claim validation failed: %w", ErrInvalidToken, err)
		}
	}

	return nil
}

func (v *Verifier) validateScope(claims *Claims) error {
	required := strings.TrimSpace(v.requiredScope)
	if required == "" {
		return nil
	}

	for _, p := range claims.Permissions {
		if strings.EqualFold(p, required) {
			return nil
		}
	}

	for _, s := range strings.Fields(claims.Scope) {
		if strings.EqualFold(s, required) {
			return nil
		}
	}

	return fmt.Errorf("%w: required scope %q not present", ErrInsufficientScope, required)
}
