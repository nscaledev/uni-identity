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
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4/jwt"
)

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
	Issuer                    string
	Audience                  string
	TokenVerificationLeeway   time.Duration
	SupportedSigningAlgorithm string
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

	Email         string      `json:"email"`
	EmailVerified *bool       `json:"email_verified"`
	Authz         authzClaims `json:"https://unikorn-cloud.org/authz"`
}

// User is the validated identity extracted from an Auth0 access token.
type User struct {
	Email         string
	Expiry        time.Time
	ClaimedOrgIDs []string
}

// Validator validates Auth0 JWT access tokens using the tenant JWKS.
type Validator struct {
	options Options
	now     func() time.Time

	mu       sync.Mutex
	verifier *gooidc.IDTokenVerifier
}

// NewValidator returns a validator using the Auth0 tenant JWKS endpoint.
func NewValidator(options Options) (*Validator, error) {
	if !options.Enabled() {
		return nil, nil
	}

	if options.Issuer == "" || options.Audience == "" {
		return nil, fmt.Errorf("%w: issuer and audience must both be specified", ErrInvalidConfig)
	}

	if options.SupportedSigningAlgorithm == "" {
		options.SupportedSigningAlgorithm = "RS256"
	}

	return &Validator{
		options: options,
		now:     time.Now,
	}, nil
}

// Validate verifies the token signature, issuer, audience, temporal claims,
// verified email, and UNI authorization context emitted by Auth0.
func (v *Validator) Validate(ctx context.Context, token string) (*User, error) {
	if v == nil {
		return nil, ErrDisabled
	}

	idToken, err := v.getVerifier(ctx).Verify(ctx, token)
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

	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" {
		return nil, ErrMissingEmail
	}

	if claims.EmailVerified == nil || !*claims.EmailVerified {
		return nil, ErrEmailUnverified
	}

	if claims.Authz.Acctype != accountTypeUser {
		return nil, fmt.Errorf("%w: acctype must be %q", ErrInvalidAuthzClaim, accountTypeUser)
	}

	if len(claims.Authz.OrgIDs) == 0 {
		return nil, fmt.Errorf("%w: orgIds must not be empty", ErrInvalidAuthzClaim)
	}

	return &User{
		Email:         email,
		Expiry:        claims.Expiry.Time(),
		ClaimedOrgIDs: claims.Authz.OrgIDs,
	}, nil
}

func (v *Validator) getVerifier(ctx context.Context) *gooidc.IDTokenVerifier {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.verifier != nil {
		return v.verifier
	}

	jwksURL := strings.TrimRight(v.options.Issuer, "/") + "/.well-known/jwks.json"
	keySet := gooidc.NewRemoteKeySet(ctx, jwksURL)

	v.verifier = gooidc.NewVerifier(v.options.Issuer, keySet, &gooidc.Config{
		ClientID: v.options.Audience,
		SupportedSigningAlgs: []string{
			v.options.SupportedSigningAlgorithm,
		},
		SkipExpiryCheck: true,
	})

	return v.verifier
}
