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

package passport

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	identityoauth2 "github.com/unikorn-cloud/identity/pkg/oauth2"
)

// Verifier verifies passport JWTs locally using cached JWKS public keys.
type Verifier struct {
	cache *JWKSCache
}

// NewVerifier returns a new Verifier backed by the given JWKS cache.
func NewVerifier(cache *JWKSCache) *Verifier {
	return &Verifier{cache: cache}
}

// Verify auto-detects and verifies a passport JWT.
// Returns ErrNotPassport when the token is not a passport — the caller should
// delegate to the remote authorizer. All other errors are fail-closed.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (*identityoauth2.PassportClaims, error) {
	if !isPassport(rawToken) {
		return nil, ErrNotPassport
	}

	token, err := jwt.ParseSigned(rawToken, []jose.SignatureAlgorithm{jose.ES512})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPassportInvalidSig, err)
	}

	if len(token.Headers) == 0 {
		return nil, fmt.Errorf("%w: JWT has no headers", ErrPassportInvalidSig)
	}

	kid := token.Headers[0].KeyID
	if kid == "" {
		return nil, fmt.Errorf("%w: JWT has no kid", ErrPassportInvalidSig)
	}

	publicKey, err := v.cache.Get(ctx, kid)
	if err != nil {
		if errors.Is(err, ErrJWKSUnavailable) {
			return nil, err
		}

		return nil, fmt.Errorf("%w: JWKS lookup failed: %w", ErrJWKSUnavailable, err)
	}

	return v.verifyClaims(token, publicKey)
}

// verifyClaims verifies the token signature, validates the standard claims
// and performs a defense-in-depth typ check.
func (v *Verifier) verifyClaims(token *jwt.JSONWebToken, publicKey *jose.JSONWebKey) (*identityoauth2.PassportClaims, error) {
	var claims identityoauth2.PassportClaims
	if err := token.Claims(publicKey, &claims); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPassportInvalidSig, err)
	}

	expected := jwt.Expected{
		Issuer: identityoauth2.PassportIssuer,
		Time:   time.Now(),
	}

	if err := claims.ValidateWithLeeway(expected, 0); err != nil {
		if errors.Is(err, jwt.ErrExpired) {
			return nil, fmt.Errorf("%w: %w", ErrPassportExpired, err)
		}

		return nil, fmt.Errorf("%w: %w", ErrPassportInvalidSig, err)
	}

	// Defense-in-depth: re-check typ claim after full verification.
	if claims.Type != identityoauth2.PassportType {
		return nil, fmt.Errorf("%w: typ claim mismatch", ErrPassportInvalidSig)
	}

	return &claims, nil
}

// isPassport decodes the JWT payload (without verifying the signature) and returns
// true if the typ body claim equals PassportType.
// Any decode/unmarshal failure is treated as a non-passport token.
func isPassport(rawToken string) bool {
	var claims struct {
		Type string `json:"typ"`
	}

	return parseJWTPayload(rawToken, &claims) == nil && claims.Type == identityoauth2.PassportType
}

// parseJWTPayload decodes the JWT payload into dest without verifying the signature.
func parseJWTPayload(rawToken string, dest any) error {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return fmt.Errorf("%w: malformed JWT", ErrPassportInvalidSig)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("%w: malformed JWT payload: %w", ErrPassportInvalidSig, err)
	}

	return json.Unmarshal(payload, dest)
}
