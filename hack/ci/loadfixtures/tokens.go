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

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/unikorn-cloud/identity/hack/ci/internal/fixturelib"
)

const (
	keyID  = "load-test-1"
	keyLen = 2048

	// Claim names read by pkg/oauth2/auth0/validator.go.
	emailClaim         = "https://unikorn-cloud.org/email"
	emailVerifiedClaim = "https://unikorn-cloud.org/email_verified"
	authzClaim         = "https://unikorn-cloud.org/authz"
	groupsClaim        = "https://unikorn-cloud.org/groups"

	tokenLifetime = 6 * time.Hour
)

// minter signs Auth0-shaped access tokens with a key that exists only in this
// process. Only the public half leaves it, as a JWKS.
type minter struct {
	signer   jose.Signer
	public   jose.JSONWebKey
	issuer   string
	audience string
}

func newMinter(issuer, audience string) *minter {
	key, err := rsa.GenerateKey(rand.Reader, keyLen)
	if err != nil {
		fixturelib.Fatalf("failed to generate signing key: %v", err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: keyID}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		fixturelib.Fatalf("failed to create signer: %v", err)
	}

	return &minter{
		signer:   signer,
		public:   jose.JSONWebKey{Key: &key.PublicKey, KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig"},
		issuer:   issuer,
		audience: audience,
	}
}

// jwks returns the public key set served at <issuer>/.well-known/jwks.json.
func (m *minter) jwks() []byte {
	out, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{m.public}})
	if err != nil {
		fixturelib.Fatalf("failed to marshal JWKS: %v", err)
	}

	return out
}

// mint returns a distinct token for the email on every call (random jti).
func (m *minter) mint(email string, orgIDs []string) string {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		fixturelib.Fatalf("failed to read random bytes: %v", err)
	}

	now := time.Now()

	std := jwt.Claims{
		Issuer:   m.issuer,
		Subject:  "auth0|" + email,
		Audience: jwt.Audience{m.audience},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(tokenLifetime)),
		ID:       hex.EncodeToString(jti),
	}

	private := map[string]any{
		emailClaim:         email,
		emailVerifiedClaim: true,
		authzClaim:         map[string]any{"acctype": "user", "orgIds": orgIDs},
		groupsClaim:        []string{"load-test"},
	}

	token, err := jwt.Signed(m.signer).Claims(std).Claims(private).Serialize()
	if err != nil {
		fixturelib.Fatalf("failed to sign token for %s: %v", email, err)
	}

	return token
}
