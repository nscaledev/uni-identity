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

package auth0 //nolint:testpackage

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

// testKeyPair holds a JWK key pair for signing and verifying test tokens.
type testKeyPair struct {
	pub  jose.JSONWebKey
	priv jose.JSONWebKey
}

func newTestKeyPair(t *testing.T, kid string) testKeyPair {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	return testKeyPair{
		pub:  jose.JSONWebKey{Key: privateKey.Public(), KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"},
		priv: jose.JSONWebKey{Key: privateKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"},
	}
}

const (
	testIssuer   = "https://tenant.auth0.com/"
	testAudience = "https://identity.example.com"
)

// auth0Token is a small fluent helper to mint signed tokens with overridable claims.
type auth0Token struct {
	Issuer      string
	Audience    string
	Subject     string
	Expiry      time.Time
	NotBefore   time.Time
	IssuedAt    time.Time
	Permissions []string
	Scope       string
	Email       string
}

func defaultAuth0Token() auth0Token {
	now := time.Now()

	return auth0Token{
		Issuer:      testIssuer,
		Audience:    testAudience,
		Subject:     "auth0|user-1",
		Expiry:      now.Add(5 * time.Minute),
		NotBefore:   now.Add(-time.Minute),
		IssuedAt:    now.Add(-time.Minute),
		Permissions: []string{DefaultRequiredScope},
	}
}

func mintToken(t *testing.T, kp testKeyPair, tok auth0Token) string {
	t.Helper()

	signingKey := jose.SigningKey{Algorithm: jose.SignatureAlgorithm(kp.priv.Algorithm), Key: kp.priv}
	signerOptions := (&jose.SignerOptions{}).WithType("JWT")

	signer, err := jose.NewSigner(signingKey, signerOptions)
	require.NoError(t, err)

	c := Claims{
		Claims: jwt.Claims{
			Issuer:    tok.Issuer,
			Subject:   tok.Subject,
			IssuedAt:  jwt.NewNumericDate(tok.IssuedAt),
			NotBefore: jwt.NewNumericDate(tok.NotBefore),
			Expiry:    jwt.NewNumericDate(tok.Expiry),
		},
		Permissions: tok.Permissions,
		Scope:       tok.Scope,
		Email:       tok.Email,
	}

	if tok.Audience != "" {
		c.Audience = jwt.Audience{tok.Audience}
	}

	raw, err := jwt.Signed(signer).Claims(c).Serialize()
	require.NoError(t, err)

	return raw
}

// jwksServer serves a JWKS over HTTP and counts requests for cache assertions.
type jwksServer struct {
	*httptest.Server
	requests atomic.Int64
}

func newJWKSServer(t *testing.T, keySet *jose.JSONWebKeySet) *jwksServer {
	t.Helper()

	js := &jwksServer{}

	js.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		js.requests.Add(1)

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(keySet); err != nil {
			t.Errorf("failed to encode key set: %v", err)
		}
	}))

	t.Cleanup(js.Close)

	return js
}

func newTestVerifier(t *testing.T, server *jwksServer) *Verifier {
	t.Helper()

	keySource := NewCachedHTTPKeySource(server.Client(), server.URL, time.Minute)

	verifier, err := NewVerifier(keySource, &Options{
		Issuer:   testIssuer,
		Audience: testAudience,
	})
	require.NoError(t, err)

	return verifier
}
