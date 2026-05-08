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
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVerifier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		options *Options
	}{
		{name: "nil options", options: nil},
		{name: "missing issuer", options: &Options{Audience: testAudience}},
		{name: "missing audience", options: &Options{Issuer: testIssuer}},
		{name: "blank issuer", options: &Options{Issuer: "   ", Audience: testAudience}},
	}

	keySource := NewCachedHTTPKeySource(nil, "https://tenant.auth0.com/.well-known/jwks.json", time.Minute)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewVerifier(keySource, tt.options)
			require.ErrorIs(t, err, ErrNotConfigured)
		})
	}
}

func TestVerifier_Issuer(t *testing.T) {
	t.Parallel()

	kp := newTestKeyPair(t, "test-kid")
	server := newJWKSServer(t, &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{kp.pub}})
	verifier := newTestVerifier(t, server)

	assert.Equal(t, testIssuer, verifier.Issuer())
}

func TestVerifier_Verify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		makeToken   func(t *testing.T, kp testKeyPair) string
		expectErrIs error
		check       func(t *testing.T, claims *Claims)
	}{
		{
			name: "bad signature rejected",
			makeToken: func(t *testing.T, _ testKeyPair) string {
				t.Helper()

				// Sign with a different key than the JWKS server publishes.
				other := newTestKeyPair(t, "test-kid")

				return mintToken(t, other, defaultAuth0Token())
			},
			expectErrIs: ErrInvalidToken,
		},
		{
			name: "expired token rejected",
			makeToken: func(t *testing.T, kp testKeyPair) string {
				t.Helper()

				tok := defaultAuth0Token()
				tok.Expiry = time.Now().Add(-time.Minute)

				return mintToken(t, kp, tok)
			},
			expectErrIs: ErrTokenExpired,
		},
		{
			name: "wrong audience rejected",
			makeToken: func(t *testing.T, kp testKeyPair) string {
				t.Helper()

				tok := defaultAuth0Token()
				tok.Audience = "https://another-api.example.com"

				return mintToken(t, kp, tok)
			},
			expectErrIs: ErrInvalidToken,
		},
		{
			name: "wrong issuer rejected",
			makeToken: func(t *testing.T, kp testKeyPair) string {
				t.Helper()

				tok := defaultAuth0Token()
				tok.Issuer = "https://other-tenant.auth0.com/"

				return mintToken(t, kp, tok)
			},
			expectErrIs: ErrInvalidToken,
		},
		{
			name: "missing required scope rejected",
			makeToken: func(t *testing.T, kp testKeyPair) string {
				t.Helper()

				tok := defaultAuth0Token()
				tok.Permissions = []string{"some:other:permission"}

				return mintToken(t, kp, tok)
			},
			expectErrIs: ErrInsufficientScope,
		},
		{
			name: "valid token with permissions claim",
			makeToken: func(t *testing.T, kp testKeyPair) string {
				t.Helper()

				return mintToken(t, kp, defaultAuth0Token())
			},
			check: func(t *testing.T, claims *Claims) {
				t.Helper()
				assert.Equal(t, "auth0|user-1", claims.Subject)
			},
		},
		{
			name: "valid token with scope claim instead of permissions",
			makeToken: func(t *testing.T, kp testKeyPair) string {
				t.Helper()

				tok := defaultAuth0Token()
				tok.Permissions = nil
				tok.Scope = "openid profile " + DefaultRequiredScope

				return mintToken(t, kp, tok)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kp := newTestKeyPair(t, "test-kid")
			server := newJWKSServer(t, &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{kp.pub}})
			verifier := newTestVerifier(t, server)

			raw := tt.makeToken(t, kp)

			claims, err := verifier.Verify(t.Context(), raw)
			if tt.expectErrIs != nil {
				require.ErrorIs(t, err, tt.expectErrIs)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, claims)

			if tt.check != nil {
				tt.check(t, claims)
			}
		})
	}

	t.Run("jwks cache hot path", func(t *testing.T) {
		t.Parallel()

		kp := newTestKeyPair(t, "test-kid")
		server := newJWKSServer(t, &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{kp.pub}})
		verifier := newTestVerifier(t, server)

		for range 5 {
			_, err := verifier.Verify(t.Context(), mintToken(t, kp, defaultAuth0Token()))
			require.NoError(t, err)
		}

		// First Verify forces a fetch; subsequent ones must be served from the cache.
		assert.Equal(t, int64(1), server.requests.Load())
	})

	t.Run("jwks kid miss triggers refresh", func(t *testing.T) {
		t.Parallel()

		original := newTestKeyPair(t, "kid-1")
		keySet := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{original.pub}}

		server := newJWKSServer(t, keySet)
		verifier := newTestVerifier(t, server)

		_, err := verifier.Verify(t.Context(), mintToken(t, original, defaultAuth0Token()))
		require.NoError(t, err)
		require.Equal(t, int64(1), server.requests.Load())

		// Mint a token with a kid the cache has never seen — should force one extra fetch.
		rotated := newTestKeyPair(t, "kid-2")
		keySet.Keys = []jose.JSONWebKey{original.pub, rotated.pub}

		_, err = verifier.Verify(t.Context(), mintToken(t, rotated, defaultAuth0Token()))
		require.NoError(t, err)
		assert.Equal(t, int64(2), server.requests.Load())
	})
}
