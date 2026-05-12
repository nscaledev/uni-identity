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

package passport //nolint:testpackage

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityoauth2 "github.com/unikorn-cloud/identity/pkg/oauth2"
)

func newVerifierServer(t *testing.T, keySet *jose.JSONWebKeySet) (*httptest.Server, *Verifier) {
	t.Helper()

	return newVerifierServerWithAudiences(t, keySet, nil)
}

func newVerifierServerWithAudiences(t *testing.T, keySet *jose.JSONWebKeySet, audiences []string) (*httptest.Server, *Verifier) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(keySet); err != nil {
			t.Errorf("failed to encode key set: %v", err)
		}
	}))

	t.Cleanup(server.Close)

	keySource := NewCachedHTTPKeySource(server.Client(), JWKSURL(server.URL), time.Minute)

	return server, NewVerifier(keySource, audiences)
}

func TestVerifier_Verify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		makeToken   func(t *testing.T, keyPair testKeyPair) string
		closeServer bool
		expectErrIs error
		checkClaims func(t *testing.T, claims *identityoauth2.PassportClaims)
	}{
		{
			name: "returns not passport error for jwt with no typ claim",
			makeToken: func(t *testing.T, keyPair testKeyPair) string {
				t.Helper()

				signingKey := jose.SigningKey{Algorithm: jose.ES512, Key: keyPair.priv}
				signerOptions := (&jose.SignerOptions{}).WithType("JWT")

				signer, err := jose.NewSigner(signingKey, signerOptions)
				require.NoError(t, err)

				token, err := jwt.Signed(signer).Claims(jwt.Claims{Subject: "sub"}).Serialize()
				require.NoError(t, err)

				return token
			},
			expectErrIs: ErrNotPassport,
		},
		{
			name: "returns not passport error for jwt with wrong typ value",
			makeToken: func(t *testing.T, keyPair testKeyPair) string {
				t.Helper()

				signingKey := jose.SigningKey{Algorithm: jose.ES512, Key: keyPair.priv}
				signerOptions := (&jose.SignerOptions{}).WithType("JWT")

				signer, err := jose.NewSigner(signingKey, signerOptions)
				require.NoError(t, err)

				claims := map[string]any{
					"sub": "subject",
					"typ": "access_token",
					"exp": time.Now().Add(time.Minute).Unix(),
				}

				token, err := jwt.Signed(signer).Claims(claims).Serialize()
				require.NoError(t, err)

				return token
			},
			expectErrIs: ErrNotPassport,
		},
		{
			name: "returns parsed claims for valid passport",
			makeToken: func(t *testing.T, keyPair testKeyPair) string {
				t.Helper()
				return mintPassport(t, keyPair)
			},
			checkClaims: func(t *testing.T, claims *identityoauth2.PassportClaims) {
				t.Helper()
				assert.Equal(t, identityoauth2.PassportType, claims.Type)
				assert.Equal(t, "test-subject", claims.Subject)
			},
		},
		{
			name: "returns expired error for expired token",
			makeToken: func(t *testing.T, keyPair testKeyPair) string {
				t.Helper()
				return mintPassport(t, keyPair, withExpired)
			},
			expectErrIs: ErrPassportExpired,
		},
		{
			name: "returns invalid signature error for wrong key material",
			makeToken: func(t *testing.T, keyPair testKeyPair) string {
				t.Helper()
				otherKeyPair := newTestKeyPair(t, "vfy-kid")

				return mintPassport(t, otherKeyPair)
			},
			expectErrIs: ErrPassportInvalidSig,
		},
		{
			name:        "returns jwks unavailable error when endpoint is unreachable",
			closeServer: true,
			makeToken: func(t *testing.T, keyPair testKeyPair) string {
				t.Helper()
				return mintPassport(t, keyPair)
			},
			expectErrIs: ErrJWKSUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			keyPair := newTestKeyPair(t, "vfy-kid")
			keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{keyPair.pub}}
			server, verifier := newVerifierServer(t, &keySet)

			if tt.closeServer {
				server.Close()
			}

			token := tt.makeToken(t, keyPair)

			claims, err := verifier.Verify(t.Context(), token)

			if tt.expectErrIs != nil {
				assert.ErrorIs(t, err, tt.expectErrIs)
			} else {
				require.NoError(t, err)
				require.NotNil(t, claims)

				if tt.checkClaims != nil {
					tt.checkClaims(t, claims)
				}
			}
		})
	}
}

func TestVerifier_Audience(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		audiences   []string
		tokenAud    []string
		expectErrIs error
	}{
		{
			name:      "accepts token whose aud claim contains the expected audience",
			audiences: []string{"uni-region"},
			tokenAud:  []string{"uni-region"},
		},
		{
			name:      "accepts token whose aud claim contains any of the expected audiences",
			audiences: []string{"uni-region", "uni-compute"},
			tokenAud:  []string{"uni-compute"},
		},
		{
			name:        "rejects token minted for a different audience",
			audiences:   []string{"uni-region"},
			tokenAud:    []string{"uni-compute"},
			expectErrIs: ErrPassportInvalidSig,
		},
		{
			name:        "rejects token with no aud claim when audience binding is required",
			audiences:   []string{"uni-region"},
			tokenAud:    nil,
			expectErrIs: ErrPassportInvalidSig,
		},
		{
			name:      "accepts token regardless of aud when verifier has no audience binding",
			audiences: nil,
			tokenAud:  []string{"some-other-service"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			keyPair := newTestKeyPair(t, "vfy-kid")
			keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{keyPair.pub}}
			_, verifier := newVerifierServerWithAudiences(t, &keySet, tt.audiences)

			var opts []func(*identityoauth2.PassportClaims)
			if tt.tokenAud != nil {
				opts = append(opts, withAudience(tt.tokenAud...))
			}

			token := mintPassport(t, keyPair, opts...)

			_, err := verifier.Verify(t.Context(), token)

			if tt.expectErrIs != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.expectErrIs)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
