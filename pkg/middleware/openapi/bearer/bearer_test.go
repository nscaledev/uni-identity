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

package bearer_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/bearer"
)

func TestIsJWE(t *testing.T) {
	t.Parallel()

	header := func(claims string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(claims))
	}

	testCases := []struct {
		name        string
		token       string
		expectJWE   bool
		expectError bool
	}{
		{
			name:      "JWS is not a JWE",
			token:     header(`{"alg":"RS256","typ":"at+jwt"}`) + ".payload.signature",
			expectJWE: false,
		},
		{
			name:      "JWE detected by enc header",
			token:     header(`{"alg":"A256GCMKW","enc":"A256GCM"}`) + ".key.iv.ciphertext.tag",
			expectJWE: true,
		},
		{
			name:        "opaque token has no header",
			token:       "opaque-token",
			expectError: true,
		},
		{
			name:        "undecodable header",
			token:       "!!!.payload.signature",
			expectError: true,
		},
		{
			name:        "unparseable header",
			token:       header("not json") + ".payload.signature",
			expectError: true,
		},
		{
			name:        "header without alg is neither",
			token:       header(`{"enc":"A256GCM"}`) + ".key.iv.ciphertext.tag",
			expectError: true,
		},
		{
			name:        "empty token",
			token:       "",
			expectError: true,
		},
		{
			name:      "case-mismatched Enc is not treated as enc",
			token:     header(`{"alg":"RS256","Enc":"A256GCM"}`) + ".payload.signature",
			expectJWE: false,
		},
		{
			name:        "case-mismatched ALG fails the alg check",
			token:       header(`{"ALG":"RS256"}`) + ".payload.signature",
			expectError: true,
		},
		{
			name:        "JWS header with JWE segment count",
			token:       header(`{"alg":"RS256"}`) + ".a.b.c.d",
			expectError: true,
		},
		{
			name:        "JWE header with JWS segment count",
			token:       header(`{"alg":"A256GCMKW","enc":"A256GCM"}`) + ".payload.signature",
			expectError: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			isJWE, err := bearer.IsJWE(test.token)

			if test.expectError {
				require.ErrorIs(t, err, bearer.ErrUnrecognized)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.expectJWE, isJWE)
		})
	}
}

// signRS256 signs claims into a compact JWS — the shape UnverifiedIssuer reads
// the issuer from without verifying the signature.
func signRS256(t *testing.T, claims any) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer, err := gojose.NewSigner(
		gojose.SigningKey{Algorithm: gojose.RS256, Key: key},
		(&gojose.SignerOptions{}).WithType("at+jwt"),
	)
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	return token
}

func TestUnverifiedIssuer(t *testing.T) {
	t.Parallel()

	t.Run("ReadsIssuerFromValidJWS", func(t *testing.T) {
		t.Parallel()

		token := signRS256(t, jwt.Claims{Issuer: "https://issuer.example.com", Subject: "sub"})

		issuer, err := bearer.UnverifiedIssuer(token)
		require.NoError(t, err)
		assert.Equal(t, "https://issuer.example.com", issuer)
	})

	t.Run("RejectsJWSWithoutIssuer", func(t *testing.T) {
		t.Parallel()

		token := signRS256(t, jwt.Claims{Subject: "sub"})

		_, err := bearer.UnverifiedIssuer(token)
		require.ErrorIs(t, err, bearer.ErrUnrecognized)
	})

	t.Run("RejectsNonJWS", func(t *testing.T) {
		t.Parallel()

		// A JWE-shaped (five-segment) token has no readable JWS payload.
		_, err := bearer.UnverifiedIssuer("a.b.c.d.e")
		require.ErrorIs(t, err, bearer.ErrUnrecognized)
	})

	t.Run("RejectsGarbage", func(t *testing.T) {
		t.Parallel()

		_, err := bearer.UnverifiedIssuer("not-a-token")
		require.ErrorIs(t, err, bearer.ErrUnrecognized)
	})
}
