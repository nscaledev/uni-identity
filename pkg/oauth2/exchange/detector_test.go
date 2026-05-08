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

package exchange_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/oauth2/exchange"
)

const (
	uniIssuer   = "uni-identity"
	auth0Issuer = "https://tenant.auth0.com/"
)

// fakeJWT mints a structurally-valid JWT (header.payload.signature) whose payload
// carries the given iss claim. Signature is junk — Detect must not verify.
func fakeJWT(t *testing.T, iss string) string {
	t.Helper()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))

	payloadJSON, err := json.Marshal(struct {
		Issuer string `json:"iss"`
	}{Issuer: iss})
	require.NoError(t, err)

	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig := base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature"))

	return header + "." + payload + "." + sig
}

func TestSourceDetector_Detect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		token       func(t *testing.T) string
		expected    exchange.Source
		expectErrIs error
	}{
		{
			name: "uni issuer routes to uni",
			token: func(t *testing.T) string {
				t.Helper()
				return fakeJWT(t, uniIssuer)
			},
			expected: exchange.SourceUNI,
		},
		{
			name: "auth0 issuer routes to auth0",
			token: func(t *testing.T) string {
				t.Helper()
				return fakeJWT(t, auth0Issuer)
			},
			expected: exchange.SourceAuth0,
		},
		{
			name: "unknown issuer returns SourceUnknown",
			token: func(t *testing.T) string {
				t.Helper()
				return fakeJWT(t, "https://attacker.example.com/")
			},
			expected: exchange.SourceUnknown,
		},
		{
			name: "missing iss claim returns SourceUnknown",
			token: func(t *testing.T) string {
				t.Helper()
				return fakeJWT(t, "")
			},
			expected: exchange.SourceUnknown,
		},
		{
			name: "malformed token surfaces ErrMalformedToken",
			token: func(t *testing.T) string {
				t.Helper()
				return "not-a-jwt"
			},
			expectErrIs: exchange.ErrMalformedToken,
		},
		{
			name: "non-base64 payload surfaces ErrMalformedToken",
			token: func(t *testing.T) string {
				t.Helper()
				return "header.<<<bad>>>.sig"
			},
			expectErrIs: exchange.ErrMalformedToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			detector := exchange.NewSourceDetector(uniIssuer, auth0Issuer)

			source, err := detector.Detect(tt.token(t))
			if tt.expectErrIs != nil {
				require.ErrorIs(t, err, tt.expectErrIs)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, source)
		})
	}
}

func TestSourceDetector_DisabledSource(t *testing.T) {
	t.Parallel()

	// Auth0 left blank — tokens minted by Auth0's issuer must route to Unknown,
	// proving operators that haven't configured Auth0 cannot accidentally route.
	detector := exchange.NewSourceDetector(uniIssuer, "")

	source, err := detector.Detect(fakeJWT(t, auth0Issuer))
	require.NoError(t, err)
	assert.Equal(t, exchange.SourceUnknown, source)
}
