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
	"encoding/base64"
	"testing"

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
