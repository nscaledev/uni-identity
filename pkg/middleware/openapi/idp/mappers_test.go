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

package idp_test

import (
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/idp"
	"github.com/unikorn-cloud/identity/pkg/openapi"
)

const (
	emailClaim    = "https://unikorn-cloud.org/email"
	verifiedClaim = "https://unikorn-cloud.org/email_verified"
)

func payload(t *testing.T, m map[string]any) []byte {
	t.Helper()

	b, err := json.Marshal(m)
	require.NoError(t, err)

	return b
}

// TestEmailUserMapper covers the federated-user transform: a verified email
// becomes the (lower-cased) subject, while machine grants and unverified or
// missing emails are rejected.
func TestEmailUserMapper(t *testing.T) {
	t.Parallel()

	mapper := idp.EmailUserMapper(emailClaim, verifiedClaim)

	t.Run("MapsVerifiedEmailToUser", func(t *testing.T) {
		t.Parallel()

		p, err := mapper(jwt.Claims{}, payload(t, map[string]any{
			emailClaim:    "Alice@Example.com",
			verifiedClaim: true,
		}))
		require.NoError(t, err)
		assert.Equal(t, "alice@example.com", p.Subject)
		assert.Equal(t, openapi.User, p.Type)
	})

	t.Run("RejectsClientCredentialsGrant", func(t *testing.T) {
		t.Parallel()

		_, err := mapper(jwt.Claims{}, payload(t, map[string]any{
			"gty":         "client-credentials",
			emailClaim:    "alice@example.com",
			verifiedClaim: true,
		}))
		require.ErrorIs(t, err, idp.ErrNotAUser)
	})

	t.Run("RejectsMissingEmail", func(t *testing.T) {
		t.Parallel()

		_, err := mapper(jwt.Claims{}, payload(t, map[string]any{verifiedClaim: true}))
		require.ErrorIs(t, err, idp.ErrMissingEmail)
	})

	t.Run("RejectsUnverifiedEmail", func(t *testing.T) {
		t.Parallel()

		_, err := mapper(jwt.Claims{}, payload(t, map[string]any{
			emailClaim:    "alice@example.com",
			verifiedClaim: false,
		}))
		require.ErrorIs(t, err, idp.ErrEmailUnverified)
	})
}

// TestSubjectTypeMapper covers the platform transform: subject from the standard
// claim, account type from a configured claim via a value map.
func TestSubjectTypeMapper(t *testing.T) {
	t.Parallel()

	mapper := idp.SubjectTypeMapper("typ", map[string]openapi.AuthClaimsAcctype{
		"fed": openapi.User,
		"sa":  openapi.Service,
	})

	t.Run("MapsSubjectAndType", func(t *testing.T) {
		t.Parallel()

		p, err := mapper(jwt.Claims{Subject: "user-1"}, payload(t, map[string]any{"typ": "sa"}))
		require.NoError(t, err)
		assert.Equal(t, "user-1", p.Subject)
		assert.Equal(t, openapi.Service, p.Type)
	})

	t.Run("RejectsMissingSubject", func(t *testing.T) {
		t.Parallel()

		_, err := mapper(jwt.Claims{}, payload(t, map[string]any{"typ": "fed"}))
		require.ErrorIs(t, err, idp.ErrInvalidToken)
	})

	t.Run("RejectsUnknownType", func(t *testing.T) {
		t.Parallel()

		_, err := mapper(jwt.Claims{Subject: "user-1"}, payload(t, map[string]any{"typ": "bogus"}))
		require.ErrorIs(t, err, idp.ErrInvalidToken)
	})
}
