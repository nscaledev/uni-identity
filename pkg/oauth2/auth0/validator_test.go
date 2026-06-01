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

package auth0_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/oauth2/auth0"
)

const validatorTestAudience = "https://identity.example.com"

type validatorTestIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newValidatorTestIssuer(t *testing.T) *validatorTestIssuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		publicKey := gojose.JSONWebKey{
			Key:       &key.PublicKey,
			KeyID:     "test-key",
			Algorithm: string(gojose.RS256),
			Use:       "sig",
		}

		assert.NoError(t, json.NewEncoder(w).Encode(gojose.JSONWebKeySet{
			Keys: []gojose.JSONWebKey{publicKey},
		}))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return &validatorTestIssuer{
		server: server,
		key:    key,
	}
}

func (i *validatorTestIssuer) issuer() string {
	return i.server.URL + "/"
}

type testAuthzClaims struct {
	Acctype string   `json:"acctype"`
	OrgIDs  []string `json:"orgIds"`
}

//nolint:tagliatelle
type testTokenClaims struct {
	jwt.Claims

	Email         string          `json:"email,omitempty"`
	EmailVerified *bool           `json:"email_verified,omitempty"`
	Authz         testAuthzClaims `json:"https://unikorn-cloud.org/authz,omitempty"`
}

func (i *validatorTestIssuer) token(t *testing.T, mutate func(*testTokenClaims)) string {
	t.Helper()

	now := time.Now()
	verified := true

	claims := &testTokenClaims{
		Claims: jwt.Claims{
			Issuer:   i.issuer(),
			Subject:  "auth0|user",
			Audience: jwt.Audience{validatorTestAudience},
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(time.Minute)),
		},
		Email:         "User@Example.COM",
		EmailVerified: &verified,
		Authz: testAuthzClaims{
			Acctype: "user",
			OrgIDs:  []string{"org-1"},
		},
	}

	if mutate != nil {
		mutate(claims)
	}

	signer, err := gojose.NewSigner(
		gojose.SigningKey{
			Algorithm: gojose.RS256,
			Key: gojose.JSONWebKey{
				Key:   i.key,
				KeyID: "test-key",
			},
		},
		(&gojose.SignerOptions{}).WithType("at+jwt"),
	)
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	return token
}

func newTestValidator(t *testing.T, issuer string) *auth0.Validator {
	t.Helper()

	validator, err := auth0.NewValidator(auth0.Options{
		Issuer:   issuer,
		Audience: validatorTestAudience,
	})
	require.NoError(t, err)
	require.NotNil(t, validator)

	return validator
}

func TestValidate(t *testing.T) {
	t.Parallel()

	issuer := newValidatorTestIssuer(t)
	validator := newTestValidator(t, issuer.issuer())

	user, err := validator.Validate(t.Context(), issuer.token(t, nil))
	require.NoError(t, err)

	assert.Equal(t, "user@example.com", user.Email)
	assert.True(t, user.Expiry.After(time.Now()))
}

func TestValidateRejectsInvalidClaims(t *testing.T) {
	t.Parallel()

	issuer := newValidatorTestIssuer(t)

	testCases := []struct {
		name   string
		mutate func(*testTokenClaims)
		target error
	}{
		{
			name: "wrong issuer",
			mutate: func(claims *testTokenClaims) {
				claims.Issuer = "https://wrong.example.com/"
			},
			target: auth0.ErrInvalidToken,
		},
		{
			name: "wrong audience",
			mutate: func(claims *testTokenClaims) {
				claims.Audience = jwt.Audience{"https://wrong.example.com"}
			},
			target: auth0.ErrInvalidToken,
		},
		{
			name: "expired",
			mutate: func(claims *testTokenClaims) {
				claims.Expiry = jwt.NewNumericDate(time.Now().Add(-1 * time.Minute))
			},
			target: auth0.ErrInvalidToken,
		},
		{
			name: "not yet valid",
			mutate: func(claims *testTokenClaims) {
				claims.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Minute))
			},
			target: auth0.ErrInvalidToken,
		},
		{
			name: "missing email",
			mutate: func(claims *testTokenClaims) {
				claims.Email = ""
			},
			target: auth0.ErrMissingEmail,
		},
		{
			name: "unverified email",
			mutate: func(claims *testTokenClaims) {
				verified := false
				claims.EmailVerified = &verified
			},
			target: auth0.ErrEmailUnverified,
		},
		{
			name: "wrong account type",
			mutate: func(claims *testTokenClaims) {
				claims.Authz.Acctype = "service"
			},
			target: auth0.ErrInvalidAuthzClaim,
		},
		{
			name: "empty org IDs",
			mutate: func(claims *testTokenClaims) {
				claims.Authz.OrgIDs = nil
			},
			target: auth0.ErrInvalidAuthzClaim,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			validator := newTestValidator(t, issuer.issuer())

			_, err := validator.Validate(t.Context(), issuer.token(t, test.mutate))
			require.Error(t, err)
			assert.ErrorIs(t, err, test.target)
		})
	}
}

func TestNewValidatorRejectsPartialConfig(t *testing.T) {
	t.Parallel()

	validator, err := auth0.NewValidator(auth0.Options{Issuer: "https://tenant.auth0.com/"})
	require.ErrorIs(t, err, auth0.ErrInvalidConfig)
	assert.Nil(t, validator)
}
