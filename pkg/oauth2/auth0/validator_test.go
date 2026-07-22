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
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
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
	server      *httptest.Server
	jwksFetches atomic.Int64

	mu          sync.Mutex
	generation  int
	kid         string
	key         *rsa.PrivateKey
	attackerKey *rsa.PrivateKey
}

// rotate replaces the issuer's signing key with a freshly generated one
// under a new kid, mimicking an Auth0 signing key rotation.
func (i *validatorTestIssuer) rotate(t *testing.T) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	i.mu.Lock()
	defer i.mu.Unlock()

	i.generation++
	i.kid = fmt.Sprintf("test-key-%d", i.generation)
	i.key = key
}

func (i *validatorTestIssuer) signingKey() (*rsa.PrivateKey, string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	return i.key, i.kid
}

func newValidatorTestIssuer(t *testing.T) *validatorTestIssuer {
	t.Helper()

	issuer := &validatorTestIssuer{}
	issuer.rotate(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		issuer.jwksFetches.Add(1)

		key, kid := issuer.signingKey()

		publicKey := gojose.JSONWebKey{
			Key:       &key.PublicKey,
			KeyID:     kid,
			Algorithm: string(gojose.RS256),
			Use:       "sig",
		}

		assert.NoError(t, json.NewEncoder(w).Encode(gojose.JSONWebKeySet{
			Keys: []gojose.JSONWebKey{publicKey},
		}))
	})

	issuer.server = httptest.NewServer(mux)
	t.Cleanup(issuer.server.Close)

	return issuer
}

func (i *validatorTestIssuer) issuer() string {
	return i.server.URL
}

type testAuthzClaims struct {
	Acctype string   `json:"acctype"`
	OrgIDs  []string `json:"orgIds"`
}

//nolint:tagliatelle
type testTokenClaims struct {
	jwt.Claims

	Email         string          `json:"https://unikorn-cloud.org/email,omitempty"`
	EmailVerified *bool           `json:"https://unikorn-cloud.org/email_verified,omitempty"`
	Authz         testAuthzClaims `json:"https://unikorn-cloud.org/authz,omitempty"`
}

func (i *validatorTestIssuer) token(t *testing.T, mutate func(*testTokenClaims)) string {
	t.Helper()

	key, kid := i.signingKey()

	return i.signedToken(t, key, kid, mutate)
}

// forgedToken returns a token with well-formed claims that reuses the
// issuer's advertised kid but is signed by a key the issuer does not hold.
// The attacker key is generated lazily and reused across calls.
func (i *validatorTestIssuer) forgedToken(t *testing.T) string {
	t.Helper()

	i.mu.Lock()

	if i.attackerKey == nil {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		i.attackerKey = key
	}

	attackerKey := i.attackerKey
	i.mu.Unlock()

	_, kid := i.signingKey()

	return i.signedToken(t, attackerKey, kid, nil)
}

func (i *validatorTestIssuer) signedToken(t *testing.T, key *rsa.PrivateKey, kid string, mutate func(*testTokenClaims)) string {
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
				Key:   key,
				KeyID: kid,
			},
		},
		(&gojose.SignerOptions{}).WithType("at+jwt"),
	)
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	return token
}

func newTestValidator(t *testing.T, options auth0.Options) *auth0.Validator {
	t.Helper()

	validator, err := auth0.NewValidator(options)
	require.NoError(t, err)
	require.NotNil(t, validator)

	return validator
}

func TestValidate(t *testing.T) {
	t.Parallel()

	issuer := newValidatorTestIssuer(t)
	validator := newTestValidator(t, auth0.Options{
		Issuer:            issuer.issuer(),
		Audience:          validatorTestAudience,
		RequireAuthzClaim: true,
	})

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

			validator := newTestValidator(t, auth0.Options{
				Issuer:            issuer.issuer(),
				Audience:          validatorTestAudience,
				RequireAuthzClaim: true,
			})

			_, err := validator.Validate(t.Context(), issuer.token(t, test.mutate))
			require.Error(t, err)
			assert.ErrorIs(t, err, test.target)
		})
	}
}

// TestValidateThrottlesForgedTokenJWKSFetches documents the JWKS DoS
// mitigation. go-oidc refetches the JWKS whenever no cached key verifies a
// token's signature, so without a bound, forged tokens reusing a known kid
// would drive one Auth0 request per token and exhaust the tenant rate limit.
// Within the refresh interval, forged tokens must be rejected without any
// additional JWKS fetch, while legitimate tokens keep validating against the
// cached key.
func TestValidateThrottlesForgedTokenJWKSFetches(t *testing.T) {
	t.Parallel()

	issuer := newValidatorTestIssuer(t)
	validator := newTestValidator(t, auth0.Options{
		Issuer:   issuer.issuer(),
		Audience: validatorTestAudience,
	})

	// Prime the key cache; this is the one permitted fetch in the window.
	_, err := validator.Validate(t.Context(), issuer.token(t, nil))
	require.NoError(t, err)
	require.Equal(t, int64(1), issuer.jwksFetches.Load())

	for range 5 {
		_, err := validator.Validate(t.Context(), issuer.forgedToken(t))
		require.ErrorIs(t, err, auth0.ErrInvalidToken)
	}

	assert.Equal(t, int64(1), issuer.jwksFetches.Load())

	// Legitimate traffic is unaffected by the throttle: the cached key
	// verifies it without an upstream fetch.
	_, err = validator.Validate(t.Context(), issuer.token(t, nil))
	require.NoError(t, err)
	assert.Equal(t, int64(1), issuer.jwksFetches.Load())
}

// TestValidatePicksUpKeyRotation documents that the JWKS fetch throttle does
// not break legitimate key rotation: once the refresh interval has elapsed,
// a token signed by a rotated key triggers exactly one refetch and validates.
func TestValidatePicksUpKeyRotation(t *testing.T) {
	t.Parallel()

	issuer := newValidatorTestIssuer(t)

	// A nanosecond interval keeps the throttle in the fetch path while
	// guaranteeing the rotation happens after the window, without needing
	// clock control. Within-window rejection is pinned by the forged-token
	// and transport tests.
	validator, err := auth0.NewValidator(auth0.Options{
		Issuer:                 issuer.issuer(),
		Audience:               validatorTestAudience,
		JWKSMinRefreshInterval: time.Nanosecond,
	})
	require.NoError(t, err)

	_, err = validator.Validate(t.Context(), issuer.token(t, nil))
	require.NoError(t, err)
	require.Equal(t, int64(1), issuer.jwksFetches.Load())

	issuer.rotate(t)

	// The rotated kid is not in the key cache, so validation must refetch
	// the JWKS, and exactly once.
	_, err = validator.Validate(t.Context(), issuer.token(t, nil))
	require.NoError(t, err)
	assert.Equal(t, int64(2), issuer.jwksFetches.Load())
}

func TestNewValidatorRejectsPartialConfig(t *testing.T) {
	t.Parallel()

	validator, err := auth0.NewValidator(auth0.Options{Issuer: "https://tenant.auth0.com/"})
	require.ErrorIs(t, err, auth0.ErrInvalidConfig)
	assert.Nil(t, validator)
}

func TestNewValidatorRejectsSymmetricAlgorithm(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		alg  string
	}{
		{name: "HS256", alg: "HS256"},
		{name: "none", alg: "none"},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			validator, err := auth0.NewValidator(auth0.Options{
				Issuer:                     "https://tenant.auth0.com/",
				Audience:                   validatorTestAudience,
				SupportedSigningAlgorithms: []string{test.alg},
			})
			require.ErrorIs(t, err, auth0.ErrInvalidConfig)
			assert.Nil(t, validator)
		})
	}
}

func TestValidateSkipEmailVerification(t *testing.T) {
	t.Parallel()

	issuer := newValidatorTestIssuer(t)

	validator := newTestValidator(t, auth0.Options{
		Issuer:                issuer.issuer(),
		Audience:              validatorTestAudience,
		SkipEmailVerification: true,
	})

	unverified := false

	user, err := validator.Validate(t.Context(), issuer.token(t, func(claims *testTokenClaims) {
		claims.EmailVerified = &unverified
	}))
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", user.Email)
}

func TestValidateRequireAuthzClaimOffToleratesMissing(t *testing.T) {
	t.Parallel()

	issuer := newValidatorTestIssuer(t)

	validator := newTestValidator(t, auth0.Options{
		Issuer:            issuer.issuer(),
		Audience:          validatorTestAudience,
		RequireAuthzClaim: false,
	})

	user, err := validator.Validate(t.Context(), issuer.token(t, func(claims *testTokenClaims) {
		claims.Authz = testAuthzClaims{}
	}))
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", user.Email)
}
