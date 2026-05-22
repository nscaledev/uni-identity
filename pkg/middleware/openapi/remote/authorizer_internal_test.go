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

package authorizer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/util/cache"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

// TestCacheTTL covers the cache expiry contract:
//
//	cache_ttl = passport.exp - now - fudge
func TestCacheTTL(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		passportExp time.Time
		want        time.Duration
	}{
		{
			name:        "60s passport yields 50s TTL after 10s fudge",
			passportExp: now.Add(60 * time.Second),
			want:        50 * time.Second,
		},
		{
			name:        "expired passport yields non-positive TTL (do not cache)",
			passportExp: now.Add(-1 * time.Second),
			want:        -11 * time.Second,
		},
		{
			name:        "passport that expires within fudge window yields non-positive TTL",
			passportExp: now.Add(5 * time.Second),
			want:        -5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			claims := &oauth2.PassportClaims{
				Claims: jwt.Claims{Expiry: jwt.NewNumericDate(tt.passportExp)},
			}

			got := cacheTTL(claims, now)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestDecodePassportClaimsRejectsMalformed keeps malformed exchange output
// from producing partial identity context.
func TestDecodePassportClaimsRejectsMalformed(t *testing.T) {
	t.Parallel()

	stringPtr := func(s string) *string { return &s }

	tests := []struct {
		name   string
		rawJWT *string
		mutate func(*oauth2.PassportClaims)
	}{
		{name: "not a JWT", rawJWT: stringPtr("not-a-jwt")},
		{name: "empty string", rawJWT: stringPtr("")},
		{name: "wrong token type", mutate: func(c *oauth2.PassportClaims) { c.Type = "access_token" }},
		{name: "missing sub", mutate: func(c *oauth2.PassportClaims) { c.Subject = "" }},
		{name: "missing exp", mutate: func(c *oauth2.PassportClaims) { c.Expiry = nil }},
		{name: "missing acctype", mutate: func(c *oauth2.PassportClaims) { c.Acctype = "" }},
		{name: "missing source", mutate: func(c *oauth2.PassportClaims) { c.Source = "" }},
		{
			name:   "exp in the past",
			mutate: func(c *oauth2.PassportClaims) { c.Expiry = jwt.NewNumericDate(time.Now().Add(-1 * time.Second)) },
		},
		{
			name:   "nbf in the future",
			mutate: func(c *oauth2.PassportClaims) { c.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Minute)) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var passport string
			if tt.rawJWT != nil {
				passport = *tt.rawJWT
			} else {
				c := validTestPassportClaims()
				tt.mutate(c)
				passport = mintTestPassport(t, c)
			}

			claims, err := decodePassportClaims(passport)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrPassportInvalid)
			assert.Nil(t, claims)
		})
	}
}

// TestAuthorizeRejectsExpiredPassport verifies stale exchange output is
// rejected and not cached.
func TestAuthorizeRejectsExpiredPassport(t *testing.T) {
	t.Parallel()

	expired := validTestPassportClaims()
	expired.Expiry = jwt.NewNumericDate(time.Now().Add(-1 * time.Second))

	exchange := &recordingTokenExchange{passport: mintTestPassport(t, expired)}
	auth := newTestAuthorizer(exchange)

	info, err := auth.Authorize(scopedAuthInput(t, "", ""))
	require.Error(t, err)
	assert.Nil(t, info)

	// A second identical request must also call exchange — nothing got cached.
	info2, err := auth.Authorize(scopedAuthInput(t, "", ""))
	require.Error(t, err)
	assert.Nil(t, info2)
	assert.Equal(t, int32(2), exchange.calls.Load(),
		"a rejected passport must never populate the cache")
}

// TestAuthorizeRejectsNotYetValidPassport ensures a syntactically valid
// passport whose nbf is still in the future is rejected. Temporal validation
// must fail closed on both stale and premature exchange output.
func TestAuthorizeRejectsNotYetValidPassport(t *testing.T) {
	t.Parallel()

	notYetValid := validTestPassportClaims()
	notYetValid.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Minute))

	exchange := &recordingTokenExchange{passport: mintTestPassport(t, notYetValid)}
	auth := newTestAuthorizer(exchange)

	info, err := auth.Authorize(scopedAuthInput(t, "", ""))
	require.Error(t, err)
	assert.Nil(t, info)

	info2, err := auth.Authorize(scopedAuthInput(t, "", ""))
	require.Error(t, err)
	assert.Nil(t, info2)
	assert.Equal(t, int32(2), exchange.calls.Load(),
		"a rejected passport must never populate the cache")
}

// TestAuthorizeDoesNotCacheNonPositiveTTL allows the current request but does
// not cache entries that are already inside the clock-skew margin.
func TestAuthorizeDoesNotCacheNonPositiveTTL(t *testing.T) {
	t.Parallel()

	nearExpiry := validTestPassportClaims()
	nearExpiry.Expiry = jwt.NewNumericDate(time.Now().Add(5 * time.Second))

	exchange := &recordingTokenExchange{passport: mintTestPassport(t, nearExpiry)}
	auth := newTestAuthorizer(exchange)

	info, err := auth.Authorize(scopedAuthInput(t, "", ""))
	require.NoError(t, err)
	require.NotNil(t, info)

	info2, err := auth.Authorize(scopedAuthInput(t, "", ""))
	require.NoError(t, err)
	require.NotNil(t, info2)

	assert.Equal(t, int32(2), exchange.calls.Load(),
		"a passport whose TTL would be ≤ 0 must not be cached, so repeat requests must re-exchange")
}

// TestPassportToUserinfo verifies projection into the handler-facing identity
// shape without synthesizing profile fields.
func TestPassportToUserinfo(t *testing.T) {
	t.Parallel()

	claims := &oauth2.PassportClaims{
		Claims:  jwt.Claims{Subject: "user-1"},
		Acctype: identityapi.User,
		Email:   "user@example.com",
		OrgIDs:  []string{"org-1", "org-2"},
	}

	userinfo := passportToUserinfo(claims)

	require.NotNil(t, userinfo)
	assert.Equal(t, "user-1", userinfo.Sub)
	require.NotNil(t, userinfo.Email)
	assert.Equal(t, "user@example.com", *userinfo.Email)
	require.NotNil(t, userinfo.HttpsunikornCloudOrgauthz)
	assert.Equal(t, identityapi.User, userinfo.HttpsunikornCloudOrgauthz.Acctype)
	assert.Equal(t, []string{"org-1", "org-2"}, userinfo.HttpsunikornCloudOrgauthz.OrgIds)

	assert.Nil(t, userinfo.Name)
	assert.Nil(t, userinfo.Picture)
}

func TestPassportToUserinfoOmitsEmptyEmail(t *testing.T) {
	t.Parallel()

	claims := &oauth2.PassportClaims{
		Claims:  jwt.Claims{Subject: "service-1"},
		Acctype: identityapi.Service,
		OrgIDs:  []string{"org-1"},
	}

	userinfo := passportToUserinfo(claims)
	assert.Nil(t, userinfo.Email)
}

type recordingTokenExchange struct {
	passport string
	calls    atomic.Int32
	mu       atomic.Pointer[[]tokenExchangeCall]
}

type tokenExchangeCall struct {
	sourceToken    string
	organizationID string
	projectID      string
}

func (e *recordingTokenExchange) Exchange(_ context.Context, sourceToken string, options *tokenExchangeOptions) (string, error) {
	e.calls.Add(1)

	call := tokenExchangeCall{sourceToken: sourceToken}
	if options != nil {
		call.organizationID = options.organizationID
		call.projectID = options.projectID
	}

	existing := e.mu.Load()

	var next []tokenExchangeCall
	if existing != nil {
		next = append(next, *existing...)
	}

	next = append(next, call)
	e.mu.Store(&next)

	return e.passport, nil
}

func (e *recordingTokenExchange) recorded() []tokenExchangeCall {
	if v := e.mu.Load(); v != nil {
		return *v
	}

	return nil
}

func newTestAuthorizer(exchange TokenExchange) *Authorizer {
	tokenCache := cache.NewLRUExpireCache[tokenCacheKey, *identityapi.Userinfo](16)

	return &Authorizer{
		exchange:   exchange,
		tokenCache: tokenCache,
	}
}

// mintTestPassport signs test claims with the algorithm accepted by the
// production parser.
func mintTestPassport(t *testing.T, claims *oauth2.PassportClaims) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES512, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)

	passport, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	return passport
}

const testSourceToken = "raw-token"

func validTestPassportClaims() *oauth2.PassportClaims {
	now := time.Now()

	return &oauth2.PassportClaims{
		Claims: jwt.Claims{
			Subject:  "user-1",
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(60 * time.Second)),
		},
		Type:    oauth2.PassportType,
		Acctype: identityapi.User,
		Source:  oauth2.PassportSourceUNI,
		OrgIDs:  []string{"org-1", "org-2"},
	}
}

func scopedAuthInput(t *testing.T, organizationID, projectID string) *openapi3filter.AuthenticationInput {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+testSourceToken)

	params := map[string]string{}
	if organizationID != "" {
		params["organizationID"] = organizationID
	}

	if projectID != "" {
		params["projectID"] = projectID
	}

	return &openapi3filter.AuthenticationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request:    req,
			PathParams: params,
		},
		SecurityScheme: &openapi3.SecurityScheme{Type: "oauth2"},
	}
}

// TestExchangePropagatesRouteScope verifies route scope reaches the exchange
// request under the token endpoint's canonical field names.
func TestExchangePropagatesRouteScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		organizationID string
		projectID      string
	}{
		{name: "no scope", organizationID: "", projectID: ""},
		{name: "org only", organizationID: "org-1", projectID: ""},
		{name: "org and project", organizationID: "org-1", projectID: "proj-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			passport := mintTestPassport(t, validTestPassportClaims())

			exchange := &recordingTokenExchange{passport: passport}
			auth := newTestAuthorizer(exchange)

			info, err := auth.Authorize(scopedAuthInput(t, tt.organizationID, tt.projectID))
			require.NoError(t, err)
			require.NotNil(t, info)

			calls := exchange.recorded()
			require.Len(t, calls, 1)
			assert.Equal(t, "raw-token", calls[0].sourceToken)
			assert.Equal(t, tt.organizationID, calls[0].organizationID)
			assert.Equal(t, tt.projectID, calls[0].projectID)
		})
	}
}

// TestCacheIsolationByScope prevents one route scope from reusing another
// scope's derived identity.
func TestCacheIsolationByScope(t *testing.T) {
	t.Parallel()

	passport := mintTestPassport(t, validTestPassportClaims())

	exchange := &recordingTokenExchange{passport: passport}
	auth := newTestAuthorizer(exchange)

	scopes := []struct {
		organizationID string
		projectID      string
	}{
		{"", ""},
		{"org-1", ""},
		{"org-1", "proj-1"},
		{"org-2", ""},
	}

	for _, scope := range scopes {
		info, err := auth.Authorize(scopedAuthInput(t, scope.organizationID, scope.projectID))
		require.NoError(t, err)
		require.NotNil(t, info)
	}

	assert.Equal(t, int32(len(scopes)), exchange.calls.Load(), //nolint:gosec // small slice length, no overflow risk.
		"each unique scope must hit exchange — none should be served from a sibling scope's cache entry")
}

// TestCacheHitWithinScope confirms repeated requests at the same scope still
// use the cache.
func TestCacheHitWithinScope(t *testing.T) {
	t.Parallel()

	passport := mintTestPassport(t, validTestPassportClaims())

	exchange := &recordingTokenExchange{passport: passport}
	auth := newTestAuthorizer(exchange)

	for range 3 {
		info, err := auth.Authorize(scopedAuthInput(t, "org-1", "proj-1"))
		require.NoError(t, err)
		require.NotNil(t, info)
	}

	assert.Equal(t, int32(1), exchange.calls.Load(),
		"identical (token, org, project) requests must be served from cache after the first exchange")
}
