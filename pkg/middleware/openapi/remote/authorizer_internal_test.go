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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/util/cache"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
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

func TestValidatePassportTemporalClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		claims  *oauth2.PassportClaims
		wantErr string
	}{
		{
			name: "expiry after now is valid",
			claims: &oauth2.PassportClaims{
				Claims: jwt.Claims{Expiry: jwt.NewNumericDate(now.Add(time.Second))},
			},
		},
		{
			name: "expiry before now is rejected",
			claims: &oauth2.PassportClaims{
				Claims: jwt.Claims{Expiry: jwt.NewNumericDate(now.Add(-time.Second))},
			},
			wantErr: "passport has expired",
		},
		{
			name: "expiry equal to now is rejected",
			claims: &oauth2.PassportClaims{
				Claims: jwt.Claims{Expiry: jwt.NewNumericDate(now)},
			},
			wantErr: "passport has expired",
		},
		{
			name: "not before after now is rejected",
			claims: &oauth2.PassportClaims{
				Claims: jwt.Claims{
					Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
					NotBefore: jwt.NewNumericDate(now.Add(time.Second)),
				},
			},
			wantErr: "passport is not yet valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validatePassportTemporalClaims(tt.claims, now)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			require.ErrorIs(t, err, ErrPassportInvalid)
			assert.Contains(t, err.Error(), tt.wantErr)
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

func TestAuthorizeReturnsTheRawPassport(t *testing.T) {
	t.Parallel()

	raw := mintTestPassport(t, validTestPassportClaims())
	exchange := &recordingTokenExchange{passport: raw}
	auth := newTestAuthorizer(exchange)

	fresh, err := auth.Authorize(scopedAuthInput(t, "", ""))
	require.NoError(t, err)
	assert.Equal(t, raw, fresh.Passport, "a fresh exchange must set the raw passport")

	cached, err := auth.Authorize(scopedAuthInput(t, "", ""))
	require.NoError(t, err)
	assert.Equal(t, raw, cached.Passport, "a cache hit must return the same raw passport")
	assert.Equal(t, int32(1), exchange.calls.Load(), "the second request must be served from the cache")
}

// TestAuthorizeCacheHitDoesNotDecodeThePassport seeds an entry whose raw value
// is not a JWS. A cache hit that decodes the raw value again fails on it. A
// cache hit that returns the claims without the raw value fails the second
// assertion.
func TestAuthorizeCacheHitDoesNotDecodeThePassport(t *testing.T) {
	t.Parallel()

	exchange := &recordingTokenExchange{}
	auth := newTestAuthorizer(exchange)

	const raw = "opaque-raw-passport"

	claims := validTestPassportClaims()
	key := newTokenCacheKey(testSourceToken, tokenExchangeOptions{})
	auth.tokenCache.Add(key, cachedPassport{claims: claims, raw: raw}, time.Minute)

	info, err := auth.Authorize(scopedAuthInput(t, "", ""))
	require.NoError(t, err)
	assert.Equal(t, claims.Subject, info.Userinfo.Sub, "a cache hit must use the stored claims")
	assert.Equal(t, raw, info.Passport, "a cache hit must return the stored raw passport")
	assert.Equal(t, testSourceToken, info.Token)
	assert.Zero(t, exchange.calls.Load(), "a cache hit must not exchange the token again")
}

// passportPerTokenExchange mints a distinct passport for each source token, so a
// test can tell whose passport a request received.
type passportPerTokenExchange struct {
	t     *testing.T
	calls atomic.Int32
}

func (e *passportPerTokenExchange) Exchange(_ context.Context, sourceToken string, _ *tokenExchangeOptions) (string, error) {
	e.calls.Add(1)

	claims := validTestPassportClaims()
	claims.Subject = "user-of-" + sourceToken

	return mintTestPassport(e.t, claims), nil
}

func authInputWithToken(t *testing.T, token, organizationID, projectID string) *openapi3filter.AuthenticationInput {
	t.Helper()

	input := scopedAuthInput(t, organizationID, projectID)
	input.RequestValidationInput.Request.Header.Set("Authorization", "Bearer "+token)

	return input
}

// TestCacheKeyIncludesSourceToken guards the check body. The cached raw passport
// goes to identity, so a key without the source token would send one user's
// passport for another user's request.
func TestCacheKeyIncludesSourceToken(t *testing.T) {
	t.Parallel()

	exchange := &passportPerTokenExchange{t: t}
	auth := newTestAuthorizer(exchange)

	first, err := auth.Authorize(authInputWithToken(t, "token-a", "org-1", "proj-1"))
	require.NoError(t, err)

	second, err := auth.Authorize(authInputWithToken(t, "token-b", "org-1", "proj-1"))
	require.NoError(t, err)

	assert.Equal(t, "user-of-token-a", first.Userinfo.Sub)
	assert.Equal(t, "user-of-token-b", second.Userinfo.Sub, "a second token must not get the first token's cached claims")
	assert.NotEqual(t, first.Passport, second.Passport, "a second token must not get the first token's raw passport")
	assert.EqualValues(t, 2, exchange.calls.Load(), "each source token needs its own exchange")
}

// TestCacheKeyIncludesEachScopeField changes one scope field at a time, so a key
// that drops only that field is caught.
func TestCacheKeyIncludesEachScopeField(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		first, second [2]string
	}{
		"organization": {first: [2]string{"org-1", "proj-1"}, second: [2]string{"org-2", "proj-1"}},
		"project":      {first: [2]string{"org-1", "proj-1"}, second: [2]string{"org-1", "proj-2"}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			exchange := &recordingTokenExchange{passport: mintTestPassport(t, validTestPassportClaims())}
			auth := newTestAuthorizer(exchange)

			for _, scope := range [][2]string{tt.first, tt.second} {
				_, err := auth.Authorize(scopedAuthInput(t, scope[0], scope[1]))
				require.NoError(t, err)
			}

			assert.EqualValues(t, 2, exchange.calls.Load(), "the same token on a different %s needs its own exchange", name)
		})
	}
}

func TestAuthorizeRequestsTheServicesOwnAudience(t *testing.T) {
	t.Parallel()

	exchange := &recordingTokenExchange{passport: mintTestPassport(t, validTestPassportClaims())}
	auth := newTestAuthorizer(exchange)
	auth.clientCN = "service-cn"

	_, err := auth.Authorize(scopedAuthInput(t, "org-1", "project-1"))
	require.NoError(t, err)

	calls := exchange.recorded()
	require.Len(t, calls, 1)
	assert.Equal(t, "service-cn", calls[0].audience)
	assert.Equal(t, "org-1", calls[0].organizationID, "the audience must not replace the route scope")
}

func LargeTestPassport(tb testing.TB) string {
	tb.Helper()

	claims := validTestPassportClaims()
	claims.OrgIDs = make([]string, 56)

	for i := range claims.OrgIDs {
		claims.OrgIDs[i] = fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
	}

	claims.Groups = []string{"bound-group-one-with-a-long-name", "bound-group-two-with-a-long-name", "bound-group-three-with-a-long-name", "bound-group-four-with-a-long-name"}

	passport := mintTestPassport(tb, claims)
	if len(passport) > 4<<10 {
		tb.Fatalf("the test passport has %d bytes, more than the passport size gate", len(passport))
	}

	return passport
}

func BenchmarkCachedPassportMemory(b *testing.B) {
	passport := LargeTestPassport(b)

	decode := func(raw string) *oauth2.PassportClaims {
		claims, err := decodePassportClaims(raw)
		if err != nil {
			b.Fatal(err)
		}

		return claims
	}

	b.Run("raw", func(b *testing.B) {
		measureCacheHeap(b, passport, strings.Clone)
	})

	b.Run("claims", func(b *testing.B) {
		measureCacheHeap(b, passport, decode)
	})

	b.Run("claims_and_raw", func(b *testing.B) {
		measureCacheHeap(b, passport, func(raw string) cachedPassport {
			return cachedPassport{claims: decode(raw), raw: strings.Clone(raw)}
		})
	})
}

func measureCacheHeap[T any](b *testing.B, passport string, value func(string) T) {
	b.Helper()

	key := func(i int) tokenCacheKey {
		return newTokenCacheKey(fmt.Sprintf("source-token-%d", i), tokenExchangeOptions{})
	}

	for range b.N {
		tokenCache := cache.NewLRUExpireCache[tokenCacheKey, T](tokenCacheSize)

		var before, after runtime.MemStats

		runtime.GC()
		runtime.ReadMemStats(&before)

		for i := range tokenCacheSize {
			tokenCache.Add(key(i), value(passport), time.Minute)
		}

		runtime.GC()
		runtime.ReadMemStats(&after)

		for i := range tokenCacheSize {
			if _, ok := tokenCache.Get(key(i)); !ok {
				b.Fatalf("cache entry %d is missing, so the measurement is not of a full cache", i)
			}
		}

		b.ReportMetric(float64(after.HeapAlloc)-float64(before.HeapAlloc), "B/cache")
	}

	b.ReportMetric(float64(len(passport)), "B/passport")
}

func BenchmarkAuthorizeCacheHit(b *testing.B) {
	exchange := &recordingTokenExchange{passport: LargeTestPassport(b)}
	auth := newTestAuthorizer(exchange)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+testSourceToken)

	input := &openapi3filter.AuthenticationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{Request: req},
		SecurityScheme:         &openapi3.SecurityScheme{Type: "oauth2"},
	}

	if _, err := auth.Authorize(input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		info, err := auth.Authorize(input)
		if err != nil || info.Passport == "" {
			b.Fatalf("cache hit failed: %v", err)
		}
	}

	b.StopTimer()

	if exchange.calls.Load() != 1 {
		b.Fatalf("%d exchanges, want 1", exchange.calls.Load())
	}
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
	audience       string
}

func (e *recordingTokenExchange) Exchange(_ context.Context, sourceToken string, options *tokenExchangeOptions) (string, error) {
	e.calls.Add(1)

	call := tokenExchangeCall{sourceToken: sourceToken}
	if options != nil {
		call.organizationID = options.organizationID
		call.projectID = options.projectID
		call.audience = options.audience
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
	tokenCache := cache.NewLRUExpireCache[tokenCacheKey, cachedPassport](16)

	return &Authorizer{
		exchange:   exchange,
		tokenCache: tokenCache,
	}
}

// mintTestPassport signs test claims with the algorithm accepted by the
// production parser.
func mintTestPassport(tb testing.TB, claims *oauth2.PassportClaims) string {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(tb, err)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES512, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(tb, err)

	passport, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(tb, err)

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

// TestCacheKeyIncludesRouteScope ensures every authorization scope is validated
// by exchange before it can be served from cache.
func TestCacheKeyIncludesRouteScope(t *testing.T) {
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

	assert.EqualValues(t, len(scopes), exchange.calls.Load(),
		"same bearer token must be exchanged separately for every org/project scope")
}

// stubTokenExchange returns a fixed error from Exchange.
type stubTokenExchange struct {
	err error
}

func (s *stubTokenExchange) Exchange(_ context.Context, _ string, _ *tokenExchangeOptions) (string, error) {
	return "", s.err
}

// TestAuthorizeProjectsExchangeErrors pins the exchange-sentinel → API-edge
// error mapping so the 401/403 split cannot silently regress.
func TestAuthorizeProjectsExchangeErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		exchangeErr    error
		wantForbidden  bool
		wantAccessDeny bool
	}{
		{
			name:           "401 from exchange becomes access denied",
			exchangeErr:    ErrTokenExchangeUnauthorized,
			wantAccessDeny: true,
		},
		{
			name:          "forbidden sentinel from exchange becomes 403",
			exchangeErr:   ErrTokenExchangeForbidden,
			wantForbidden: true,
		},
		{
			name:           "generic exchange failure falls back to access denied",
			exchangeErr:    ErrTokenExchangeFailed,
			wantAccessDeny: true,
		},
		{
			name:           "unavailable (5xx/transport) falls back to access denied",
			exchangeErr:    ErrTokenExchangeUnavailable,
			wantAccessDeny: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			auth := newTestAuthorizer(&stubTokenExchange{err: tt.exchangeErr})

			info, err := auth.Authorize(scopedAuthInput(t, "org-1", ""))
			require.Error(t, err)
			require.Nil(t, info)

			if tt.wantForbidden {
				assert.True(t, coreerrors.IsForbidden(err),
					"forbidden sentinel must surface as a 403 at the API edge; got %v", err)
				assert.False(t, coreerrors.IsAccessDenied(err),
					"forbidden must not be conflated with access-denied")
			}

			if tt.wantAccessDeny {
				assert.True(t, coreerrors.IsAccessDenied(err),
					"authentication failures must surface as 401 access_denied; got %v", err)
				assert.False(t, coreerrors.IsForbidden(err),
					"authentication failures must not surface as 403")
			}
		})
	}
}

// withSrcIss returns a PassportClaims with the given src_iss set, built from
// the canonical valid test claims. It is the option function for mintTestPassport
// in tests that must assert SrcIss propagation.
func withSrcIss(srcIss string) *oauth2.PassportClaims {
	c := validTestPassportClaims()
	c.SrcIss = srcIss

	return c
}

// runRemoteAuthorizer creates a minimal Authorizer backed by a recordingTokenExchange
// that returns passport, runs Authorize against it, and returns the resulting Info.
func runRemoteAuthorizer(t *testing.T, claims *oauth2.PassportClaims) *authorization.Info {
	t.Helper()

	passport := mintTestPassport(t, claims)
	exchange := &recordingTokenExchange{passport: passport}
	auth := newTestAuthorizer(exchange)

	info, err := auth.Authorize(scopedAuthInput(t, "", ""))
	require.NoError(t, err)
	require.NotNil(t, info)

	return info
}

// TestRemoteAuthorizerPropagatesSrcIss verifies that src_iss from the decoded
// passport claims is threaded through to authorization.Info.SrcIss.
func TestRemoteAuthorizerPropagatesSrcIss(t *testing.T) {
	t.Parallel()

	const want = "https://staff.auth0.com"

	info := runRemoteAuthorizer(t, withSrcIss(want))
	if info.SrcIss != want {
		t.Fatalf("Info.SrcIss = %q, want %q", info.SrcIss, want)
	}
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

// errStubPropagated4xx stands in for a deterministic 4xx that CheckMany
// propagates verbatim (errors.PropagateError) — i.e. any error that does NOT
// wrap ErrDecisionUnavailable. A static sentinel keeps the err113 linter happy.
var errStubPropagated4xx = errors.New("propagated 4xx from identity")

// TestIsBreakerFailure pins which CheckMany errors count toward opening the
// circuit breaker. Only a genuine failure to obtain a verdict — a
// transport error, a 5xx, a malformed 200, or this package's own checkTimeout
// expiry, all folded into ErrDecisionUnavailable — must count. Caller
// cancellation (context.Canceled, even when wrapped in ErrDecisionUnavailable
// by the transport path) and a deterministic 4xx (propagated verbatim, so NOT
// ErrDecisionUnavailable) must NOT, so client behaviour cannot open a breaker
// that fail-closes authorization for unrelated users.
func TestIsBreakerFailure(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		err   error
		count bool
	}{
		{"nil (a served verdict) never counts", nil, false},
		{"transport/5xx unavailability counts", fmt.Errorf("%w: identity returned status 503", ErrDecisionUnavailable), true},
		{"our own checkTimeout (deadline exceeded) counts", fmt.Errorf("%w: %w", ErrDecisionUnavailable, context.DeadlineExceeded), true},
		{"caller cancellation wrapped in unavailable does NOT count", fmt.Errorf("%w: %w", ErrDecisionUnavailable, context.Canceled), false},
		{"bare caller cancellation does NOT count", context.Canceled, false},
		{"deterministic 4xx (propagated, not unavailable) does NOT count", errStubPropagated4xx, false},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, testCase.count, isBreakerFailure(nil, testCase.err))
		})
	}
}
