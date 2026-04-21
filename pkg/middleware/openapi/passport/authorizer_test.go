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

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/mock"
	identityoauth2 "github.com/unikorn-cloud/identity/pkg/oauth2"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"

	"k8s.io/apimachinery/pkg/util/cache"
)

// oauth2AuthInput builds a minimal AuthenticationInput carrying the given bearer token.
func oauth2AuthInput(rawToken string) *openapi3filter.AuthenticationInput {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	if rawToken != "" {
		request.Header.Set("Authorization", "Bearer "+rawToken)
	}

	return &openapi3filter.AuthenticationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{Request: request},
		SecurityScheme:         &openapi3.SecurityScheme{Type: "oauth2"},
	}
}

func newAuthorizerWithMock(t *testing.T, keyPair testKeyPair) (*Authorizer, *mock.MockAuthorizer, *httptest.Server) {
	t.Helper()

	ctrl := gomock.NewController(t)
	remote := mock.NewMockAuthorizer(ctrl)
	keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{keyPair.pub}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(&keySet); err != nil {
			t.Errorf("failed to encode key set: %v", err)
		}
	}))

	t.Cleanup(server.Close)

	jwksCache := NewJWKSCache(server.Client(), server.URL+"/oauth2/v2/jwks", time.Minute)
	verifier := NewVerifier(jwksCache)
	authorizer := &Authorizer{
		verifier:    verifier,
		remote:      remote,
		claimsCache: cache.NewLRUExpireCache(passportClaimsCacheSize),
	}

	return authorizer, remote, server
}

func passportInfoWithACL(t *testing.T, keyPair testKeyPair) (*authorization.Info, *identityapi.Acl) {
	t.Helper()

	expectedACL := &identityapi.Acl{}
	token := mintPassport(t, keyPair, withACL(expectedACL))

	return &authorization.Info{Token: token}, expectedACL
}

func TestGetBearerToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		header     string
		expectErr  bool
		errContain string
		expected   string
	}{
		{
			name:       "rejects missing authorization header",
			expectErr:  true,
			errContain: "authorization header missing",
		},
		{
			name:       "rejects malformed authorization header",
			header:     "Bearer",
			expectErr:  true,
			errContain: "authorization header malformed",
		},
		{
			name:       "rejects non-bearer scheme",
			header:     "Basic abc123",
			expectErr:  true,
			errContain: "authorization scheme not allowed",
		},
		{
			name:     "accepts bearer token",
			header:   "Bearer token-value",
			expected: "token-value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				request.Header.Set("Authorization", tt.header)
			}

			input := &openapi3filter.AuthenticationInput{
				RequestValidationInput: &openapi3filter.RequestValidationInput{Request: request},
			}

			token, err := getBearerToken(input)

			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContain)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, token)
		})
	}
}

func TestAuthorizer_Authorize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		makeToken   func(t *testing.T, keyPair testKeyPair) string
		closeServer bool
		setupMock   func(mockRemote *mock.MockAuthorizer, input *openapi3filter.AuthenticationInput)
		expectErr   bool
		errContains string
		checkInfo   func(t *testing.T, info *authorization.Info, token string)
	}{
		{
			name: "returns error when authorization header is missing",
			makeToken: func(_ *testing.T, _ testKeyPair) string {
				return ""
			},
			expectErr: true,
		},
		{
			name: "delegates to remote for non-passport token",
			makeToken: func(t *testing.T, _ testKeyPair) string {
				t.Helper()
				return "not.a.passport"
			},
			setupMock: func(mockRemote *mock.MockAuthorizer, input *openapi3filter.AuthenticationInput) {
				mockRemote.EXPECT().Authorize(input).Return(&authorization.Info{
					Token:    "remote-token",
					Userinfo: &identityapi.Userinfo{Sub: "remote-sub"},
				}, nil)
			},
			checkInfo: func(t *testing.T, info *authorization.Info, _ string) {
				t.Helper()
				assert.Equal(t, "remote-token", info.Token)
				assert.Equal(t, "remote-sub", info.Userinfo.Sub)
			},
		},
		{
			name: "returns error for expired passport",
			makeToken: func(t *testing.T, keyPair testKeyPair) string {
				t.Helper()
				return mintPassport(t, keyPair, withExpired)
			},
			expectErr: true,
		},
		{
			name: "returns error for passport with invalid signature",
			makeToken: func(t *testing.T, keyPair testKeyPair) string {
				t.Helper()
				otherKeyPair := newTestKeyPair(t, "auth-kid")

				return mintPassport(t, otherKeyPair)
			},
			expectErr: true,
		},
		{
			name:        "returns server error when jwks endpoint is unreachable",
			closeServer: true,
			makeToken: func(t *testing.T, keyPair testKeyPair) string {
				t.Helper()
				return mintPassport(t, keyPair)
			},
			expectErr:   true,
			errContains: "JWKS unavailable",
		},
		{
			name: "populates authorization info from claims for valid passport",
			makeToken: func(t *testing.T, keyPair testKeyPair) string {
				t.Helper()
				return mintPassport(t, keyPair, withACL(&identityapi.Acl{}))
			},
			checkInfo: func(t *testing.T, info *authorization.Info, token string) {
				t.Helper()
				assert.Equal(t, token, info.Token)
				assert.Equal(t, "test-subject", info.Userinfo.Sub)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			keyPair := newTestKeyPair(t, "auth-kid")
			authorizer, remote, server := newAuthorizerWithMock(t, keyPair)

			if tt.closeServer {
				server.Close()
			}

			token := tt.makeToken(t, keyPair)
			input := oauth2AuthInput(token)

			if tt.setupMock != nil {
				tt.setupMock(remote, input)
			}

			info, err := authorizer.Authorize(input)

			if tt.expectErr {
				require.Error(t, err)

				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, info)

				if tt.checkInfo != nil {
					tt.checkInfo(t, info, token)
				}
			}
		})
	}
}

func TestAuthorizer_ClaimsCache(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		token     string
		claims    *identityoauth2.PassportClaims
		wantCache bool
	}{
		{
			name:      "uses default ttl when exp is missing",
			token:     "no-exp-token",
			claims:    &identityoauth2.PassportClaims{},
			wantCache: true,
		},
		{
			name:  "does not cache expired claims",
			token: "expired-token",
			claims: &identityoauth2.PassportClaims{
				Claims: jwt.Claims{Expiry: jwt.NewNumericDate(time.Now().Add(-time.Minute))},
			},
			wantCache: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authorizer := &Authorizer{claimsCache: cache.NewLRUExpireCache(passportClaimsCacheSize)}
			authorizer.cacheClaims(tt.token, tt.claims)

			claims, ok, err := authorizer.claimsFromCache(tt.token)
			require.NoError(t, err)
			assert.Equal(t, tt.wantCache, ok)

			if tt.wantCache {
				require.NotNil(t, claims)
			}
		})
	}
}

func TestAuthorizer_GetACL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		skipAuthContext bool
		makeInfo        func(t *testing.T, keyPair testKeyPair) (*authorization.Info, *identityapi.Acl)
		setupAuthorizer func(t *testing.T, authorizer *Authorizer, info *authorization.Info, expectedACL *identityapi.Acl)
		setupMock       func(mockRemote *mock.MockAuthorizer, ctx any)
		expectErr       bool
	}{
		{
			name:            "returns error when authorization context missing",
			skipAuthContext: true,
			expectErr:       true,
		},
		{
			name:     "returns acl from token claims cache",
			makeInfo: passportInfoWithACL,
			setupAuthorizer: func(_ *testing.T, authorizer *Authorizer, info *authorization.Info, expectedACL *identityapi.Acl) {
				authorizer.cacheClaims(info.Token, &identityoauth2.PassportClaims{ACL: expectedACL})
			},
		},
		{
			name: "delegates to remote for non-passport token",
			makeInfo: func(_ *testing.T, _ testKeyPair) (*authorization.Info, *identityapi.Acl) {
				return &authorization.Info{Token: "not.a.passport.token"}, nil
			},
			setupMock: func(mockRemote *mock.MockAuthorizer, ctx any) {
				mockRemote.EXPECT().GetACL(ctx, "org-id").Return(&identityapi.Acl{}, nil)
			},
		},
		{
			name:     "returns embedded acl for passport token when acl not cached",
			makeInfo: passportInfoWithACL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			keyPair := newTestKeyPair(t, "auth-kid")
			authorizer, remote, _ := newAuthorizerWithMock(t, keyPair)

			ctx := t.Context()

			var (
				info        *authorization.Info
				expectedACL *identityapi.Acl
			)

			if !tt.skipAuthContext {
				info, expectedACL = tt.makeInfo(t, keyPair)
				ctx = authorization.NewContext(ctx, info)
			}

			if tt.setupAuthorizer != nil {
				tt.setupAuthorizer(t, authorizer, info, expectedACL)
			}

			if tt.setupMock != nil {
				tt.setupMock(remote, ctx)
			}

			acl, err := authorizer.GetACL(ctx, "org-id")

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)

				if expectedACL != nil {
					assert.Equal(t, expectedACL, acl)
				}
			}
		})
	}
}
