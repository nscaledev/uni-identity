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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/mock"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

var errExchangeNotConfigured = errors.New("exchange not configured")

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

func newAuthorizerWithMock(t *testing.T, keyPair testKeyPair, exchange exchanger) (*Authorizer, *mock.MockAuthorizer) {
	t.Helper()

	ctrl := gomock.NewController(t)
	uni := mock.NewMockAuthorizer(ctrl)
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

	if exchange == nil {
		exchange = exchangeFunc(func(_ context.Context, _ string, _ *exchangeOptions) (string, error) {
			return "", errExchangeNotConfigured
		})
	}

	authorizer := &Authorizer{
		verifier: verifier,
		uni:      uni,
		exchange: exchange,
	}

	return authorizer, uni
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
		name      string
		makeToken func(t *testing.T, keyPair testKeyPair) string
		exchange  func(t *testing.T, keyPair testKeyPair) exchanger
		setupMock func(mockRemote *mock.MockAuthorizer, input *openapi3filter.AuthenticationInput)
		expectErr bool
		contains  string
		checkInfo func(t *testing.T, info *authorization.Info, inputToken string)
	}{
		{
			name: "returns error when authorization header is missing",
			makeToken: func(_ *testing.T, _ testKeyPair) string {
				return ""
			},
			expectErr: true,
		},
		{
			name: "returns error when exchange returns unauthorized",
			makeToken: func(_ *testing.T, _ testKeyPair) string {
				return "not.a.passport"
			},
			exchange: func(_ *testing.T, _ testKeyPair) exchanger {
				return exchangeFunc(func(_ context.Context, _ string, _ *exchangeOptions) (string, error) {
					return "", ErrExchangeUnauthorized
				})
			},
			expectErr: true,
			contains:  "token is invalid or has expired",
		},
		{
			name: "falls back to remote when exchange unavailable",
			makeToken: func(_ *testing.T, _ testKeyPair) string {
				return "not.a.passport"
			},
			exchange: func(_ *testing.T, _ testKeyPair) exchanger {
				return exchangeFunc(func(_ context.Context, _ string, _ *exchangeOptions) (string, error) {
					return "", ErrExchangeUnavailable
				})
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
				assert.Empty(t, info.Passport)
			},
		},
		{
			name: "exchanges raw token and populates passport context",
			makeToken: func(_ *testing.T, _ testKeyPair) string {
				return "raw-source-token"
			},
			exchange: func(t *testing.T, keyPair testKeyPair) exchanger {
				t.Helper()

				passportToken := mintPassport(t, keyPair)

				return exchangeFunc(func(_ context.Context, sourceToken string, _ *exchangeOptions) (string, error) {
					assert.Equal(t, "raw-source-token", sourceToken)
					return passportToken, nil
				})
			},
			checkInfo: func(t *testing.T, info *authorization.Info, _ string) {
				t.Helper()
				assert.Equal(t, "raw-source-token", info.Token)
				assert.NotEmpty(t, info.Passport)
				assert.Equal(t, "test-subject", info.Userinfo.Sub)
			},
		},
		{
			name: "returns error for expired passport",
			makeToken: func(t *testing.T, keyPair testKeyPair) string {
				t.Helper()
				return mintPassport(t, keyPair, withExpired)
			},
			expectErr: true,
			contains:  "passport token has expired",
		},
		{
			name: "returns error for passport with invalid signature",
			makeToken: func(t *testing.T, _ testKeyPair) string {
				t.Helper()
				otherKeyPair := newTestKeyPair(t, "auth-kid")

				return mintPassport(t, otherKeyPair)
			},
			expectErr: true,
			contains:  "passport token has an invalid signature",
		},
		{
			name: "populates authorization info from incoming passport",
			makeToken: func(t *testing.T, keyPair testKeyPair) string {
				t.Helper()
				return mintPassport(t, keyPair)
			},
			checkInfo: func(t *testing.T, info *authorization.Info, token string) {
				t.Helper()
				assert.Empty(t, info.Token)
				assert.Equal(t, token, info.Passport)
				assert.Equal(t, "test-subject", info.Userinfo.Sub)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			keyPair := newTestKeyPair(t, "auth-kid")

			var exchange exchanger
			if tt.exchange != nil {
				exchange = tt.exchange(t, keyPair)
			}

			authorizer, remote := newAuthorizerWithMock(t, keyPair, exchange)

			token := tt.makeToken(t, keyPair)
			input := oauth2AuthInput(token)

			if tt.setupMock != nil {
				tt.setupMock(remote, input)
			}

			info, err := authorizer.Authorize(input)

			if tt.expectErr {
				require.Error(t, err)

				if tt.contains != "" {
					assert.Contains(t, err.Error(), tt.contains)
				}

				return
			}

			require.NoError(t, err)
			require.NotNil(t, info)

			if tt.checkInfo != nil {
				tt.checkInfo(t, info, token)
			}
		})
	}
}

func TestAuthorizer_GetACL(t *testing.T) {
	t.Parallel()

	keyPair := newTestKeyPair(t, "auth-kid")
	authorizer, remote := newAuthorizerWithMock(t, keyPair, nil)

	ctx := t.Context()
	expectedACL := &identityapi.Acl{}

	remote.EXPECT().GetACL(ctx, "org-id").Return(expectedACL, nil)

	acl, err := authorizer.GetACL(ctx, "org-id")
	require.NoError(t, err)
	assert.Equal(t, expectedACL, acl)
}

func TestAuthorizer_AuthorizePassesScopeToExchange(t *testing.T) {
	t.Parallel()

	keyPair := newTestKeyPair(t, "auth-kid")

	var capturedOptions *exchangeOptions

	authorizer, _ := newAuthorizerWithMock(t, keyPair, exchangeFunc(func(_ context.Context, sourceToken string, options *exchangeOptions) (string, error) {
		assert.Equal(t, "raw-source-token", sourceToken)

		capturedOptions = options

		return mintPassport(t, keyPair), nil
	}))

	input := oauth2AuthInput("raw-source-token")
	input.RequestValidationInput.PathParams = map[string]string{
		"organizationID": "org-1",
		"projectID":      "proj-1",
	}

	_, err := authorizer.Authorize(input)
	require.NoError(t, err)
	require.NotNil(t, capturedOptions)
	assert.Equal(t, "org-1", capturedOptions.organizationID)
	assert.Equal(t, "proj-1", capturedOptions.projectID)
}

func TestPassportFlow_PassportInputKeepsPassportOnlyACLContext(t *testing.T) {
	t.Parallel()

	keyPair := newTestKeyPair(t, "auth-kid")
	authorizer, uni := newAuthorizerWithMock(t, keyPair, nil)

	input := oauth2AuthInput(mintPassport(t, keyPair))
	info, err := authorizer.Authorize(input)
	require.NoError(t, err)
	require.NotNil(t, info)
	require.Empty(t, info.Token)
	require.NotEmpty(t, info.Passport)

	ctx := authorization.NewContext(t.Context(), info)

	uni.EXPECT().GetACL(gomock.Any(), "org-id").DoAndReturn(func(ctx context.Context, _ string) (*identityapi.Acl, error) {
		aclInfo, err := authorization.FromContext(ctx)
		require.NoError(t, err)
		assert.Empty(t, aclInfo.Token)
		assert.Equal(t, info.Passport, aclInfo.Passport)

		return &identityapi.Acl{}, nil
	})

	_, err = authorizer.GetACL(ctx, "org-id")
	require.NoError(t, err)
}

func TestPassportFlow_ExchangeInputKeepsSourceTokenForACLContext(t *testing.T) {
	t.Parallel()

	keyPair := newTestKeyPair(t, "auth-kid")
	passportToken := mintPassport(t, keyPair)

	authorizer, uni := newAuthorizerWithMock(t, keyPair, exchangeFunc(func(_ context.Context, sourceToken string, _ *exchangeOptions) (string, error) {
		require.Equal(t, "raw-source-token", sourceToken)
		return passportToken, nil
	}))

	input := oauth2AuthInput("raw-source-token")
	info, err := authorizer.Authorize(input)
	require.NoError(t, err)
	require.NotNil(t, info)
	require.Equal(t, "raw-source-token", info.Token)
	require.Equal(t, passportToken, info.Passport)

	ctx := authorization.NewContext(t.Context(), info)

	uni.EXPECT().GetACL(gomock.Any(), "org-id").DoAndReturn(func(ctx context.Context, _ string) (*identityapi.Acl, error) {
		aclInfo, err := authorization.FromContext(ctx)
		require.NoError(t, err)
		assert.Equal(t, "raw-source-token", aclInfo.Token)
		assert.Equal(t, passportToken, aclInfo.Passport)

		return &identityapi.Acl{}, nil
	})

	_, err = authorizer.GetACL(ctx, "org-id")
	require.NoError(t, err)
}

func TestNewExchangeOptionsFromInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     *openapi3filter.AuthenticationInput
		expectNil bool
		expectOrg string
		expectPrj string
	}{
		{
			name: "returns options when path params are present",
			input: func() *openapi3filter.AuthenticationInput {
				input := oauth2AuthInput("raw-token")
				input.RequestValidationInput.PathParams = map[string]string{
					"organizationID": "org-1",
					"projectID":      "proj-1",
				}

				return input
			}(),
			expectOrg: "org-1",
			expectPrj: "proj-1",
		},
		{
			name:      "returns nil when input is nil",
			input:     nil,
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			options := newExchangeOptionsFromInput(tt.input)
			if tt.expectNil {
				assert.Nil(t, options)
				return
			}

			require.NotNil(t, options)
			assert.Equal(t, tt.expectOrg, options.organizationID)
			assert.Equal(t, tt.expectPrj, options.projectID)
		})
	}
}

func TestAuthorizerOptionsWithDefaults(t *testing.T) {
	t.Parallel()

	t.Run("applies package defaults when nil", func(t *testing.T) {
		t.Parallel()

		var options *Options
		resolved := options.withDefaults()

		assert.Equal(t, defaultJWKSCacheTTL, resolved.JWKSCacheTTL)
		assert.Equal(t, defaultJWKSTimeout, resolved.JWKSTimeout)
		assert.Equal(t, defaultExchangeTimeout, resolved.ExchangeTimeout)
	})

	t.Run("preserves explicit non-zero values", func(t *testing.T) {
		t.Parallel()

		resolved := (&Options{
			JWKSCacheTTL:    2 * time.Minute,
			JWKSTimeout:     750 * time.Millisecond,
			ExchangeTimeout: 900 * time.Millisecond,
		}).withDefaults()

		assert.Equal(t, 2*time.Minute, resolved.JWKSCacheTTL)
		assert.Equal(t, 750*time.Millisecond, resolved.JWKSTimeout)
		assert.Equal(t, 900*time.Millisecond, resolved.ExchangeTimeout)
	})
}
