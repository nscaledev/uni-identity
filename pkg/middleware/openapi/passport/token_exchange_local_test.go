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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	oauth2errors "github.com/unikorn-cloud/identity/pkg/oauth2/errors"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

type tokenExchangeServiceFunc func(ctx context.Context, options *identityapi.TokenRequestOptions) (*identityapi.Token, error)

func (f tokenExchangeServiceFunc) ExchangePassport(ctx context.Context, options *identityapi.TokenRequestOptions) (*identityapi.Token, error) {
	return f(ctx, options)
}

func TestLocalTokenExchange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		service   tokenExchangeServiceFunc
		expectErr error
	}{
		{
			name: "returns exchanged passport on success",
			service: func(_ context.Context, options *identityapi.TokenRequestOptions) (*identityapi.Token, error) {
				if options.GrantType != string(identityapi.UrnIetfParamsOauthGrantTypeTokenExchange) {
					return nil, fmt.Errorf("unexpected grant_type: %s", options.GrantType)
				}

				if options.SubjectTokenType == nil || *options.SubjectTokenType != tokenExchangeSubjectToken {
					return nil, fmt.Errorf("unexpected subject_token_type")
				}

				if options.RequestedTokenType == nil || *options.RequestedTokenType != tokenExchangeRequestedPassport {
					return nil, fmt.Errorf("unexpected requested_token_type")
				}

				if options.SubjectToken == nil || *options.SubjectToken != "raw-token" {
					return nil, fmt.Errorf("unexpected subject_token")
				}

				if options.XOrganizationId == nil || *options.XOrganizationId != "org-1" {
					return nil, fmt.Errorf("unexpected organizationId")
				}

				if options.XProjectId == nil || *options.XProjectId != "proj-1" {
					return nil, fmt.Errorf("unexpected projectId")
				}

				return &identityapi.Token{AccessToken: "passport-token"}, nil
			},
		},
		{
			name: "maps oauth unauthorized to exchange unauthorized",
			service: func(_ context.Context, _ *identityapi.TokenRequestOptions) (*identityapi.Token, error) {
				return nil, oauth2errors.OAuth2AccessDenied("token invalid")
			},
			expectErr: ErrTokenExchangeUnauthorized,
		},
		{
			name: "maps oauth bad request to exchange failed",
			service: func(_ context.Context, _ *identityapi.TokenRequestOptions) (*identityapi.Token, error) {
				return nil, oauth2errors.OAuth2InvalidRequest("bad request")
			},
			expectErr: ErrTokenExchangeFailed,
		},
		{
			name: "maps generic error to exchange unavailable",
			service: func(_ context.Context, _ *identityapi.TokenRequestOptions) (*identityapi.Token, error) {
				return nil, fmt.Errorf("boom")
			},
			expectErr: ErrTokenExchangeUnavailable,
		},
		{
			name: "returns missing access token sentinel",
			service: func(_ context.Context, _ *identityapi.TokenRequestOptions) (*identityapi.Token, error) {
				return &identityapi.Token{}, nil
			},
			expectErr: ErrTokenExchangeMissingAccessToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			exchange := NewLocalTokenExchange(tt.service)
			token, err := exchange.Exchange(t.Context(), "raw-token", &tokenExchangeOptions{
				organizationID: "org-1",
				projectID:      "proj-1",
			})

			if tt.expectErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.expectErr)
				assert.Empty(t, token)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, "passport-token", token)
		})
	}
}

func TestLocalTokenExchange_NilServiceReturnsUnavailable(t *testing.T) {
	t.Parallel()

	exchange := NewLocalTokenExchange(nil)

	_, err := exchange.Exchange(t.Context(), "raw-token", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenExchangeUnavailable)
}
