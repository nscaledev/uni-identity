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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	oauth2errors "github.com/unikorn-cloud/identity/pkg/oauth2/errors"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

var (
	errUnexpectedGrantType          = errors.New("unexpected grant_type")
	errUnexpectedSubjectTokenType   = errors.New("unexpected subject_token_type")
	errUnexpectedRequestedTokenType = errors.New("unexpected requested_token_type")
	errUnexpectedSubjectToken       = errors.New("unexpected subject_token")
	errUnexpectedOrganizationID     = errors.New("unexpected organizationId")
	errUnexpectedProjectID          = errors.New("unexpected projectId")
	errBoom                         = errors.New("boom")
)

type tokenExchangeServiceFunc func(ctx context.Context, options *identityapi.TokenRequestOptions) (*identityapi.Token, error)

func (f tokenExchangeServiceFunc) ExchangePassport(ctx context.Context, options *identityapi.TokenRequestOptions) (*identityapi.Token, error) {
	return f(ctx, options)
}

func TestLocalTokenExchange(t *testing.T) {
	t.Parallel()

	t.Run("returns exchanged passport on success", func(t *testing.T) {
		t.Parallel()

		exchange := NewLocalTokenExchange(tokenExchangeServiceFunc(func(_ context.Context, options *identityapi.TokenRequestOptions) (*identityapi.Token, error) {
			require.Equal(t, string(identityapi.UrnIetfParamsOauthGrantTypeTokenExchange), options.GrantType, errUnexpectedGrantType.Error())

			require.NotNil(t, options.SubjectTokenType)
			require.Equal(t, tokenExchangeSubjectToken, *options.SubjectTokenType, errUnexpectedSubjectTokenType.Error())

			require.NotNil(t, options.RequestedTokenType)
			require.Equal(t, tokenExchangeRequestedPassport, *options.RequestedTokenType, errUnexpectedRequestedTokenType.Error())

			require.NotNil(t, options.SubjectToken)
			require.Equal(t, "raw-token", *options.SubjectToken, errUnexpectedSubjectToken.Error())

			require.NotNil(t, options.XOrganizationId)
			require.Equal(t, "org-1", *options.XOrganizationId, errUnexpectedOrganizationID.Error())

			require.NotNil(t, options.XProjectId)
			require.Equal(t, "proj-1", *options.XProjectId, errUnexpectedProjectID.Error())

			return &identityapi.Token{AccessToken: "passport-token"}, nil
		}))

		token, err := exchange.Exchange(t.Context(), "raw-token", &tokenExchangeOptions{
			organizationID: "org-1",
			projectID:      "proj-1",
		})

		require.NoError(t, err)
		assert.Equal(t, "passport-token", token)
	})

	tests := []struct {
		name      string
		service   tokenExchangeServiceFunc
		expectErr error
	}{
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
				return nil, errBoom
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

			require.ErrorIs(t, err, tt.expectErr)
			assert.Empty(t, token)
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
