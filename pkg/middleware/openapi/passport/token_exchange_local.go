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

package passport

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	identityoauth2 "github.com/unikorn-cloud/identity/pkg/oauth2"
	oauth2errors "github.com/unikorn-cloud/identity/pkg/oauth2/errors"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

type tokenExchangeService interface {
	ExchangePassport(ctx context.Context, options *identityapi.TokenRequestOptions) (*identityapi.Token, error)
}

type localTokenExchange struct {
	service tokenExchangeService
}

var _ TokenExchange = (*localTokenExchange)(nil)

func NewLocalTokenExchange(service tokenExchangeService) TokenExchange {
	return &localTokenExchange{service: service}
}

func (e *localTokenExchange) Exchange(ctx context.Context, sourceToken string, options *tokenExchangeOptions) (string, error) {
	if e.service == nil {
		return "", fmt.Errorf("%w: local token exchange not configured", ErrTokenExchangeUnavailable)
	}

	tokenOptions := &identityapi.TokenRequestOptions{
		GrantType:          string(identityapi.UrnIetfParamsOauthGrantTypeTokenExchange),
		SubjectToken:       &sourceToken,
		SubjectTokenType:   ptrString(identityoauth2.AccessTokenSubjectTokenType()),
		RequestedTokenType: ptrString(identityoauth2.PassportIssuedTokenType()),
	}

	if options != nil {
		if options.organizationID != "" {
			tokenOptions.XOrganizationId = &options.organizationID
		}

		if options.projectID != "" {
			tokenOptions.XProjectId = &options.projectID
		}
	}

	token, err := e.service.ExchangePassport(ctx, tokenOptions)
	if err != nil {
		var oauthErr *oauth2errors.Error
		if errors.As(err, &oauthErr) {
			switch {
			case oauthErr.StatusCode() == http.StatusUnauthorized:
				return "", ErrTokenExchangeUnauthorized
			case oauthErr.StatusCode() >= http.StatusInternalServerError:
				return "", fmt.Errorf("%w: %w", ErrTokenExchangeUnavailable, err)
			default:
				return "", fmt.Errorf("%w: %w", ErrTokenExchangeFailed, err)
			}
		}

		return "", fmt.Errorf("%w: %w", ErrTokenExchangeUnavailable, err)
	}

	if token == nil || token.AccessToken == "" {
		return "", ErrTokenExchangeMissingAccessToken
	}

	return token.AccessToken, nil
}

func ptrString(value string) *string {
	return &value
}
