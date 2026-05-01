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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	//nolint:gosec // OAuth token type URNs, not credentials.
	tokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	//nolint:gosec // OAuth token type URNs, not credentials.
	tokenExchangeSubjectToken = "urn:ietf:params:oauth:token-type:access_token"
	//nolint:gosec // OAuth token type URNs, not credentials.
	tokenExchangeRequestedPassport = "urn:nscale:params:oauth:token-type:passport"
)

// HTTPTokenExchange exchanges source access tokens through an OAuth2 token endpoint.
type HTTPTokenExchange struct {
	httpClient *http.Client
	tokenURL   string
}

type tokenExchangeResponse struct {
	AccessToken string `json:"access_token"` //nolint:tagliatelle
}

// NewHTTPTokenExchange builds a token exchanger that performs RFC8693 token exchange over HTTP.
func NewHTTPTokenExchange(httpClient *http.Client, tokenURL string) *HTTPTokenExchange {
	return &HTTPTokenExchange{httpClient: httpClient, tokenURL: tokenURL}
}

var _ TokenExchange = (*HTTPTokenExchange)(nil)

func tokenExchangeForm(sourceToken string, options *tokenExchangeOptions) url.Values {
	form := url.Values{}
	form.Set("grant_type", tokenExchangeGrantType)
	form.Set("subject_token", sourceToken)
	form.Set("subject_token_type", tokenExchangeSubjectToken)
	form.Set("requested_token_type", tokenExchangeRequestedPassport)

	if options != nil {
		if options.organizationID != "" {
			form.Set("organizationId", options.organizationID)
		}

		if options.projectID != "" {
			form.Set("projectId", options.projectID)
		}
	}

	return form
}

func classifyTokenExchangeStatus(statusCode int) error {
	switch {
	case statusCode == http.StatusUnauthorized:
		return ErrTokenExchangeUnauthorized
	case statusCode >= http.StatusInternalServerError:
		return fmt.Errorf("%w: status code %d", ErrTokenExchangeUnavailable, statusCode)
	case statusCode != http.StatusOK:
		return fmt.Errorf("%w: status code %d", ErrTokenExchangeFailed, statusCode)
	default:
		return nil
	}
}

func decodeTokenExchangeResponse(resp *http.Response) (string, error) {
	defer resp.Body.Close()

	if err := classifyTokenExchangeStatus(resp.StatusCode); err != nil {
		return "", err
	}

	var body tokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("%w: %w", ErrTokenExchangeInvalidResponse, err)
	}

	if body.AccessToken == "" {
		return "", ErrTokenExchangeMissingAccessToken
	}

	return body.AccessToken, nil
}

func (c *HTTPTokenExchange) Exchange(ctx context.Context, sourceToken string, options *tokenExchangeOptions) (string, error) {
	form := tokenExchangeForm(sourceToken, options)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create exchange request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrTokenExchangeUnavailable, err)
	}

	return decodeTokenExchangeResponse(resp)
}

type tokenExchangeFunc func(ctx context.Context, sourceToken string, options *tokenExchangeOptions) (string, error)

func (f tokenExchangeFunc) Exchange(ctx context.Context, sourceToken string, options *tokenExchangeOptions) (string, error) {
	return f(ctx, sourceToken, options)
}

var _ TokenExchange = tokenExchangeFunc(nil)
