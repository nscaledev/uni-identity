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
	"encoding/json"
	"fmt"
	"io"
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

	// RFC 6749 §5.2 error code identity returns for scope refusal.
	oauth2ErrorInvalidScope = "invalid_scope"

	// Token-endpoint error bodies are small JSON; the cap bounds the
	// classifier's exposure to a misbehaving or hostile upstream.
	errorBodySniffLimit = 8 * 1024
)

// HTTPTokenExchange exchanges source access tokens through an OAuth2 token endpoint.
type HTTPTokenExchange struct {
	httpClient *http.Client
	tokenURL   string
}

type tokenExchangeResponse struct {
	AccessToken string `json:"access_token"` //nolint:tagliatelle
}

// oauth2ErrorBody is the subset of the RFC 6749 §5.2 error shape consulted by
// the classifier.
type oauth2ErrorBody struct {
	Error string `json:"error"`
}

// NewHTTPTokenExchange builds a token exchanger that performs RFC 8693 token exchange over HTTP.
func NewHTTPTokenExchange(httpClient *http.Client, tokenURL string) TokenExchange {
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
		// Must match the token endpoint's form schema.
		if options.organizationID != "" {
			form.Set("x_organization_id", options.organizationID)
		}

		if options.projectID != "" {
			form.Set("x_project_id", options.projectID)
		}
	}

	return form
}

// classifyTokenExchangeStatus maps a token-endpoint status to the sentinel
// the authorizer dispatches on. body is only consulted on 400.
func classifyTokenExchangeStatus(statusCode int, body []byte) error {
	switch {
	case statusCode == http.StatusUnauthorized:
		return ErrTokenExchangeUnauthorized
	case statusCode == http.StatusBadRequest && isInvalidScopeError(body):
		return ErrTokenExchangeForbidden
	case statusCode >= http.StatusInternalServerError:
		return fmt.Errorf("%w: status code %d", ErrTokenExchangeUnavailable, statusCode)
	case statusCode != http.StatusOK:
		return fmt.Errorf("%w: status code %d", ErrTokenExchangeFailed, statusCode)
	default:
		return nil
	}
}

// isInvalidScopeError returns true only for a parseable RFC 6749 §5.2 body
// with error code invalid_scope. Malformed bodies fall through.
func isInvalidScopeError(body []byte) bool {
	var oauthErr oauth2ErrorBody
	if err := json.Unmarshal(body, &oauthErr); err != nil {
		return false
	}

	return oauthErr.Error == oauth2ErrorInvalidScope
}

func decodeTokenExchangeResponse(resp *http.Response) (string, error) {
	defer resp.Body.Close()

	// Only 400 needs the body (RFC 6749 §5.2 error code). Cap the read
	// here so the 200 path stream-decodes uncapped.
	if resp.StatusCode == http.StatusBadRequest {
		body, err := io.ReadAll(io.LimitReader(resp.Body, errorBodySniffLimit))
		if err != nil {
			return "", fmt.Errorf("%w: failed to read response body: %w", ErrTokenExchangeInvalidResponse, err)
		}

		return "", classifyTokenExchangeStatus(http.StatusBadRequest, body)
	}

	if err := classifyTokenExchangeStatus(resp.StatusCode, nil); err != nil {
		return "", err
	}

	var responseBody tokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&responseBody); err != nil {
		return "", fmt.Errorf("%w: %w", ErrTokenExchangeInvalidResponse, err)
	}

	if responseBody.AccessToken == "" {
		return "", ErrTokenExchangeMissingAccessToken
	}

	return responseBody.AccessToken, nil
}

// Exchange performs the RFC 8693 form-post against the configured token endpoint
// and returns the issued passport on success.
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
