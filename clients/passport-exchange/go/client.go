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

package passportexchange

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type retryPolicy struct {
	maxAttempts          int
	retryableStatusCodes map[int]struct{}
	retryNetworkErrors   bool
	minBackoff           time.Duration
	maxBackoff           time.Duration
}

type retryClass int

const (
	retryNone retryClass = iota
	retryTransport
	retryStatus
)

// Client is the Go passport exchange client.
type Client struct {
	baseURL        string
	httpClient     *http.Client
	retry          retryPolicy
	cache          *responseCache
	requestEditors []RequestEditorFn
	metrics        MetricsHooks
	clock          Clock
}

// NewClient creates a configured exchange client.
func NewClient(options Options) (*Client, error) {
	if strings.TrimSpace(options.BaseURL) == "" {
		return nil, ErrBaseURLRequired
	}

	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	clock := options.Clock
	if clock == nil {
		clock = realClock{}
	}

	client := &Client{
		baseURL:        strings.TrimRight(options.BaseURL, "/"),
		httpClient:     httpClient,
		retry:          normalizeRetry(options.Retry),
		cache:          newResponseCache(options.Cache),
		requestEditors: options.RequestEditors,
		metrics:        options.Metrics,
		clock:          clock,
	}

	return client, nil
}

// Exchange exchanges a source token for a passport JWT.
func (c *Client) Exchange(ctx context.Context, sourceToken string, request ExchangeRequest) (*ExchangeResponse, error) {
	if strings.TrimSpace(sourceToken) == "" {
		return nil, ErrSourceTokenRequired
	}

	cacheKey := exchangeCacheKey(sourceToken, request)
	now := c.clock.Now()

	if cached, ok := c.cache.get(cacheKey, now); ok {
		c.incTotal("cached")
		return cached, nil
	}

	formBody := encodeRequestBody(request)
	started := c.clock.Now()

	attempt := 1

	for {
		result, class, err := c.performExchangeAttempt(ctx, sourceToken, formBody)
		if err == nil {
			result.Cached = false

			c.cache.set(cacheKey, *result, c.clock.Now())
			c.incTotal("success")
			c.observeDuration(c.clock.Now().Sub(started))

			return result, nil
		}

		if isUnauthorized(err) {
			c.incTotal("unauthorized")
			c.observeDuration(c.clock.Now().Sub(started))

			return nil, err
		}

		if c.shouldRetry(ctx, attempt, class) {
			attempt++
			continue
		}

		c.incTotal("error")
		c.observeDuration(c.clock.Now().Sub(started))

		return nil, err
	}
}

func (c *Client) performExchangeAttempt(ctx context.Context, sourceToken, formBody string) (*ExchangeResponse, retryClass, error) {
	request, err := c.buildExchangeRequest(ctx, sourceToken, formBody)
	if err != nil {
		return nil, retryNone, err
	}

	response, err := c.doExchangeRequest(request)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, retryNone, err
		}

		return nil, retryTransport, &TransportError{Cause: err}
	}

	result, class, err := parseExchangeResponse(response, c.retry.retryableStatusCodes)
	if err != nil {
		return nil, class, err
	}

	return result, retryNone, nil
}

func (c *Client) shouldRetry(ctx context.Context, attempt int, class retryClass) bool {
	switch class {
	case retryTransport:
		return c.shouldRetryTransportError(ctx, attempt)
	case retryStatus:
		return c.shouldRetryStatusError(ctx, attempt)
	case retryNone:
		return false
	default:
		return false
	}
}

func (c *Client) buildExchangeRequest(ctx context.Context, sourceToken, encodedBody string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+ExchangePath, strings.NewReader(encodedBody))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBuildExchangeRequest, err)
	}

	request.Header.Set("Authorization", "Bearer "+sourceToken)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	for _, editor := range c.requestEditors {
		if err := editor(ctx, request); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrEditExchangeRequest, err)
		}
	}

	return request, nil
}

func (c *Client) doExchangeRequest(request *http.Request) (*http.Response, error) {
	return c.httpClient.Do(request)
}

type oauth2ErrorPayload struct {
	Error string `json:"error"`
	//nolint:tagliatelle
	ErrorDescription string `json:"error_description"`
}

func parseExchangeResponse(response *http.Response, retryableStatuses map[int]struct{}) (*ExchangeResponse, retryClass, error) {
	defer response.Body.Close()

	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, retryNone, err
	}

	status := response.StatusCode

	if status >= http.StatusOK && status < http.StatusMultipleChoices {
		result, err := parseExchangeSuccess(bodyBytes)
		if err != nil {
			return nil, retryNone, err
		}

		return result, retryNone, nil
	}

	oauthError := parseOAuthErrorPayload(bodyBytes)

	class, err := parseExchangeError(status, oauthError, retryableStatuses)

	return nil, class, err
}

func parseExchangeSuccess(bodyBytes []byte) (*ExchangeResponse, error) {
	var result ExchangeResponse
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return nil, err
	}

	if strings.TrimSpace(result.Passport) == "" {
		return nil, ErrExchangeResponseMissingPassport
	}

	return &result, nil
}

func parseOAuthErrorPayload(bodyBytes []byte) oauth2ErrorPayload {
	var oauthError oauth2ErrorPayload
	if len(bodyBytes) > 0 {
		_ = json.Unmarshal(bodyBytes, &oauthError)
	}

	return oauthError
}

func parseExchangeError(status int, oauthError oauth2ErrorPayload, retryableStatuses map[int]struct{}) (retryClass, error) {
	httpError := &HTTPStatusError{
		StatusCode:  status,
		ErrorCode:   oauthError.Error,
		Description: oauthError.ErrorDescription,
	}

	if status == http.StatusUnauthorized {
		return retryNone, &UnauthorizedError{
			StatusCode:  status,
			ErrorCode:   oauthError.Error,
			Description: oauthError.ErrorDescription,
		}
	}

	if status >= http.StatusBadRequest && status < http.StatusInternalServerError {
		return retryNone, httpError
	}

	if status >= http.StatusInternalServerError {
		if _, retryable := retryableStatuses[status]; retryable {
			return retryStatus, httpError
		}

		return retryNone, httpError
	}

	return retryNone, httpError
}

func isUnauthorized(err error) bool {
	var unauthorized *UnauthorizedError

	return errors.As(err, &unauthorized)
}

func (c *Client) shouldRetryTransportError(ctx context.Context, attempt int) bool {
	if !c.retry.retryNetworkErrors {
		return false
	}

	if attempt >= c.retry.maxAttempts {
		return false
	}

	if !hasRetryBudget(ctx, c.clock) {
		return false
	}

	if !c.sleepWithContext(ctx, backoffDuration(c.retry.minBackoff, c.retry.maxBackoff)) {
		return false
	}

	return true
}

func (c *Client) shouldRetryStatusError(ctx context.Context, attempt int) bool {
	if attempt >= c.retry.maxAttempts {
		return false
	}

	if !hasRetryBudget(ctx, c.clock) {
		return false
	}

	if !c.sleepWithContext(ctx, backoffDuration(c.retry.minBackoff, c.retry.maxBackoff)) {
		return false
	}

	return true
}

func (c *Client) sleepWithContext(ctx context.Context, duration time.Duration) bool {
	if duration <= 0 {
		return true
	}

	complete := make(chan struct{})

	go func() {
		c.clock.Sleep(duration)
		close(complete)
	}()

	select {
	case <-ctx.Done():
		return false
	case <-complete:
		return true
	}
}

func (c *Client) incTotal(result string) {
	if c.metrics.IncTotal != nil {
		c.metrics.IncTotal(result)
	}
}

func (c *Client) observeDuration(duration time.Duration) {
	if c.metrics.ObserveDuration != nil {
		c.metrics.ObserveDuration(duration)
	}
}

func normalizeRetry(config RetryConfig) retryPolicy {
	maxAttempts := config.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = defaultRetryMaxAttempts
	}

	retryableCodes := config.RetryableStatusCodes
	if len(retryableCodes) == 0 {
		retryableCodes = []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout}
	}

	retryableStatusCodes := map[int]struct{}{}
	for _, code := range retryableCodes {
		retryableStatusCodes[code] = struct{}{}
	}

	minBackoff := config.MinBackoff
	if minBackoff <= 0 {
		minBackoff = defaultRetryMinBackoff
	}

	maxBackoff := config.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = defaultRetryMaxBackoff
	}

	if maxBackoff < minBackoff {
		maxBackoff = minBackoff
	}

	retryNetworkErrors := true
	if config.RetryNetworkErrors != nil {
		retryNetworkErrors = *config.RetryNetworkErrors
	}

	return retryPolicy{
		maxAttempts:          maxAttempts,
		retryableStatusCodes: retryableStatusCodes,
		retryNetworkErrors:   retryNetworkErrors,
		minBackoff:           minBackoff,
		maxBackoff:           maxBackoff,
	}
}

func encodeRequestBody(request ExchangeRequest) string {
	values := url.Values{}

	if request.OrganizationID != "" {
		values.Set("organizationId", request.OrganizationID)
	}

	if request.ProjectID != "" {
		values.Set("projectId", request.ProjectID)
	}

	return values.Encode()
}

func exchangeCacheKey(sourceToken string, request ExchangeRequest) string {
	hash := sha256.Sum256([]byte(sourceToken + "|" + request.OrganizationID + "|" + request.ProjectID))

	return hex.EncodeToString(hash[:])
}

func hasRetryBudget(ctx context.Context, clock Clock) bool {
	deadline, ok := ctx.Deadline()
	if !ok {
		return true
	}

	return deadline.Sub(clock.Now()) > minRemainingDurationForRetry
}

func backoffDuration(minBackoff, maxBackoff time.Duration) time.Duration {
	if maxBackoff <= minBackoff {
		return minBackoff
	}

	window := maxBackoff - minBackoff

	jitter, ok := secureRandomDuration(window)
	if !ok {
		return minBackoff + (window / 2)
	}

	return minBackoff + jitter
}

func secureRandomDuration(window time.Duration) (time.Duration, bool) {
	upperBound := big.NewInt(int64(window) + 1)

	randomValue, err := cryptorand.Int(cryptorand.Reader, upperBound)
	if err != nil {
		return 0, false
	}

	return time.Duration(randomValue.Int64()), true
}
