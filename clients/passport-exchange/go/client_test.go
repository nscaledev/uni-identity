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

//nolint:testpackage
package passportexchange

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errDialTCPTimeout    = errors.New("dial tcp timeout")
	errConnectionRefused = errors.New("connection refused")
	errEditorFailure     = errors.New("editor failure")
)

func boolPtr(value bool) *bool {
	return &value
}

type testClock struct {
	now time.Time
}

func newTestClock(now time.Time) *testClock {
	return &testClock{now: now}
}

func (c *testClock) Now() time.Time {
	return c.now
}

func (c *testClock) Sleep(time.Duration) {}

func (c *testClock) Advance(duration time.Duration) {
	c.now = c.now.Add(duration)
}

func newTestClient(t *testing.T, serverURL string, retry RetryConfig) *Client {
	t.Helper()

	client, err := NewClient(Options{
		BaseURL: serverURL,
		Retry:   retry,
		Clock:   newTestClock(time.Now()),
	})
	require.NoError(t, err)

	return client
}

func TestExchangeSuccess(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, ExchangePath, r.URL.Path)
		assert.Equal(t, "Bearer test-source-token", r.Header.Get("Authorization"))

		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		assert.Equal(t, "org-1", r.Form.Get("organizationId"))
		assert.Equal(t, "project-1", r.Form.Get("projectId"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"passport":"passport-jwt","expires_in":120}`))
	}))
	t.Cleanup(server.Close)

	client := newTestClient(t, server.URL, RetryConfig{})

	response, err := client.Exchange(t.Context(), "test-source-token", ExchangeRequest{
		OrganizationID: "org-1",
		ProjectID:      "project-1",
	})
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, "passport-jwt", response.Passport)
	assert.Equal(t, 120, response.ExpiresIn)
	assert.False(t, response.Cached)
	assert.Equal(t, int32(1), callCount.Load())
}

func TestExchangeCacheHit(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"passport":"cached-passport","expires_in":120}`))
	}))
	t.Cleanup(server.Close)

	var cachedMetricCount atomic.Int32

	client, err := NewClient(Options{
		BaseURL: server.URL,
		Cache: CacheConfig{
			Enabled: true,
		},
		Clock: newTestClock(time.Now()),
		Metrics: MetricsHooks{
			IncTotal: func(result string) {
				if result == "cached" {
					cachedMetricCount.Add(1)
				}
			},
		},
	})
	require.NoError(t, err)

	first, err := client.Exchange(t.Context(), "source-token", ExchangeRequest{})
	require.NoError(t, err)
	assert.False(t, first.Cached)

	second, err := client.Exchange(t.Context(), "source-token", ExchangeRequest{})
	require.NoError(t, err)
	assert.True(t, second.Cached)
	assert.Equal(t, first.Passport, second.Passport)
	assert.Equal(t, int32(1), callCount.Load())
	assert.Equal(t, int32(1), cachedMetricCount.Load())
}

func TestExchangeCacheExpiry(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"passport":"cache-expiry-passport","expires_in":0}`))
	}))
	t.Cleanup(server.Close)

	clock := newTestClock(time.Now())

	client, err := NewClient(Options{
		BaseURL: server.URL,
		Cache: CacheConfig{
			Enabled:    true,
			DefaultTTL: 2 * time.Second,
		},
		Clock: clock,
	})
	require.NoError(t, err)

	_, err = client.Exchange(t.Context(), "source-token", ExchangeRequest{})
	require.NoError(t, err)
	assert.Equal(t, int32(1), callCount.Load())

	clock.Advance(3 * time.Second)

	_, err = client.Exchange(t.Context(), "source-token", ExchangeRequest{})
	require.NoError(t, err)
	assert.Equal(t, int32(2), callCount.Load())
}

func TestExchangeUnauthorizedError(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"access_denied","error_description":"token invalid"}`))
	}))
	t.Cleanup(server.Close)

	client := newTestClient(t, server.URL, RetryConfig{})

	response, err := client.Exchange(t.Context(), "source-token", ExchangeRequest{})
	require.Nil(t, response)
	require.Error(t, err)

	unauthorized := &UnauthorizedError{}
	require.ErrorAs(t, err, &unauthorized)
	assert.Equal(t, http.StatusUnauthorized, unauthorized.StatusCode)
	assert.Equal(t, "access_denied", unauthorized.ErrorCode)
	assert.Equal(t, "token invalid", unauthorized.Description)
	assert.Equal(t, int32(1), callCount.Load())
}

func assertDoesNotRetryStatus(t *testing.T, statusCode int, errorBody string) {
	t.Helper()

	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempt := callCount.Add(1)

		w.Header().Set("Content-Type", "application/json")

		if attempt == 1 {
			w.WriteHeader(statusCode)
			_, _ = w.Write([]byte(errorBody))

			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"passport":"unexpected-success","expires_in":60}`))
	}))
	t.Cleanup(server.Close)

	client := newTestClient(t, server.URL, RetryConfig{})

	response, err := client.Exchange(t.Context(), "source-token", ExchangeRequest{})
	require.Nil(t, response)
	require.Error(t, err)

	httpError := &HTTPStatusError{}
	require.ErrorAs(t, err, &httpError)
	assert.Equal(t, statusCode, httpError.StatusCode)
	assert.Equal(t, int32(1), callCount.Load())
}

func TestExchangeDoesNotRetry4xx(t *testing.T) {
	t.Parallel()

	assertDoesNotRetryStatus(t, http.StatusBadRequest, `{"error":"invalid_request","error_description":"bad form"}`)
}

func TestExchangeRetries503ByDefault(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempt := callCount.Add(1)

		w.Header().Set("Content-Type", "application/json")

		if attempt == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"server_error","error_description":"temporary"}`))

			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"passport":"retried-passport","expires_in":60}`))
	}))
	t.Cleanup(server.Close)

	client := newTestClient(t, server.URL, RetryConfig{})

	response, err := client.Exchange(t.Context(), "source-token", ExchangeRequest{})
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, "retried-passport", response.Passport)
	assert.Equal(t, int32(2), callCount.Load())
}

func TestExchangeDoesNotRetry500ByDefault(t *testing.T) {
	t.Parallel()

	assertDoesNotRetryStatus(t, http.StatusInternalServerError, `{"error":"server_error","error_description":"unknown"}`)
}

func TestExchangeCanRetry500WhenConfigured(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempt := callCount.Add(1)

		w.Header().Set("Content-Type", "application/json")

		if attempt == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"server_error","error_description":"retryable by config"}`))

			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"passport":"configured-retry-success","expires_in":60}`))
	}))
	t.Cleanup(server.Close)

	client := newTestClient(t, server.URL, RetryConfig{
		RetryableStatusCodes: []int{http.StatusInternalServerError, http.StatusServiceUnavailable},
	})

	response, err := client.Exchange(t.Context(), "source-token", ExchangeRequest{})
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, "configured-retry-success", response.Passport)
	assert.Equal(t, int32(2), callCount.Load())
}

func TestExchangeRetriesNetworkErrorByDefault(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int32

	transport := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		attempt := callCount.Add(1)
		if attempt == 1 {
			return nil, errDialTCPTimeout
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       ioNopCloser(strings.NewReader(`{"passport":"network-retry-success","expires_in":60}`)),
		}, nil
	})

	httpClient := &http.Client{Transport: transport}

	client, err := NewClient(Options{
		BaseURL:    "https://identity.example.com",
		HTTPClient: httpClient,
		Clock:      newTestClock(time.Now()),
		Retry: RetryConfig{
			MinBackoff: 0,
			MaxBackoff: 0,
		},
	})
	require.NoError(t, err)

	response, err := client.Exchange(t.Context(), "source-token", ExchangeRequest{})
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, "network-retry-success", response.Passport)
	assert.Equal(t, int32(2), callCount.Load())
}

func TestExchangeDoesNotRetryNetworkErrorWhenDisabled(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int32

	transport := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		callCount.Add(1)

		return nil, errConnectionRefused
	})

	httpClient := &http.Client{Transport: transport}

	client, err := NewClient(Options{
		BaseURL:    "https://identity.example.com",
		HTTPClient: httpClient,
		Clock:      newTestClock(time.Now()),
		Retry: RetryConfig{
			RetryNetworkErrors: boolPtr(false),
		},
	})
	require.NoError(t, err)

	response, err := client.Exchange(t.Context(), "source-token", ExchangeRequest{})
	require.Nil(t, response)
	require.Error(t, err)

	transportError := &TransportError{}
	require.ErrorAs(t, err, &transportError)
	assert.Equal(t, int32(1), callCount.Load())
}

func TestExchangeDoesNotRetryRequestEditorError(t *testing.T) {
	t.Parallel()

	var editorCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"passport":"unexpected-success","expires_in":60}`))
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(Options{
		BaseURL: server.URL,
		Clock:   newTestClock(time.Now()),
		RequestEditors: []RequestEditorFn{
			func(context.Context, *http.Request) error {
				editorCalls.Add(1)

				return errEditorFailure
			},
		},
	})
	require.NoError(t, err)

	response, err := client.Exchange(t.Context(), "source-token", ExchangeRequest{})
	require.Nil(t, response)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrEditExchangeRequest)
	assert.Equal(t, int32(1), editorCalls.Load())
}

func TestExchangeRespectsTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(80 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"passport":"slow-success","expires_in":60}`))
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(Options{
		BaseURL: server.URL,
		Clock:   newTestClock(time.Now()),
		Retry: RetryConfig{
			RetryNetworkErrors: boolPtr(false),
		},
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()

	response, err := client.Exchange(ctx, "source-token", ExchangeRequest{})
	require.Nil(t, response)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type nopCloser struct {
	reader *strings.Reader
}

func ioNopCloser(reader *strings.Reader) *nopCloser {
	return &nopCloser{reader: reader}
}

func (n *nopCloser) Read(data []byte) (int, error) {
	return n.reader.Read(data)
}

func (n *nopCloser) Close() error {
	return nil
}
