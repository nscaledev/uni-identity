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
	"net/http"
	"time"
)

const (
	defaultRetryMinBackoff       = 50 * time.Millisecond
	defaultRetryMaxBackoff       = 200 * time.Millisecond
	defaultRetryMaxAttempts      = 2
	defaultCacheTTL              = time.Minute
	minRemainingDurationForRetry = 250 * time.Millisecond
)

// ExchangePath is the exchange endpoint path.
const ExchangePath = "/oauth2/v2/exchange"

// RequestEditorFn mutates an outbound HTTP request before dispatch.
// It can be used for principal propagation and trace headers.
type RequestEditorFn func(context.Context, *http.Request) error

// ExchangeRequest configures optional exchange context.
type ExchangeRequest struct {
	OrganizationID string
	ProjectID      string
}

// ExchangeResponse is the successful exchange response payload.
type ExchangeResponse struct {
	Passport string `json:"passport"`
	//nolint:tagliatelle
	ExpiresIn int  `json:"expires_in"`
	Cached    bool `json:"-"`
}

// Options configures a token exchange client.
type Options struct {
	BaseURL        string
	HTTPClient     *http.Client
	Retry          RetryConfig
	Cache          CacheConfig
	RequestEditors []RequestEditorFn
	Metrics        MetricsHooks
	Clock          Clock
}

// RetryConfig configures retry behavior.
type RetryConfig struct {
	MaxAttempts          int
	RetryableStatusCodes []int
	RetryNetworkErrors   *bool
	MinBackoff           time.Duration
	MaxBackoff           time.Duration
}

// CacheConfig controls in-process response caching.
type CacheConfig struct {
	Enabled    bool
	DefaultTTL time.Duration
}

// MetricsHooks allows callers to plug in metrics without enforcing a metrics backend.
type MetricsHooks struct {
	IncTotal        func(result string)
	ObserveDuration func(duration time.Duration)
}
