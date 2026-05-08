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

package exchange_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/oauth2/auth0"
	oauth2errors "github.com/unikorn-cloud/identity/pkg/oauth2/errors"
	"github.com/unikorn-cloud/identity/pkg/oauth2/exchange"
)

var errUnrecognised = errors.New("boom")

// metricLabels finds the matching counter sample in the default registry and
// returns its label set. We can't share counters between subtests safely, so
// each test asserts on labels for a single emitted sample.
func metricLabels(t *testing.T, metricName string) []map[string]string {
	t.Helper()

	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	for _, family := range families {
		if family.GetName() != metricName {
			continue
		}

		results := make([]map[string]string, 0, len(family.GetMetric()))
		for _, m := range family.GetMetric() {
			results = append(results, labelsToMap(m.GetLabel()))
		}

		return results
	}

	return nil
}

func labelsToMap(pairs []*dto.LabelPair) map[string]string {
	m := make(map[string]string, len(pairs))
	for _, p := range pairs {
		m[p.GetName()] = p.GetValue()
	}

	return m
}

//nolint:paralleltest // DefaultGatherer is process-global; parallel writers would race label assertions.
func TestObserveExchange(t *testing.T) {
	t.Run("emits source and result labels", func(t *testing.T) {
		exchange.ObserveExchange(exchange.SourceAuth0, exchange.ResultSuccess, 10*time.Millisecond)
		exchange.ObserveExchange(exchange.SourceUNI, exchange.ResultUnauthorized, 5*time.Millisecond)
		exchange.ObserveExchange(exchange.SourceUnknown, exchange.ResultUnsupportedSource, time.Millisecond)

		labels := metricLabels(t, "identity_exchange_requests_total")

		assert.Contains(t, labels, map[string]string{"source": "auth0", "result": string(exchange.ResultSuccess)})
		assert.Contains(t, labels, map[string]string{"source": "uni", "result": string(exchange.ResultUnauthorized)})
		assert.Contains(t, labels, map[string]string{"source": "unknown", "result": string(exchange.ResultUnsupportedSource)})

		durLabels := metricLabels(t, "identity_exchange_duration_seconds")
		assert.Contains(t, durLabels, map[string]string{"source": "auth0"})
		assert.Contains(t, durLabels, map[string]string{"source": "uni"})
		assert.Contains(t, durLabels, map[string]string{"source": "unknown"})
	})
}

func TestClassifyResult(t *testing.T) {
	t.Parallel()

	t.Run("maps known errors to stable labels", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name     string
			err      error
			expected exchange.Result
		}{
			{name: "nil success", err: nil, expected: exchange.ResultSuccess},
			{name: "malformed token", err: exchange.ErrMalformedToken, expected: exchange.ResultMalformed},
			{name: "unsupported source", err: exchange.ErrUnsupportedSource, expected: exchange.ResultUnsupportedSource},
			{name: "wrapped unsupported source", err: fmt.Errorf("router: %w", exchange.ErrUnsupportedSource), expected: exchange.ResultUnsupportedSource},
			{name: "auth0 jwks unavailable", err: auth0.ErrJWKSUnavailable, expected: exchange.ResultJWKSUnavailable},
			{name: "auth0 token expired", err: auth0.ErrTokenExpired, expected: exchange.ResultExpired},
			{name: "auth0 insufficient scope", err: auth0.ErrInsufficientScope, expected: exchange.ResultInsufficientScope},
			{name: "auth0 invalid token", err: auth0.ErrInvalidToken, expected: exchange.ResultUnauthorized},
			{name: "uni userinfo unavailable", err: exchange.ErrUNIUserinfoNotAvailable, expected: exchange.ResultUnauthorized},
			{name: "oauth2 invalid request", err: oauth2errors.OAuth2InvalidRequest("bad request"), expected: exchange.ResultInvalidRequest},
			{name: "unrecognized falls through to error", err: errUnrecognised, expected: exchange.ResultError},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				assert.Equal(t, tt.expected, exchange.ClassifyResult(tt.err))
			})
		}
	})
}
