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

package idp

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

var errFakeUpstreamDown = errors.New("fake upstream down")

type fakeRoundTripper struct {
	calls int
	err   error
}

func (f *fakeRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	f.calls++

	if f.err != nil {
		return nil, f.err
	}

	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}

func newThrottleTestRequest(t *testing.T) *http.Request {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://tenant.example.com/.well-known/jwks.json", nil)
	require.NoError(t, err)

	return req
}

func roundTrip(t *testing.T, transport http.RoundTripper, req *http.Request) error {
	t.Helper()

	resp, err := transport.RoundTrip(req)
	if resp != nil {
		require.NoError(t, resp.Body.Close())
	}

	return err
}

func noopMeter() metric.Meter {
	return noop.NewMeterProvider().Meter("test")
}

// TestThrottledTransportSecondRequestThrottled documents the DoS mitigation:
// a second JWKS fetch within the interval is rejected without reaching the
// upstream, so invalid tokens cannot drive one fetch per token. Once the
// interval elapses, the next fetch is allowed through again.
func TestThrottledTransportSecondRequestThrottled(t *testing.T) {
	t.Parallel()

	base := &fakeRoundTripper{}

	clock := time.Unix(1_700_000_000, 0)
	now := func() time.Time { return clock }

	transport := newThrottledTransport(base, 60*time.Second, now, noopMeter())
	req := newThrottleTestRequest(t)

	require.NoError(t, roundTrip(t, transport, req))
	assert.Equal(t, 1, base.calls)

	require.ErrorIs(t, roundTrip(t, transport, req), errJWKSRefreshThrottled)
	assert.Equal(t, 1, base.calls)

	clock = clock.Add(60 * time.Second)

	require.NoError(t, roundTrip(t, transport, req))
	assert.Equal(t, 2, base.calls)
}

// TestThrottledTransportLogsOncePerWindow pins the log rate-limiting. When
// the throttle is absorbing a refetch storm it fires on nearly every request,
// so a per-request log would reproduce the very flooding the throttle exists
// to prevent. Each window must emit exactly one log line, and a new window
// must re-arm it.
//
// The logger is injected through the request context only to capture output
// deterministically. In production RoundTrip runs with the key set's
// background context (see getVerifier), which carries no logger, so the line
// resolves to the process-global logger the server installs via SetupLogging;
// the once-per-window logic under test is independent of which sink receives
// it.
func TestThrottledTransportLogsOncePerWindow(t *testing.T) {
	t.Parallel()

	var logLines int

	logger := funcr.New(func(_, _ string) { logLines++ }, funcr.Options{})

	base := &fakeRoundTripper{}

	clock := time.Unix(1_700_000_000, 0)
	now := func() time.Time { return clock }

	transport := newThrottledTransport(base, 60*time.Second, now, noopMeter())

	req := newThrottleTestRequest(t)
	req = req.WithContext(log.IntoContext(req.Context(), logger))

	// A forwarded fetch opens the window; the storm behind it is suppressed —
	// never reaching base — and must log exactly once.
	require.NoError(t, roundTrip(t, transport, req))

	for range 5 {
		require.ErrorIs(t, roundTrip(t, transport, req), errJWKSRefreshThrottled)
	}

	assert.Equal(t, 1, base.calls)
	assert.Equal(t, 1, logLines)

	// A new window re-arms the log: next forwarded fetch, next storm, one
	// more line — and still only the two forwarded fetches reach base.
	clock = clock.Add(60 * time.Second)

	require.NoError(t, roundTrip(t, transport, req))

	for range 5 {
		require.ErrorIs(t, roundTrip(t, transport, req), errJWKSRefreshThrottled)
	}

	assert.Equal(t, 2, base.calls)
	assert.Equal(t, 2, logLines)
}

// TestThrottledTransportCountsEverySuppressedFetch pins the metric's
// count-every-suppressed-fetch contract. The README presents the counter as
// reflecting the true storm rate, so — unlike the once-per-window log — the
// increment must fire on every rejection. A refactor that moved it behind the
// log gate would undercount a storm to one per interval and must fail here.
//
// The meter is injected from a sealed local provider rather than the global
// one, so the test mutates no process-wide state and stays parallel-safe.
func TestThrottledTransportCountsEverySuppressedFetch(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	meter := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test")

	base := &fakeRoundTripper{}

	clock := time.Unix(1_700_000_000, 0)
	now := func() time.Time { return clock }

	transport := newThrottledTransport(base, 60*time.Second, now, meter)
	req := newThrottleTestRequest(t)

	// One forwarded fetch opens the window; five suppressed fetches follow.
	require.NoError(t, roundTrip(t, transport, req))

	for range 5 {
		require.ErrorIs(t, roundTrip(t, transport, req), errJWKSRefreshThrottled)
	}

	// The sealed provider has exactly one scope and one instrument — the
	// throttle counter — so the storm's count can be read off directly.
	var rm metricdata.ResourceMetrics

	require.NoError(t, reader.Collect(t.Context(), &rm))
	require.Len(t, rm.ScopeMetrics, 1)
	require.Len(t, rm.ScopeMetrics[0].Metrics, 1)

	counter := rm.ScopeMetrics[0].Metrics[0]
	assert.Equal(t, "unikorn_identity_auth0_jwks_refreshes_throttled", counter.Name)

	sum, ok := counter.Data.(metricdata.Sum[int64])
	require.True(t, ok)
	require.Len(t, sum.DataPoints, 1)

	// Every suppressed fetch is counted — not one per window.
	assert.Equal(t, int64(5), sum.DataPoints[0].Value)
}

// TestThrottledTransportFailedRequestConsumesWindow ensures the window is
// spent whether or not the fetch succeeds. If failures were free, a failing
// or rate-limited upstream would be hammered with one request per token
// instead of one per interval — the exact load the throttle exists to bound.
func TestThrottledTransportFailedRequestConsumesWindow(t *testing.T) {
	t.Parallel()

	base := &fakeRoundTripper{err: errFakeUpstreamDown}

	clock := time.Unix(1_700_000_000, 0)
	now := func() time.Time { return clock }

	transport := newThrottledTransport(base, 60*time.Second, now, noopMeter())
	req := newThrottleTestRequest(t)

	require.ErrorIs(t, roundTrip(t, transport, req), errFakeUpstreamDown)
	assert.Equal(t, 1, base.calls)

	require.ErrorIs(t, roundTrip(t, transport, req), errJWKSRefreshThrottled)
	assert.Equal(t, 1, base.calls)
}
