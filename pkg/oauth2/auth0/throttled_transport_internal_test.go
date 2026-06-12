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

package auth0

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestThrottledTransportSecondRequestThrottled documents the DoS mitigation:
// a second JWKS fetch within the interval is rejected without reaching the
// upstream, so invalid tokens cannot drive one fetch per token. Once the
// interval elapses, the next fetch is allowed through again.
func TestThrottledTransportSecondRequestThrottled(t *testing.T) {
	t.Parallel()

	base := &fakeRoundTripper{}

	clock := time.Unix(1_700_000_000, 0)
	now := func() time.Time { return clock }

	transport := newThrottledTransport(base, 60*time.Second, now)
	req := newThrottleTestRequest(t)

	require.NoError(t, roundTrip(t, transport, req))
	assert.Equal(t, 1, base.calls)

	require.ErrorIs(t, roundTrip(t, transport, req), errJWKSRefreshThrottled)
	assert.Equal(t, 1, base.calls)

	clock = clock.Add(60 * time.Second)

	require.NoError(t, roundTrip(t, transport, req))
	assert.Equal(t, 2, base.calls)
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

	transport := newThrottledTransport(base, 60*time.Second, now)
	req := newThrottleTestRequest(t)

	require.ErrorIs(t, roundTrip(t, transport, req), errFakeUpstreamDown)
	assert.Equal(t, 1, base.calls)

	require.ErrorIs(t, roundTrip(t, transport, req), errJWKSRefreshThrottled)
	assert.Equal(t, 1, base.calls)
}
