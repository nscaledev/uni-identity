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
	"sync"
	"time"
)

// errJWKSRefreshThrottled is returned when a JWKS fetch is attempted before
// the minimum refresh interval has elapsed since the last attempt. It is
// unexported because go-oidc wraps keyset errors with %v, so callers above
// the verifier could never match it with errors.Is anyway.
var errJWKSRefreshThrottled = errors.New("auth0 JWKS refresh throttled")

// throttledTransport bounds the rate of upstream JWKS fetches.
//
// go-oidc's RemoteKeySet fetches the JWKS whenever no cached key verifies a
// token's signature — for unknown kids and for forged signatures over known
// kids alike — and only deduplicates concurrent fetches. A stream of invalid
// tokens can therefore drive one HTTP request per token and exhaust the JWKS
// endpoint's rate limit. Throttling at the HTTP layer bounds every fetch
// trigger to one upstream request per minInterval: tokens that verify
// against a cached key never reach this transport, and anything that demands
// a refetch inside the window fails verification without contacting Auth0.
//
// After a legitimate Auth0 key rotation, the first token demanding a refetch
// fetches as normal (or waits out at most one window under attack), and the
// refreshed cache then serves the new key without further fetches.
type throttledTransport struct {
	base        http.RoundTripper
	minInterval time.Duration
	now         func() time.Time

	mu          sync.Mutex
	lastRequest time.Time
}

func newThrottledTransport(base http.RoundTripper, minInterval time.Duration, now func() time.Time) *throttledTransport {
	if now == nil {
		now = time.Now
	}

	return &throttledTransport{
		base:        base,
		minInterval: minInterval,
		now:         now,
	}
}

func (t *throttledTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()

	if t.now().Sub(t.lastRequest) < t.minInterval {
		t.mu.Unlock()
		return nil, errJWKSRefreshThrottled
	}

	// The window is consumed whether or not the request succeeds, so a
	// failing upstream is contacted at most once per interval.
	t.lastRequest = t.now()
	t.mu.Unlock()

	return t.base.RoundTrip(req)
}
