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

	"go.opentelemetry.io/otel/metric"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// errJWKSRefreshThrottled is returned when a JWKS fetch is attempted before
// the minimum refresh interval has elapsed since the last attempt.
var errJWKSRefreshThrottled = errors.New("auth0 JWKS refresh throttled")

// throttledTransport bounds the rate of upstream JWKS fetches.
//
// The keySet refetches the JWKS whenever a token presents a key ID absent from
// the cache. A stream of unknown-kid tokens could therefore drive one HTTP
// request per token and exhaust the JWKS endpoint's rate limit. Throttling at
// the HTTP layer bounds every fetch trigger to one upstream request per
// minInterval: tokens that verify against a cached key never reach this
// transport, and anything that demands a refetch inside the window fails
// verification without contacting Auth0.
//
// After a legitimate Auth0 key rotation, the first token demanding a refetch
// fetches as normal (or waits out at most one window under attack), and the
// refreshed cache then serves the new key without further fetches.
type throttledTransport struct {
	base        http.RoundTripper
	minInterval time.Duration
	now         func() time.Time
	throttled   metric.Int64Counter

	mu          sync.Mutex
	lastRequest time.Time
	// loggedThisWindow gates the throttled-path log to once per window: it
	// is cleared when a fetch is forwarded and set on the first rejection
	// thereafter. See RoundTrip for why per-request logging is unsafe here.
	loggedThisWindow bool
}

func newThrottledTransport(base http.RoundTripper, minInterval time.Duration, now func() time.Time, meter metric.Meter) *throttledTransport {
	if now == nil {
		now = time.Now
	}

	// The error only reports an invalid instrument configuration; the name,
	// description, and unit here are static, and the API returns a usable
	// no-op counter regardless, so there is nothing actionable to handle.
	throttled, _ := meter.Int64Counter(
		"unikorn_identity_auth0_jwks_refreshes_throttled",
		metric.WithDescription("Upstream JWKS fetches suppressed by the minimum-refresh-interval throttle."),
		metric.WithUnit("{fetch}"),
	)

	return &throttledTransport{
		base:        base,
		minInterval: minInterval,
		now:         now,
		throttled:   throttled,
	}
}

func (t *throttledTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()

	if t.now().Sub(t.lastRequest) < t.minInterval {
		firstInWindow := !t.loggedThisWindow
		t.loggedThisWindow = true
		t.mu.Unlock()

		// Count every suppressed fetch so the metric reflects the true
		// rate — a sustained spike is the refetch-storm attack signature.
		t.throttled.Add(req.Context(), 1)

		// Log at most once per window, though: when the throttle is
		// absorbing a storm it fires on nearly every request, so a
		// per-request log would reproduce the very flooding it prevents.
		//
		// req.Context() is the key set's background context (see
		// getVerifier), not a per-request one, so it carries no
		// request-scoped logger; this resolves to the process-global
		// logger the server installs via SetupLogging.
		if firstInWindow {
			log.FromContext(req.Context()).Info(
				"auth0 JWKS refresh throttled; suppressing refetches until the interval elapses",
				"minInterval", t.minInterval.String(),
			)
		}

		return nil, errJWKSRefreshThrottled
	}

	// The window is consumed whether or not the request succeeds, so a
	// failing upstream is contacted at most once per interval.
	t.lastRequest = t.now()
	t.loggedThisWindow = false
	t.mu.Unlock()

	return t.base.RoundTrip(req)
}
