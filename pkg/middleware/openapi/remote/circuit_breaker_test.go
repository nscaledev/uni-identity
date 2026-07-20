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

package authorizer_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/failsafe-go/failsafe-go/circuitbreaker"
	"github.com/stretchr/testify/require"

	authorizer "github.com/unikorn-cloud/identity/pkg/middleware/openapi/remote"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// These tests pin cut #2's circuit breaker guarding CheckMany: it must trip
// on sustained failure to obtain a verdict (never on a returned deny), fail
// every call instantly with NO further HTTP round trip while open, recover
// through a half-open probe, and preserve the existing fail-closed mapping
// through AllowCoarse. They reuse the checkHandler/newCheckAuthorizer/
// checkAuthContext fixtures from decision_test.go.

// testBreaker builds a fast, deterministic, COUNT-based circuit breaker for
// these tests: exactly failureThreshold consecutive failures trips it open,
// and a single half-open success closes it again. Production (NewAuthorizer)
// instead uses a slower time-based failure-RATE profile tuned for real
// traffic, not test determinism -- but the mechanics under test here (trips
// on a CheckMany error, never on a deny, fails fast with no round trip while
// open, recovers via half-open) are identical either way: both are ordinary
// failsafe-go CircuitBreaker instances that CheckMany drives the same way.
func testBreaker(failureThreshold uint, delay time.Duration) circuitbreaker.CircuitBreaker[[]bool] {
	return circuitbreaker.NewBuilder[[]bool]().
		WithFailureThreshold(failureThreshold).
		WithDelay(delay).
		WithSuccessThreshold(1).
		Build()
}

func singleCheck() []authorizer.CheckRequest {
	return []authorizer.CheckRequest{
		{Resource: authorizer.Resource{Kind: "identity:groups", OrganizationID: "org-1"}, Action: identityapi.Read},
	}
}

// TestCircuitBreakerOpensOnSustainedFailure pins the trip condition: enough
// consecutive CheckMany failures (a 5xx -- no verdict obtained) opens the
// breaker. This also exercises WithCircuitBreaker as a tuning seam: the
// custom (fast, count-based) breaker below is what actually governs
// CheckMany's behavior here, not the slower production default.
func TestCircuitBreakerOpensOnSustainedFailure(t *testing.T) {
	t.Parallel()

	breaker := testBreaker(2, time.Minute)
	h := &checkHandler{status: http.StatusInternalServerError}
	auth := newCheckAuthorizer(t, h, authorizer.WithCircuitBreaker(breaker))

	ctx := checkAuthContext(t, "", false)

	for range 2 {
		_, err := auth.CheckMany(ctx, singleCheck())
		require.ErrorIs(t, err, authorizer.ErrDecisionUnavailable)
	}

	require.True(t, breaker.IsOpen(), "the breaker must open after the configured run of sustained failures")
}

// TestCircuitBreakerFailsFastWithoutRoundTrip is the whole point of the
// breaker: once open, CheckMany must fail instantly and must NOT invoke the
// transport a second time -- protecting a struggling PDP from further load,
// rather than paying for another (bounded but nonzero) call.
func TestCircuitBreakerFailsFastWithoutRoundTrip(t *testing.T) {
	t.Parallel()

	breaker := testBreaker(1, time.Minute)
	h := &checkHandler{status: http.StatusInternalServerError}
	auth := newCheckAuthorizer(t, h, authorizer.WithCircuitBreaker(breaker))

	ctx := checkAuthContext(t, "", false)

	_, err := auth.CheckMany(ctx, singleCheck())
	require.ErrorIs(t, err, authorizer.ErrDecisionUnavailable)
	require.True(t, breaker.IsOpen())
	require.Equal(t, 1, h.requests, "the one failing call must have reached the transport")

	_, err = auth.CheckMany(ctx, singleCheck())
	require.ErrorIs(t, err, authorizer.ErrDecisionUnavailable)
	require.Equal(t, 1, h.requests, "an open breaker must short-circuit: the transport must NOT be invoked a second time")
}

// TestCircuitBreakerDeniesDoNotTrip pins the load-bearing correctness
// invariant: a run of SUCCESSFUL checks that deny (Allowed=false) must never
// open the breaker, however many of them there are. CheckMany returns
// (allowed, nil) for a served decision regardless of allow/deny content (see
// decision.go/mapCheckResponse), so the breaker -- which only ever sees the
// nil error -- must treat every one of these as a success. The threshold is
// deliberately hair-trigger (1) to make the claim as strong as possible: even
// a breaker that would open on a SINGLE failure must stay closed here.
func TestCircuitBreakerDeniesDoNotTrip(t *testing.T) {
	t.Parallel()

	breaker := testBreaker(1, time.Minute)
	h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: false}}}
	auth := newCheckAuthorizer(t, h, authorizer.WithCircuitBreaker(breaker))

	ctx := checkAuthContext(t, "", false)

	for range 10 {
		allowed, err := auth.CheckMany(ctx, singleCheck())
		require.NoError(t, err)
		require.Equal(t, []bool{false}, allowed)
	}

	require.True(t, breaker.IsClosed(), "a run of policy denies -- successful checks -- must never open the breaker")
	require.Equal(t, 10, h.requests, "every deny must still be a real, served call")
}

// TestCircuitBreakerRecoversThroughHalfOpen pins recovery: after the cooldown
// elapses the breaker allows a half-open probe through (not another
// short-circuit); a successful probe closes it and the transport is
// reachable normally again.
func TestCircuitBreakerRecoversThroughHalfOpen(t *testing.T) {
	t.Parallel()

	breaker := testBreaker(1, 20*time.Millisecond)
	h := &checkHandler{status: http.StatusInternalServerError}
	auth := newCheckAuthorizer(t, h, authorizer.WithCircuitBreaker(breaker))

	ctx := checkAuthContext(t, "", false)

	_, err := auth.CheckMany(ctx, singleCheck())
	require.ErrorIs(t, err, authorizer.ErrDecisionUnavailable)
	require.True(t, breaker.IsOpen())

	// The backend recovers; wait out the cooldown before probing.
	h.status = http.StatusOK
	h.results = []identityapi.AuthorizationCheckResult{{Allowed: true}}

	time.Sleep(30 * time.Millisecond)

	allowed, err := auth.CheckMany(ctx, singleCheck())
	require.NoError(t, err, "a successful half-open probe must be served, not short-circuited")
	require.Equal(t, []bool{true}, allowed)
	require.True(t, breaker.IsClosed(), "the single successful probe must close the breaker (WithSuccessThreshold(1))")
	require.Equal(t, 2, h.requests, "the probe must be a real call: one failure, then one successful probe")
}

// TestCircuitBreakerFailClosedMappingIntact pins parity with today's
// transport-failure behavior: an open breaker must still surface as
// rbac.ErrDecisionUnavailable (a deny) through AllowCoarse, exactly like any
// other CheckMany failure -- engine.go folds every CheckMany error the same
// way (see engine.go's AllowCoarseMany) -- so the breaker changes only HOW
// FAST the deny arrives, never the decision shape.
func TestCircuitBreakerFailClosedMappingIntact(t *testing.T) {
	t.Parallel()

	breaker := testBreaker(1, time.Minute)
	h := &checkHandler{status: http.StatusInternalServerError}
	engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h, authorizer.WithCircuitBreaker(breaker)))

	resource := rbac.Resource{Kind: "identity:groups", OrganizationID: "org-1"}
	ctx := checkAuthContext(t, "", false)

	// Trip it via the ordinary transport-failure path.
	require.ErrorIs(t, engine.AllowCoarse(ctx, resource, identityapi.Read), rbac.ErrDecisionUnavailable)
	require.True(t, breaker.IsOpen())

	// Open-breaker path: still rbac.ErrDecisionUnavailable, i.e. still a deny,
	// identical in shape to the transport-failure case above.
	err := engine.AllowCoarse(ctx, resource, identityapi.Read)
	require.ErrorIs(t, err, rbac.ErrDecisionUnavailable)
	require.Equal(t, 1, h.requests, "the second AllowCoarse call must have been short-circuited by the open breaker")
}

// TestCircuitBreakerOptionDisable pins the rollback path: WithCircuitBreaker(nil)
// removes the breaker entirely, so CheckMany behaves exactly as it did before
// this guardrail existed -- every call reaches the transport, however many
// failed before it.
func TestCircuitBreakerOptionDisable(t *testing.T) {
	t.Parallel()

	h := &checkHandler{status: http.StatusInternalServerError}
	auth := newCheckAuthorizer(t, h, authorizer.WithCircuitBreaker(nil))

	ctx := checkAuthContext(t, "", false)

	for range 5 {
		_, err := auth.CheckMany(ctx, singleCheck())
		require.ErrorIs(t, err, authorizer.ErrDecisionUnavailable)
	}

	require.Equal(t, 5, h.requests, "with the breaker disabled every call must reach the transport, even after repeated failures")
}

// TestCircuitBreakerDefaultTripsOnSustainedFailure proves NewAuthorizer wires
// a WORKING breaker with the shipped defaults and zero extra configuration --
// "every consumer (region/compute/kubernetes) gets it for free" -- rather
// than only testing the mechanism via a custom WithCircuitBreaker override.
// It drives exactly the default profile's minimum sample size (10 executions,
// see NewAuthorizer's defaultBreakerFailureExecutionThreshold) as sustained
// failures: a 100% failure rate over those 10 is well past the 50% trip
// threshold, and — because the underlying stats are a rolling SUM over the
// whole window, not bucket-local — this trips deterministically with no
// sleep needed, however fast the calls execute.
func TestCircuitBreakerDefaultTripsOnSustainedFailure(t *testing.T) {
	t.Parallel()

	h := &checkHandler{status: http.StatusInternalServerError}
	auth := newCheckAuthorizer(t, h) // no WithCircuitBreaker override: the real NewAuthorizer default

	ctx := checkAuthContext(t, "", false)

	for range 10 {
		_, err := auth.CheckMany(ctx, singleCheck())
		require.ErrorIs(t, err, authorizer.ErrDecisionUnavailable)
	}

	require.Equal(t, 10, h.requests)

	// The default breaker must now be open: the next call is short-circuited.
	_, err := auth.CheckMany(ctx, singleCheck())
	require.ErrorIs(t, err, authorizer.ErrDecisionUnavailable)
	require.Equal(t, 10, h.requests, "the default breaker must have opened after 10 sustained failures: the 11th call must not reach the transport")
}
