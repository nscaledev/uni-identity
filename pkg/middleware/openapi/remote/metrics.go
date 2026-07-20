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
	"time"

	"github.com/failsafe-go/failsafe-go/circuitbreaker"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// This file is Task 9's CALLER-side decision telemetry: one structured log
// record and one counter increment per (resource, action) entry of a
// RemoteEngine.AllowCoarseMany round trip, plus one latency observation for
// the round trip itself.  It is the CONSUMER's own view of a remote
// decision — network latency and the outcome the caller itself observed
// (allow/deny/unavailable) — hooked at the CheckMany call in
// AllowCoarseMany, the same choke point AllowCoarse funnels through (see
// engine.go), so a single-resource AllowCoarse call is instrumented for
// free: exactly one latency observation and one counter increment, never
// two, regardless of which method the caller entered through.
//
// This is deliberately distinct from, and NOT redundant with, identity's OWN
// server-side A10 decision observability (pkg/rbac/decision_log.go): A10
// records the PDP-served decision from INSIDE identity's process for every
// CheckMany caller, including a request that arrived over this package's
// remote /authorization/check call.  This file records the SAME logical
// decision from the OTHER end of that wire call: the downstream caller's own
// process, measuring the hop A10 cannot see (its own network round trip to
// identity) and never touching identity's log stream or instruments.  The
// "source"="remote" field exists so the two streams stay distinguishable if
// ever aggregated together.
//
// Unlike A10's (decision x class) attribute pair, the outcome vocabulary
// here is flat and three-way (allow, deny, unavailable): CheckMany's error
// taxonomy collapses to a single "unavailable" class at this boundary (see
// engine.go's AllowCoarseMany, which folds every CheckMany failure into
// rbac.ErrDecisionUnavailable) -- there is no resolution/impersonation split
// to preserve on the caller side, so a second "class" attribute would be
// dead weight.
//
// Levels mirror A10's convention: denies and unavailable outcomes are
// unconditional Info (the deny-focused default stream); allows are V(1)
// (visible at raised verbosity, quiet by default).

// remoteDecisionMessage is the load-bearing message constant of the
// caller-side decision-log stream: dashboards and operators grep it, so a
// rename is a breaking change (the unit tests duplicate it deliberately).
const remoteDecisionMessage = "remote authorization decision"

// newRemoteDecisionInstruments creates the two Task 9 caller-side decision
// instruments, mirroring pkg/rbac/decision_log.go's newDecisionInstruments
// idiom exactly.
//
// Both export ONLY when the consumer service is started with
// --otlp-endpoint (metrics are pushed over OTLP; no /metrics endpoint
// exists) -- without it the recordings are silently dropped.
func newRemoteDecisionInstruments() (metric.Int64Counter, metric.Float64Histogram) {
	// The errors only report an invalid instrument configuration; the names,
	// descriptions, and units are static and the API returns usable no-op
	// instruments regardless, so there is nothing actionable to handle.
	decisions, _ := otel.Meter(constants.Application).Int64Counter(
		"unikorn_identity_authz_remote_decision_total",
		metric.WithDescription("Caller-observed outcomes of a RemoteEngine AllowCoarse/AllowCoarseMany decision, by outcome (allow, deny or unavailable): the consumer's own view of the remote /authorization/check round trip, distinct from identity's server-side unikorn_identity_authz_decisions_total."),
		metric.WithUnit("{decision}"),
	)

	// Explicit boundaries sized for a cross-service network hop, not a
	// localhost gRPC call: A10's pdp_latency tops out at 2s because it never
	// leaves the pod, but this histogram times a call across the network to
	// identity, so it is shifted an order of magnitude up (0.005s..5s) -- the
	// top buckets exist to make a slow or timing-out identity visible.
	latency, _ := otel.Meter(constants.Application).Float64Histogram(
		"unikorn_identity_authz_remote_decision_latency",
		metric.WithDescription("RemoteEngine CheckMany round-trip latency, as observed by the caller: one sample per AllowCoarse/AllowCoarseMany call, whatever the batch size."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
	)

	return decisions, latency
}

// remoteDecisionOutcome renders the closed allow/deny/unavailable vocabulary
// for one check's verdict.  callErr is the error CheckMany returned for the
// WHOLE round trip (nil on a served batch); allowed is that one check's own
// policy verdict, only meaningful when callErr is nil.  This is exactly the
// classification AllowCoarse's own return value already carries (nil,
// rbac.ErrPolicyDenied, or rbac.ErrDecisionUnavailable) -- CheckMany never
// itself returns a policy deny as an error, a batch failure is always
// unavailability (see engine.go) -- so testing callErr first and allowed
// second, rather than errors.Is on a per-check error nothing constructs, is
// a complete and equivalent classification.
func remoteDecisionOutcome(callErr error, allowed bool) string {
	switch {
	case callErr != nil:
		return "unavailable"
	case allowed:
		return "allow"
	default:
		return "deny"
	}
}

// remoteDecisionSubject reads the ONLY identity field this record may carry
// -- the acting subject -- from the request's authorization info, mirroring
// pkg/rbac's decisionSubject discipline (unexported there, so this is a
// minimal local renderer, not an import): a missing or unresolvable info
// yields an empty subject, never an invented one, and NEVER a token, claim
// or passport.
func remoteDecisionSubject(ctx context.Context) string {
	info, err := authorization.FromContext(ctx)
	if err != nil || info.Userinfo == nil {
		return ""
	}

	return info.Userinfo.Sub
}

// recordDecisions emits one log record and one counter increment per
// (resource, action) entry of an AllowCoarseMany round trip -- the flat,
// greppable batch shape A10 also uses.  elapsed is the WHOLE round trip
// (CheckMany's call, not any one entry), shared by every entry's record; the
// caller has already folded the same elapsed value into the latency
// histogram once, before calling this.
func (e *RemoteEngine) recordDecisions(ctx context.Context, checks []CheckRequest, allowed []bool, callErr error, elapsed time.Duration) {
	subject := remoteDecisionSubject(ctx)
	logger := log.FromContext(ctx)

	for i, check := range checks {
		var verdict bool
		if callErr == nil {
			verdict = allowed[i]
		}

		outcome := remoteDecisionOutcome(callErr, verdict)

		fields := []any{
			"subject", subject,
			"endpoint", check.Resource.Kind,
			"operation", string(check.Action),
			"organization_id", check.Resource.OrganizationID,
			"project_id", check.Resource.ProjectID,
			"decision", outcome,
			"source", "remote",
			"latency", elapsed,
		}

		if outcome == "allow" {
			logger.V(1).Info(remoteDecisionMessage, fields...)
		} else {
			logger.Info(remoteDecisionMessage, fields...)
		}

		e.decisions.Add(ctx, 1, metric.WithAttributes(
			attribute.String("outcome", outcome),
		))
	}
}

// This section is cut #2's breaker-state observability, mirroring the
// caller-side decision instruments above exactly: a no-op-safe otel counter
// (exports only with --otlp-endpoint) plus a structured log line, both keyed
// off the failsafe-go CircuitBreaker's own OnStateChanged event (see
// NewAuthorizer) rather than anything derived from a single decision. This is
// the ONLY way an operator sees the breaker open without reading source, so
// every transition — not only closed->open — is logged unconditionally at
// Info: half-open dropping back to open (a failed recovery probe) is exactly
// as actionable as the initial trip.

// remoteBreakerStateMessage is the load-bearing message constant of the
// breaker-state-transition log stream (mirrors remoteDecisionMessage):
// dashboards/alerts grep it, so a rename is a breaking change.
const remoteBreakerStateMessage = "remote authorization circuit breaker state changed"

// newRemoteBreakerStateInstrument creates the breaker-state-transition
// counter, mirroring newRemoteDecisionInstruments' construction idiom
// exactly (the config error is unactionable; the API returns a usable no-op
// instrument regardless).
func newRemoteBreakerStateInstrument() metric.Int64Counter {
	counter, _ := otel.Meter(constants.Application).Int64Counter(
		"unikorn_identity_authz_remote_breaker_transitions_total",
		metric.WithDescription("Circuit-breaker state transitions guarding the RemoteEngine CheckMany round trip (see NewAuthorizer/WithCircuitBreaker), by the state entered (closed, open, half_open)."),
		metric.WithUnit("{transition}"),
	)

	return counter
}

// breakerStateName renders a circuitbreaker.State for the log/metric
// vocabulary above.
func breakerStateName(s circuitbreaker.State) string {
	switch s {
	case circuitbreaker.ClosedState:
		return "closed"
	case circuitbreaker.OpenState:
		return "open"
	case circuitbreaker.HalfOpenState:
		return "half_open"
	default:
		return "unknown"
	}
}

// newBreakerStateChangedListener returns the failsafe OnStateChanged
// listener wired into the default breaker (see NewAuthorizer). event.Context
// is whichever request happened to trigger the transition (the executor is
// bound to that call's context in CheckMany), else context.Background if
// none was configured; log.FromContext falls back sanely either way.
func newBreakerStateChangedListener(counter metric.Int64Counter) func(circuitbreaker.StateChangedEvent) {
	return func(event circuitbreaker.StateChangedEvent) {
		newState := breakerStateName(event.NewState)

		log.FromContext(event.Context()).Info(remoteBreakerStateMessage,
			"from", breakerStateName(event.OldState),
			"to", newState,
			"source", "remote",
		)

		counter.Add(event.Context(), 1, metric.WithAttributes(
			attribute.String("state", newState),
		))
	}
}
