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

package rbac

import (
	"context"
	goerrors "errors"
	"runtime/debug"

	"github.com/unikorn-cloud/identity/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// This file is the A7 shadow-mode comparator: with --authorization-engine
// shadow, every dispatched Allow* check evaluates the legacy ACL walk AND the
// Cerbos coarse check synchronously, SERVES THE LEGACY VERDICT
// UNCONDITIONALLY, and logs disagreement.  Nothing the shadow evaluation does
// — a policy deny, a PDP outage, a panic — may alter the served verdict: the
// comparison is recover-wrapped and its result is only ever a log line.
//
// The log taxonomy is load-bearing for the A12 cutover gate:
//
//   - "cerbos shadow divergence" — the PDP produced a VERDICT and it differs
//     from legacy's.  Comparison is on allow/deny alone, never on error
//     message strings.  This is the policy-parity signal A12 reads.
//   - "cerbos shadow evaluation failure" — no verdict was obtained
//     (ErrDecisionUnavailable, ErrResolutionFailed, or a recovered panic).
//     This is infra signal, triaged separately: a PDP restart during the
//     shadow phase must never register as policy divergence.
//
// Records emit through the request-scoped logr logger (log.FromContext) into
// the shared zap JSON stream, trace-correlated by the core OTel middleware —
// the same sink as A10's decision records (decision_log.go).  logr has no
// warn level; both record classes emit at Info so they are unconditionally
// visible, which the A12 gate requires.
//
// Synchronous comparison is deliberate: deterministic, testable, and bounded
// by the PDP client's --cerbos-check-timeout.  Shadow is an opt-in validation
// phase, not steady state — each dispatched check pays bindings resolution
// plus a PDP round trip on top of the legacy walk (see pkg/rbac/README.md
// for the cost notes).
const (
	shadowDivergenceMessage = "cerbos shadow divergence"
	shadowFailureMessage    = "cerbos shadow evaluation failure"
)

// engineForShadow returns the context's decision engine when — and only when
// — the shadow comparison must run alongside the legacy decision for this
// kind: an engine was seeded and its mode for the kind is shadow (modeForKind).
// A kind cut over to Cerbos (its modeForKind is cerbos, the A12 switch) is
// therefore NOT shadowed under a shadow baseline — it is authoritative-served
// through engineForDispatch instead, exactly right.  Impersonated requests are
// compared too, since A14: the legacy intersection verdict against the AND-ed
// dual-check verdict — both single booleans, so the comparator needs no
// structural change.
func engineForShadow(ctx context.Context, kind string) *RBAC {
	engine := EngineFromContext(ctx)

	if engine == nil || engine.modeForKind(kind) != EngineShadow {
		return nil
	}

	return engine
}

// shadowed returns legacyErr UNCHANGED, first running the Cerbos shadow
// comparison when shadow mode is active for this context.  This is the
// zero-behaviour-change contract of shadow mode: the legacy verdict — already
// computed by the time this runs — is always the served verdict.
func shadowed(ctx context.Context, resource Resource, operation openapi.AclOperation, legacyErr error) error {
	if engine := engineForShadow(ctx, resource.Kind); engine != nil {
		engine.shadowCompare(ctx, resource, operation, legacyErr == nil)
	}

	return legacyErr
}

// shadowCompare evaluates the Cerbos coarse check for one already-decided
// legacy verdict and logs disagreement.  It never returns anything and never
// panics: the recover wrap is the worst-case half of the zero-behaviour-change
// contract — a panicking PDP client (or a bug in the comparison itself) is a
// log line, never a request failure.
func (r *RBAC) shadowCompare(ctx context.Context, resource Resource, operation openapi.AclOperation, legacyAllowed bool) {
	var attrs []any

	defer func() {
		if value := recover(); value != nil {
			log.FromContext(ctx).Info(shadowFailureMessage, append(attrs,
				"cerbos_class", "panic",
				"panic", value,
				"stack", string(debug.Stack()))...)
		}
	}()

	attrs = shadowAttrs(ctx, resource, operation, legacyAllowed)

	// The marker keeps this evaluation out of the served-decision audit
	// records and counter (decision_log.go): shadow's own taxonomy below is
	// the observability for this path.  The shared PDP latency histogram
	// still records — transport health is path-independent.  The shallow copy
	// inherits r.pdp directly (a nil PDP stays nil, so Check fails closed
	// exactly as it would in cerbos mode).
	shadow := *r
	shadow.shadowEvaluation = true

	err := shadow.Check(ctx, resource, operation)

	switch {
	case err == nil, goerrors.Is(err, ErrPolicyDenied):
		// A verdict was obtained: compare allow/deny — NEVER error message
		// strings (cerbos-path denials carry a generic message by design).
		cerbosAllowed := err == nil

		if cerbosAllowed == legacyAllowed {
			return
		}

		// The correlate pins the policy-store revision this divergence was
		// observed against — the store hash r.policyHasher reports, or "" when
		// none is configured (A20, replacing the empty PDP version/scope echo).
		log.FromContext(ctx).Info(shadowDivergenceMessage, append(attrs,
			"cerbos_verdict", decisionVerdict(cerbosAllowed),
			"cerbos_class", shadowClass(err),
			"policy_hash", r.policyStoreHash(ctx))...)
	default:
		// No verdict was obtained (unavailability, resolution failure or an
		// unclassified error): infra signal, NEVER divergence — A12's
		// zero-divergence gate must not be poisoned by a PDP restart.
		log.FromContext(ctx).Info(shadowFailureMessage, append(attrs,
			"cerbos_class", shadowClass(err),
			"error", err)...)
	}
}

// shadowAttrs assembles the fields common to both shadow log classes.  The
// field set is CLOSED and credential-free by construction: only the subject
// identifier and account type are read from the authorization info
// (decisionSubject, the same closed read the decision log uses), never
// tokens or claims.
func shadowAttrs(ctx context.Context, resource Resource, operation openapi.AclOperation, legacyAllowed bool) []any {
	subject, actorType := decisionSubject(ctx)

	return []any{
		"subject", subject,
		"actor_type", actorType,
		"endpoint", resource.Kind,
		"operation", string(operation),
		"organization_id", resource.OrganizationID,
		"project_id", resource.ProjectID,
		"legacy_verdict", decisionVerdict(legacyAllowed),
	}
}

// shadowClass names the Cerbos-side outcome for the log record, derived from
// the decision error taxonomy via errors.Is — never from message strings.
func shadowClass(err error) string {
	switch {
	case err == nil:
		return "allowed"
	case goerrors.Is(err, ErrPolicyDenied):
		return "policy_denied"
	case goerrors.Is(err, ErrDecisionUnavailable):
		return "decision_unavailable"
	case goerrors.Is(err, ErrResolutionFailed):
		return "resolution_failed"
	default:
		return "unclassified"
	}
}
