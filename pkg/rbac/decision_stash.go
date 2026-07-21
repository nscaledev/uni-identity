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
	"slices"
	"sync"

	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// This file is the F2 decision stash: a request-scoped accumulator of Allow*
// outcomes, seeded by pkg/middleware/audit before it calls the handler chain
// and read back once the handler returns, so the audit record can carry the
// resources a request actually referenced and the authorization verdict on
// each — closing the design doc §8 finding that the front-door audit dropped
// this information entirely.
//
// Purely additive: appendDecision is a no-op unless a context carries an
// accumulator (seeded ONLY by NewDecisionAccumulatorContext), so every
// existing Allow* caller and every pre-existing test is unaffected, and no
// authorization decision itself changes — this only observes the verdict
// dispatchCoarse/AllowProjectScopeCreate already computed.
//
// Hooked at exactly two choke points, mirroring how A10's decision_log.go
// hooks CheckMany rather than decorating every call site: dispatchCoarse
// (handler.go) is the single dispatch point behind AllowGlobalScope,
// AllowOrganizationScope and AllowProjectScope (and therefore their …ID/
// …Reader delegates — see pkg/rbac/README.md's "three argument flavours"),
// so one append there covers all three families without duplicating the
// call at every wrapper. AllowProjectScopeCreate is hooked separately since
// it deliberately never calls dispatchCoarse (its live project-existence
// orchestration is entangled with legacy ACL structure — see its own NOTE).
// AllowRole is NOT hooked: it is a role-GRANTABILITY meta-check over a
// role's whole scope set (many endpoint/operation pairs, no single
// referenced resource), structurally unlike the four scope-check families,
// and out of scope for a per-resource audit trail.

// Decision is one entry in the request-scoped decision accumulator: the
// outcome of a single Allow* dispatch. pkg/middleware/audit seeds the
// accumulator before calling the handler chain and reads it back afterwards
// to attach the referenced resources and their authorization outcomes to
// the audit record.
type Decision struct {
	// ResourceKind is the RBAC endpoint name the check was evaluated
	// against, e.g. "identity:groups".
	ResourceKind string

	// ResourceID optionally identifies the specific resource instance
	// checked. Empty for coarse checks: global/organization/project scope
	// checks never carry a specific instance (see Resource.ID).
	ResourceID string

	// Action is the ACL operation checked (openapi.AclOperation
	// stringified, e.g. "create"/"read"/"update"/"delete").
	Action string

	// Decision is the tri-state verdict: "allow", "deny" or "unavailable".
	// "unavailable" means no policy verdict was reached at all (a binding
	// resolution or PDP/transport failure, or an impersonation type-gate
	// refusal) and the request was failed closed — distinct from an
	// explicit policy "deny", though callers of Allow* itself cannot tell
	// the two apart (both are a non-nil error; see decision_log.go's
	// "deny-shape parity" note).
	Decision string

	// Reason classifies why, reusing decision_log.go's vocabulary:
	// "policy" (an actual policy verdict, allow or deny), "impersonation"
	// (invalid impersonated principal type), "resolution" (binding
	// resolution failure) or "unavailable" (PDP/transport failure).
	Reason string
}

// decisionAccumulator collects Decision entries for one request. Guarded by
// a mutex: Allow* dispatch is normally sequential per request, but list
// filtering and other future callers may not be, and this must never be a
// data race.
type decisionAccumulator struct {
	mu      sync.Mutex
	entries []Decision
}

func (a *decisionAccumulator) append(d Decision) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.entries = append(a.entries, d)
}

func (a *decisionAccumulator) snapshot() []Decision {
	a.mu.Lock()
	defer a.mu.Unlock()

	return slices.Clone(a.entries)
}

type decisionAccumulatorKeyType int

const decisionAccumulatorKey decisionAccumulatorKeyType = iota

// NewDecisionAccumulatorContext seeds an empty decision accumulator into
// ctx. Allow* dispatch (dispatchCoarse, AllowProjectScopeCreate) appends to
// it ONLY when present — a context never seeded here (every non-middleware
// caller and every pre-existing test) takes the unchanged code path with no
// side effect. pkg/middleware/audit is the production caller: it seeds this
// before invoking the handler chain and reads it back via
// DecisionsFromContext once the handler returns.
func NewDecisionAccumulatorContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, decisionAccumulatorKey, &decisionAccumulator{})
}

// DecisionsFromContext returns a snapshot of the decisions accumulated so
// far, or nil if ctx carries no accumulator (NewDecisionAccumulatorContext
// was never called on it or an ancestor of it).
func DecisionsFromContext(ctx context.Context) []Decision {
	acc, ok := ctx.Value(decisionAccumulatorKey).(*decisionAccumulator)
	if !ok {
		return nil
	}

	return acc.snapshot()
}

// appendDecision records one Allow* outcome into ctx's accumulator, if
// present; a no-op otherwise. Called from dispatchCoarse and
// AllowProjectScopeCreate — the Allow* facade's dispatch choke points — so
// every scope check appends exactly once regardless of which of the three
// argument flavours (plain string, …ID, …Reader) the caller used.
func appendDecision(ctx context.Context, resource Resource, action openapi.AclOperation, err error) {
	acc, ok := ctx.Value(decisionAccumulatorKey).(*decisionAccumulator)
	if !ok {
		return
	}

	decision, reason := decisionOutcome(err)

	acc.append(Decision{
		ResourceKind: resource.Kind,
		ResourceID:   resource.ID,
		Action:       string(action),
		Decision:     decision,
		Reason:       reason,
	})
}

// RecordDecision records one authorization outcome into ctx's accumulator, if
// present; a no-op otherwise. It exists for the rare authorization paths that
// decide access WITHOUT going through an Allow* dispatch choke point
// (dispatchCoarse / AllowProjectScopeCreate) — notably a handler's self-access
// shortcut, which grants a service account access to itself with no ACL walk.
// Such a path must call this so the front-door audit still learns the resource
// kind and verdict it referenced (otherwise the audit record's resource type is
// empty). err is classified exactly as an Allow* return (nil == allow).
func RecordDecision(ctx context.Context, resource Resource, action openapi.AclOperation, err error) {
	appendDecision(ctx, resource, action, err)
}

// decisionOutcome classifies an Allow* facade return for the decision
// accumulator, reusing decision_log.go's reason vocabulary and sentinel
// taxonomy — but deliberately NOT decisionClass itself: decisionClass
// classifies CheckMany's PDP-served errors only, where an error matching
// none of the sentinels means the PDP/transport failed (its "unavailable"
// default). The Allow* facade's return spans a WIDER surface — notably
// today's default legacy ACL walk, and whatever shadow/remote-shadow mode
// always SERVES (both unconditionally return the legacy verdict) — whose
// plain errors.HTTPForbidden denial carries no wrapped sentinel at all
// (allowOrganizationScopeLegacy et al. never call .WithError). Reusing
// decisionClass verbatim here would misclassify that extremely common
// case — the system's own default operating mode — as "unavailable"
// instead of "deny". Here, an unrecognized non-nil error is instead an
// explicit denial (the ACL said no): only the specific fail-closed
// sentinels (ErrResolutionFailed, ErrDecisionUnavailable,
// ErrImpersonationNotSupported) classify as "unavailable" — no verdict was
// reached, so the request was failed closed rather than actually denied by
// a policy.
//
// Returns (decision, reason).
func decisionOutcome(err error) (string, string) {
	switch {
	case err == nil:
		return "allow", "policy"
	case goerrors.Is(err, ErrResolutionFailed):
		return "unavailable", "resolution"
	case goerrors.Is(err, ErrDecisionUnavailable):
		return "unavailable", "unavailable"
	case goerrors.Is(err, ErrImpersonationNotSupported):
		return "unavailable", "impersonation"
	default:
		// ErrPolicyDenied (an explicit Cerbos deny) and every legacy/plain
		// HTTPForbidden (no wrapped sentinel) both land here: a real
		// verdict was reached, and it was no.
		return "deny", "policy"
	}
}
