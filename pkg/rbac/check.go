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
	"fmt"
	"time"

	sdk "github.com/cerbos/cerbos-sdk-go/cerbos"

	"github.com/unikorn-cloud/identity/pkg/authz/cerbos"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
)

// This file is the Cerbos decision API (migration task A5): resolve the
// subject's bindings, build one CheckResources request, and map the response
// to allow/deny.  Impersonated requests are served by the A14 dual check —
// two AND-ed single-principal evaluations, the impersonated principal and
// the acting service (decideImpersonated) — replacing the legacy
// confused-deputy ACL intersection.  The PolicyDecisionPoint seam is the PDP
// CLIENT boundary: only the local in-process Cerbos client satisfies it.  A8
// does NOT plug a "remote PDP" in here — its POST /authorization/check
// endpoint (pkg/handler) is a REMOTE ENTRY into THIS decision layer: a
// downstream service without a sidecar calls identity, whose handler runs
// CheckMany against the SAME local PDP client.  (A remote transport BELOW
// decide() would still need to read identity's authorization resources (the
// Group/Role/Project/Organization CRDs) to resolve bindings — Kubernetes
// access a downstream service does not have — which is exactly what the
// endpoint centralizes; see decision_engine.go for why the
// Allow*-facade remote-provider is a separate designed follow-up.)  Decision
// audit logging and metrics live in decision_log.go (A10), hooked at the
// CheckMany choke point below so every consumer — Check, allowCoarse, and
// A8's remote handler alike — is observed, pre-PDP fail-closed denials
// included.

// The decision error taxonomy.  All three failure classes are DENY-shaped —
// a caller treating any non-nil error as a deny is always fail-closed — but
// they stay distinct so a policy deny is distinguishable from an outage or a
// bad request via errors.Is.
var (
	// ErrPolicyDenied is an explicit deny from the PDP: the policies were
	// consulted and did not allow the action.
	ErrPolicyDenied = goerrors.New("operation denied by authorization policy")

	// ErrDecisionUnavailable is the fail-closed mapping for every failure to
	// obtain a verdict: no PDP client configured, transport errors, per-call
	// deadline expiry, and malformed responses.
	ErrDecisionUnavailable = goerrors.New("authorization decision unavailable")

	// ErrResolutionFailed is the fail-closed mapping for failures before the
	// PDP is asked: missing authorization info, bindings resolution errors
	// and request-construction errors.
	ErrResolutionFailed = goerrors.New("authorization binding resolution failed")

	// ErrImpersonationNotSupported is returned for an impersonated request
	// whose principal carries an invalid or unsupported TYPE: System,
	// unknown or empty (see impersonationTypeGate).  NARROWED with A14 —
	// valid User/Service impersonations are served by the dual check
	// (decideImpersonated) and no longer land here.  The sentinel (and its
	// "impersonation" decision-record/counter class) is retained under the
	// narrowed meaning: the class vocabulary is closed and renames are
	// breaking (see decision_log.go and pkg/rbac/README.md).
	ErrImpersonationNotSupported = goerrors.New("impersonated requests are not supported by the cerbos decision path")
)

// PolicyDecisionPoint is the PDP CLIENT surface the decision API consumes:
// the in-process client (pkg/authz/cerbos.Client) satisfies it.  This is NOT
// where A8's remote path lives — A8's /authorization/check is a remote ENTRY
// into this layer (its handler calls CheckMany, which uses this seam's local
// client), not an alternative implementation of this interface.
type PolicyDecisionPoint interface {
	CheckResources(ctx context.Context, principal *sdk.Principal, resources *sdk.ResourceBatch) (*sdk.CheckResourcesResponse, error)
}

// WithCerbos injects the PDP client used by Check and CheckMany, returning
// the receiver for chaining at construction.  An RBAC without one is legal —
// several consumers construct RBAC in contexts without a PDP — and its
// Check/CheckMany then fail closed with ErrDecisionUnavailable.
func (r *RBAC) WithCerbos(pdp PolicyDecisionPoint) *RBAC {
	r.pdp = pdp

	return r
}

// Resource identifies what a decision is about.  OrganizationID and
// ProjectID scope the check: both empty is a global check; organization only
// is an org-level check (the project attribute stays ABSENT on the wire —
// the no-flow-up invariant depends on that, see the request builder); both
// set is a project-level check.  An empty ID is a coarse check (the builder
// substitutes "*").
type Resource struct {
	// Kind is the endpoint name, e.g. "identity:groups", matched verbatim
	// against the generated resource policies.
	Kind string

	// ID optionally identifies a specific resource instance.
	ID string

	// OrganizationID optionally scopes the check to an organization.
	OrganizationID string

	// ProjectID optionally scopes the check to a project; requires
	// OrganizationID.
	ProjectID string
}

// CheckRequest pairs a resource with the operation to authorize on it.
type CheckRequest struct {
	Resource Resource
	Action   openapi.AclOperation
}

// Check returns nil if the authenticated subject may perform action on
// resource, and an error otherwise.  FAIL-CLOSED: any resolver, transport or
// PDP failure is a deny, distinguishable from a plain policy deny
// (ErrPolicyDenied) via errors.Is.
func (r *RBAC) Check(ctx context.Context, resource Resource, action openapi.AclOperation) error {
	allowed, err := r.CheckMany(ctx, []CheckRequest{{Resource: resource, Action: action}})
	if err != nil {
		return err
	}

	if !allowed[0] {
		return fmt.Errorf("%w: operation '%s' on endpoint '%s'", ErrPolicyDenied, action, resource.Kind)
	}

	return nil
}

// CheckMany evaluates several (resource, action) pairs in ONE CheckResources
// call PER PRINCIPAL — the design's one-call-per-request batching; direct
// requests make one call, impersonated requests two (one per side of the
// A14 dual check) — returning per-check verdicts in request order.  The
// error taxonomy matches Check, except plain policy denies are the false
// entries rather than an error.
func (r *RBAC) CheckMany(ctx context.Context, checks []CheckRequest) ([]bool, error) {
	start := time.Now()

	allowed, response, err := r.decide(ctx, checks)

	// Shadow evaluations ride this same funnel via a marked shallow engine
	// copy (shadow.go) but must not pollute the served-decision audit stream
	// or counter — shadow has its own divergence/failure taxonomy.  The PDP
	// latency histogram, recorded inside decide, IS shared deliberately:
	// transport health is path-independent.
	if !r.shadowEvaluation {
		r.recordDecisions(ctx, checks, allowed, response, err, time.Since(start))
	}

	return allowed, err
}

// decide is CheckMany's evaluation body, additionally returning the raw PDP
// response so the decision records can carry the in-band policy correlate.
// Direct requests are one single-principal evaluation; impersonated requests
// (the legacy detection predicate, type-gated) are the A14 dual check.
func (r *RBAC) decide(ctx context.Context, checks []CheckRequest) ([]bool, *sdk.CheckResourcesResponse, error) {
	impersonated := impersonationFromContext(ctx)

	if impersonated != nil {
		// The type gate is a pre-PDP fail-closed deny, like the resolution
		// failures below: refused before any client or info is consulted.
		if err := impersonationTypeGate(impersonated); err != nil {
			return nil, nil, err
		}
	}

	if r.pdp == nil {
		return nil, nil, fmt.Errorf("%w: no PDP client configured", ErrDecisionUnavailable)
	}

	info, err := authorization.FromContext(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrResolutionFailed, err)
	}

	if impersonated != nil {
		return r.decideImpersonated(ctx, info, impersonated, checks)
	}

	return r.evaluate(ctx, info, checks)
}

// evaluate is the single-principal evaluation: resolve the subject's
// bindings, build ONE CheckResources request covering every check, and map
// the response.  Direct requests run it once; impersonated requests run it
// once per side of the dual check.
func (r *RBAC) evaluate(ctx context.Context, info *authorization.Info, checks []CheckRequest) ([]bool, *sdk.CheckResourcesResponse, error) {
	bindings, err := r.ResolveBindings(ctx, info)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrResolutionFailed, err)
	}

	// The principal is keyed by the same subject string the resolver keyed
	// on.  An empty bindings slice is valid and deny-safe (see
	// BuildPrincipal): the request is still sent and every check denies.
	checkPrincipal, err := cerbos.BuildPrincipal(info.Userinfo.Sub, bindings)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrResolutionFailed, err)
	}

	entries := make([]cerbos.BatchEntry, len(checks))

	for i, check := range checks {
		resource, err := cerbos.BuildResource(check.Resource.Kind, check.Resource.ID, check.Resource.OrganizationID, check.Resource.ProjectID)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrResolutionFailed, err)
		}

		entries[i] = cerbos.BatchEntry{Resource: resource, Actions: []openapi.AclOperation{check.Action}}
	}

	batch, err := cerbos.BuildBatch(entries)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrResolutionFailed, err)
	}

	// The histogram is recorded tightly around the PDP round trip — no
	// resolution, no result mapping — success and failure alike: a call that
	// burned the whole --cerbos-check-timeout is exactly the signal this
	// instrument exists to surface.
	pdpStart := time.Now()

	response, err := r.pdp.CheckResources(ctx, checkPrincipal, batch)

	r.pdpLatency.Record(ctx, time.Since(pdpStart).Seconds())

	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrDecisionUnavailable, err)
	}

	allowed, err := mapResults(checks, entries, response)

	return allowed, response, err
}

// mapResults maps the PDP response onto the request order.  CheckResources
// results are positional — the engine evaluates inputs in order — and the
// per-entry kind/id echo is verified as a cheap guard against a shape
// mismatch.  Any inconsistency is a fail-closed unavailability, never a
// guessed verdict.
func mapResults(checks []CheckRequest, entries []cerbos.BatchEntry, response *sdk.CheckResourcesResponse) ([]bool, error) {
	if len(response.Results) != len(checks) {
		return nil, fmt.Errorf("%w: expected %d results, got %d", ErrDecisionUnavailable, len(checks), len(response.Results))
	}

	allowed := make([]bool, len(checks))

	for i, result := range response.Results {
		requested := entries[i].Resource.Obj

		if result.GetResource().GetKind() != requested.GetKind() || result.GetResource().GetId() != requested.GetId() {
			return nil, fmt.Errorf("%w: result %d is for %s/%s, expected %s/%s", ErrDecisionUnavailable,
				i, result.GetResource().GetKind(), result.GetResource().GetId(), requested.GetKind(), requested.GetId())
		}

		// The SDK's IsAllowed only returns true on an explicit EFFECT_ALLOW:
		// missing actions and errored results are false — deny by default.
		entry := &sdk.ResourceResult{CheckResourcesResponse_ResultEntry: result}
		allowed[i] = entry.IsAllowed(string(checks[i].Action))
	}

	return allowed, nil
}

// impersonationFromContext applies the impersonation-detection predicate —
// EXACTLY the legacy one (getSystemAccountACL): a principal in context, the
// impersonation marker, and a non-empty actor.  A missing principal, a
// missing marker, or a marker without an actor all mean "not impersonated",
// never a failure.  Returns nil for direct requests.
//
// Scope note: legacy consults this predicate only for System-account callers
// (GetACL's account-type dispatch), whereas the dual check applies to ANY
// marked request regardless of the acting account type.  For a hypothetical
// non-System caller carrying the marker this is strictly narrower than
// legacy (which would ignore the marker) — deny-safe, never escalation —
// but it is a theoretical shadow-divergence source for such traffic.
func impersonationFromContext(ctx context.Context) *principal.Principal {
	p, err := principal.FromContext(ctx)
	if err != nil || !principal.ImpersonateFromContext(ctx) || p.Actor == "" {
		return nil
	}

	return p
}

// impersonationTypeGate refuses impersonated principal types that cannot be
// impersonated.  PINNED: only User and Service pass; System and
// unknown/empty types are ErrImpersonationNotSupported — legacy parity,
// where processImpersonatedPrincipalACL (rbac.go) hard-errors with
// ErrInvalidPrincipalType for exactly those inputs.  This is deliberately
// NOT ResolveBindings' default-to-User arm: the actor string is
// caller-propagated, and silently resolving an unknown type as a user would
// answer for the wrong principal class.
func impersonationTypeGate(p *principal.Principal) error {
	switch p.Type {
	case openapi.User, openapi.Service:
		return nil
	case openapi.System:
		return fmt.Errorf("%w: invalid or unsupported impersonated principal type %q", ErrImpersonationNotSupported, p.Type)
	default:
		return fmt.Errorf("%w: invalid or unsupported impersonated principal type %q", ErrImpersonationNotSupported, p.Type)
	}
}

// impersonatedInfo synthesizes the authorization info the impersonated side
// of the dual check resolves bindings from, mirroring the legacy claims
// rebuild EXACTLY (getSystemAccountACL, rbac.go): Sub is the propagated
// actor, Acctype the propagated principal type, and OrgIds the principal's
// organizations with the defensive singular-OrganizationID fallback (a
// caller that only sets OrganizationID still resolves the scoped
// organization rather than an empty grant set).
//
// COUPLING: ResolveBindings reads ONLY Userinfo.Sub and the
// HttpsunikornCloudOrgauthz claims (Acctype, OrgIds) — see
// pkg/middleware/authorization/authinfo.go and bindings.go — so this
// synthesized Info is a complete resolution input.  The impersonated
// principal has no token of its own and none is fabricated.
func impersonatedInfo(p *principal.Principal) *authorization.Info {
	organizationIDs := p.OrganizationIDs
	if len(organizationIDs) == 0 && p.OrganizationID != "" {
		organizationIDs = []string{p.OrganizationID}
	}

	return &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: p.Actor,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: p.Type,
				OrgIds:  organizationIDs,
			},
		},
	}
}

// decideImpersonated serves an impersonated request as TWO AND-ed
// single-principal evaluations over the identical (resource, action) set:
// the impersonated principal and the acting service (A14, replacing the
// legacy confused-deputy intersection getSystemAccountACL performs).
//
// EQUIVALENCE (the proven A14 grounding): the legacy path answers from
// walk(intersectACL(P, S)) where S — a system-account ACL — is Global-only
// (processSystemAccountACL accumulates only Role.Spec.Scopes.Global) and
// intersectACL filters EVERY section of P against ONLY serviceACL.Global
// (rbac.go).  Every legacy Allow* walk is a monotone OR of per-section
// membership tests, so the filter distributes over the walk:
//
//	walk(intersectACL(P,S), endpoint, op, scope)
//	    == walk(P, endpoint, op, scope) AND (endpoint, op) ∈ S.Global
//
// and the service's OWN verdict at ANY scope equals (endpoint, op) ∈
// S.Global — global-first flow-down over a Global-only ACL.  Therefore the
// AND of two independent single-principal checks over the identical
// (resource, action) equals the legacy intersect verdict, given A5
// single-principal parity.  The service side inherits global→org→project
// flow-down structurally — a <roleID>#global binding activates on any
// resource regardless of its organization/project attributes — which the
// decision-parity matrix asserts rather than assumes.
//
// BOTH sides are always evaluated — no short-circuit — so the decision
// record and metrics always see the complete outcome; the per-entry verdict
// is impersonated-side AND service-side.  The two PDP round trips run
// sequentially, each under the client's own per-call timeout, and each
// records its own latency histogram sample; the decision counter still
// increments ONCE per decision (recordDecisions runs at the CheckMany choke
// point, above this).  A resolver or transport failure on EITHER side maps
// to the same fail-closed classes as a direct request, the impersonated
// side's taking precedence when both fail.
func (r *RBAC) decideImpersonated(ctx context.Context, info *authorization.Info, p *principal.Principal, checks []CheckRequest) ([]bool, *sdk.CheckResourcesResponse, error) {
	// The impersonated side evaluates FIRST, deliberately: shadow's
	// capturingPDP retains only the last response, and the service side's
	// is the one that must win (see shadow.go).
	impersonatedAllowed, _, impersonatedErr := r.evaluate(ctx, impersonatedInfo(p), checks)

	serviceAllowed, serviceResponse, serviceErr := r.evaluate(ctx, info, checks)

	if impersonatedErr != nil {
		return nil, nil, impersonatedErr
	}

	if serviceErr != nil {
		return nil, nil, serviceErr
	}

	allowed := make([]bool, len(checks))

	for i := range checks {
		allowed[i] = impersonatedAllowed[i] && serviceAllowed[i]
	}

	// The service-side response is the returned policy correlate,
	// consistent with the shadow capture; both correlates are empty against
	// today's PDP anyway (the A15 seam).
	return allowed, serviceResponse, nil
}
