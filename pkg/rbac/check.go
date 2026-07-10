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
// to allow/deny.  Only the local in-process PDP client path exists today; the
// PolicyDecisionPoint seam is where A8 slots the remote transport
// (/authorization/check) for services without a sidecar.  Decision audit
// logging and metrics live in decision_log.go (A10), hooked at the CheckMany
// choke point below so every consumer — Check, allowCoarse, and A8's remote
// handler alike — is observed, pre-PDP fail-closed denials included.

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

	// ErrImpersonationNotSupported is returned for any request carrying an
	// impersonation principal: the legacy confused-deputy intersection
	// (getSystemAccountACL) has no Cerbos equivalent until A14, so such
	// requests fail closed rather than being resolved as the WRONG subject
	// (the calling service instead of the impersonated principal).
	ErrImpersonationNotSupported = goerrors.New("impersonated requests are not supported by the cerbos decision path")
)

// PolicyDecisionPoint is the PDP surface the decision API consumes.  The
// in-process client (pkg/authz/cerbos.Client) satisfies it; A8's remote
// /authorization/check transport slots in behind the same seam.
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
// call — the design's one-call-per-request batching — returning per-check
// verdicts in request order.  The error taxonomy matches Check, except plain
// policy denies are the false entries rather than an error.
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
func (r *RBAC) decide(ctx context.Context, checks []CheckRequest) ([]bool, *sdk.CheckResourcesResponse, error) {
	if err := refuseImpersonation(ctx); err != nil {
		return nil, nil, err
	}

	if r.pdp == nil {
		return nil, nil, fmt.Errorf("%w: no PDP client configured", ErrDecisionUnavailable)
	}

	info, err := authorization.FromContext(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrResolutionFailed, err)
	}

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

// refuseImpersonation fails closed on impersonated requests: the legacy path
// intersects the impersonated principal's ACL with the service's own ACL
// (getSystemAccountACL's confused-deputy prevention) and the Cerbos
// equivalent — the dual check — arrives with A14.  Detection mirrors the
// legacy predicate exactly (a principal in context, the impersonation marker
// and a non-empty actor); silently resolving the calling service's own
// subject instead would answer for the WRONG identity.  Until A14 lands,
// A7's shadow comparator must exclude or annotate impersonated requests
// (see pkg/authz/cerbos/README.md).
func refuseImpersonation(ctx context.Context) error {
	p, err := principal.FromContext(ctx)
	if err != nil || !principal.ImpersonateFromContext(ctx) || p.Actor == "" {
		// A missing principal means "not impersonated", not a failure —
		// the exact legacy predicate.
		return nil //nolint:nilerr
	}

	return ErrImpersonationNotSupported
}
