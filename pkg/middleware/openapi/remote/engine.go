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
	"fmt"
	"time"

	"go.opentelemetry.io/otel/metric"

	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// RemoteEngine adapts this package's remote decision call (CheckMany, over
// identity's POST /authorization/check) onto rbac.CoarseEngine: the "remote
// transport ABOVE rbac.decide()" that pkg/middleware/openapi/README.md flags
// as a designed follow-up to A8 (see "The Decision-Engine Crossing"). A
// downstream service without a local PDP client gets the same coarse
// Allow*/list-filtering decisions identity's own *RBAC serves in-process.
//
// Error sentinels are translated at this boundary, not just forwarded:
// CheckMany fails closed with THIS package's ErrDecisionUnavailable (or a
// propagated 4xx), never pkg/rbac's, because decision.go does not import
// pkg/rbac. AllowCoarseMany re-wraps any CheckMany error with
// rbac.ErrDecisionUnavailable (preserving the original via %w) so a caller
// checking errors.Is against rbac's sentinels gets the identical answer
// regardless of whether the local or remote CoarseEngine served the
// decision — the whole point of the seam.
type RemoteEngine struct {
	authorizer *Authorizer

	// decisions and latency are Task 9's caller-side decision instruments
	// (see metrics.go): the consumer's own view of the CheckMany round trip,
	// distinct from identity's server-side A10 instruments.  Both are no-op
	// unless metrics are exported (--otlp-endpoint).
	decisions metric.Int64Counter
	latency   metric.Float64Histogram
}

var _ rbac.CoarseEngine = (*RemoteEngine)(nil)

// NewRemoteEngine wraps an Authorizer as a rbac.CoarseEngine.
func NewRemoteEngine(a *Authorizer) *RemoteEngine {
	decisions, latency := newRemoteDecisionInstruments()

	return &RemoteEngine{authorizer: a, decisions: decisions, latency: latency}
}

// RemoteDecisionEngine exposes this Authorizer as a rbac.CoarseEngine. The
// engine is built ONCE (in NewAuthorizer) and cached: it holds no per-request
// state — the acting principal rides the ctx — and rebuilding it per request
// would re-register its OTel instruments (newRemoteDecisionInstruments) on the
// hot path, since seedDecisionEngines calls this on every request.
func (a *Authorizer) RemoteDecisionEngine() rbac.CoarseEngine {
	return a.remoteEngine
}

// AllowCoarseMany is the batch primitive: it resolves per-resource verdicts for
// N resources in order, splitting the batch across as many CheckMany round
// trips as the wire cap requires (see checkManyChunked/maxChecksPerRequest) so
// a batch of any size resolves instead of failing wholesale above the cap.  A
// CheckMany failure is folded into rbac.ErrDecisionUnavailable (see the type
// doc) rather than forwarded as-is.
//
// This is the Task 9 caller-side telemetry choke point (see metrics.go): the
// CheckMany round trip is timed tightly (no request-slice construction, no
// error wrapping) for exactly ONE latency observation per call, whatever the
// batch size, and recordDecisions emits one log record and one counter
// increment per (resource, action) entry.  AllowCoarse below funnels through
// here, so it is instrumented for free without a second observation.
func (e *RemoteEngine) AllowCoarseMany(ctx context.Context, resources []rbac.Resource, action identityapi.AclOperation) ([]bool, error) {
	// Impersonate on the outbound check iff the AUTHENTICATED caller is a bearer
	// principal (authorization.Info.SystemAccount == false).  A system-account
	// (mTLS) caller is conveyed to identity by the cert-relay
	// (Unikorn-Client-Certificate) and resolved directly, so forcing
	// impersonation there would wrongly compute intersect(user, caller) and deny
	// service-privilege ops the caller holds but the propagated user lacks (e.g.
	// compute→region:servers).  A bearer caller cannot be conveyed by cert (the
	// check endpoint is mTLS-only and drops the bearer), so it is impersonated to
	// be resolved as the user.  An inbound X-Impersonate (a caller already
	// delegating) flows through unchanged — this only ADDS marking for bearer
	// callers, never strips.  Mirrors identity's own getSystemAccountACL branch.
	// Scoped to this call only: reached solely from Allow* dispatch, long AFTER
	// the middleware fetched the ACL via GetACL on the unmarked request context,
	// so GetACL — and thus the shadow legacy baseline — is untouched.
	if info, err := authorization.FromContext(ctx); err == nil && info != nil && !info.SystemAccount {
		ctx = principal.NewImpersonateContext(ctx)
	}

	checks := make([]CheckRequest, len(resources))
	for i, resource := range resources {
		checks[i] = CheckRequest{Resource: Resource(resource), Action: action}
	}

	start := time.Now()

	allowed, err := e.checkManyChunked(ctx, checks)

	elapsed := time.Since(start)

	e.latency.Record(ctx, elapsed.Seconds())
	e.recordDecisions(ctx, checks, allowed, err, elapsed)

	if err != nil {
		return nil, fmt.Errorf("%w: %w", rbac.ErrDecisionUnavailable, err)
	}

	return allowed, nil
}

// AllowCoarse is the single-resource convenience the Allow* facade uses; nil
// == allow, else rbac.CoarseForbidden's HTTPForbidden shape wrapping
// ErrPolicyDenied or ErrDecisionUnavailable — identical to the local
// CoarseEngine's error shape.
//
// It carries no Task 9 instrumentation of its own: delegating to
// AllowCoarseMany above means every AllowCoarse call is already exactly one
// latency observation and one counter increment — instrumenting here too
// would double-record a call that makes exactly one CheckMany round trip.
func (e *RemoteEngine) AllowCoarse(ctx context.Context, resource rbac.Resource, action identityapi.AclOperation) error {
	allowed, err := e.AllowCoarseMany(ctx, []rbac.Resource{resource}, action)
	if err != nil {
		return rbac.CoarseForbidden(resource, action, err)
	}

	if !allowed[0] {
		return rbac.CoarseForbidden(resource, action, fmt.Errorf("%w: operation '%s' on '%s'", rbac.ErrPolicyDenied, action, resource.Kind))
	}

	return nil
}

// maxChecksPerRequest bounds how many checks ride a single CheckMany round
// trip.  It mirrors identity's wire contract (server.spec.yaml
// authorizationCheckList maxItems) and the PDP's own maxResourcesPerRequest:
// a request exceeding it is rejected wholesale (a deterministic 400), so a
// batch larger than this MUST be split rather than sent as one over-cap
// request that can never succeed.  Keep this in sync with that maxItems.
const maxChecksPerRequest = 50

// checkManyChunked issues checks in wire-cap-sized batches (maxChecksPerRequest)
// and concatenates the per-resource verdicts in order, so a caller batch of any
// size resolves correctly instead of failing wholesale above the cap.
// Fail-closed: any chunk that fails to obtain a verdict fails the WHOLE batch
// (the error is returned and no partial verdicts leak out), and each chunk is
// independently guarded by the circuit breaker inside CheckMany.
func (e *RemoteEngine) checkManyChunked(ctx context.Context, checks []CheckRequest) ([]bool, error) {
	if len(checks) <= maxChecksPerRequest {
		return e.authorizer.CheckMany(ctx, checks)
	}

	allowed := make([]bool, 0, len(checks))

	for start := 0; start < len(checks); start += maxChecksPerRequest {
		end := min(start+maxChecksPerRequest, len(checks))

		chunk, err := e.authorizer.CheckMany(ctx, checks[start:end])
		if err != nil {
			return nil, err
		}

		allowed = append(allowed, chunk...)
	}

	return allowed, nil
}
