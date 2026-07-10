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
	"time"

	sdk "github.com/cerbos/cerbos-sdk-go/cerbos"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// This file is the A10 decision observability: one structured audit record
// and one counter increment per SERVED Cerbos-path decision, hooked at the
// CheckMany choke point (every consumer funnels through it — Check wraps it,
// cerbos-mode allowCoarse wraps Check, and A8's remote /authorization/check
// handler will land on it too, so remote decisions inherit these records for
// free).  Hooking the choke point rather than decorating the PDP client is
// deliberate: the pre-PDP fail-closed denials (no client, resolution
// failures, refused impersonated principal types) are decisions and must be
// recorded.
//
// The sink is the shared audit sink: the request-scoped logr logger
// (log.FromContext), which the server wires to zap JSON via SetupLogging.
// The core OTel middleware seeds that logger with the request's traceID and
// spanID, so every record is trace-correlated automatically — that IS the
// design's correlation id; no explicit field is needed.
//
// Levels mirror the core logging middleware's convention (4xx unconditional,
// V(1) otherwise): denies at Info unconditionally, allows at V(1).  This
// satisfies the design's "every decision" — allows are visible at raised
// verbosity — while keeping the default stream deny-focused.
//
// The field set is CLOSED and credential-free by construction: only the
// subject identifier and account type are read from the authorization info,
// NEVER tokens, passports or claims (the shadow comparator's discipline).
// Impersonated decisions extend it by exactly two fields — the impersonated
// subject and its principal type, read from the propagated principal.
//
// Shadow evaluations ride the same funnel through a marked shallow engine
// copy (shadow.go) and are excluded here: shadow has its own
// divergence/failure taxonomy for A12's cutover gate.  Only the PDP latency
// histogram is shared — transport health is path-independent.

// decisionMessage is the load-bearing message constant of the decision audit
// stream: dashboards and operators grep it, so renames are breaking changes
// (the unit tests duplicate it deliberately).
const decisionMessage = "authorization decision"

// newDecisionInstruments creates the two A10 decision instruments.
//
// Both export ONLY when the server is started with --otlp-endpoint (metrics
// are pushed over OTLP; no /metrics endpoint exists) — without it the
// recordings are silently dropped.
func newDecisionInstruments() (metric.Int64Counter, metric.Float64Histogram) {
	// The errors only report an invalid instrument configuration; the names,
	// descriptions, and units are static and the API returns usable no-op
	// instruments regardless, so there is nothing actionable to handle.
	decisions, _ := otel.Meter(constants.Application).Int64Counter(
		"unikorn_identity_authz_decisions_total",
		metric.WithDescription("Cerbos-path authorization decisions served, by decision and sentinel class."),
		metric.WithUnit("{decision}"),
	)

	// The repository's first histogram.  Explicit sub-second boundaries are
	// sized for localhost gRPC to the PDP sidecar; the top buckets exist to
	// make --cerbos-check-timeout expiries (deny-on-timeout) visible.
	pdpLatency, _ := otel.Meter(constants.Application).Float64Histogram(
		"unikorn_identity_authz_pdp_latency",
		metric.WithDescription("Cerbos PDP CheckResources round-trip latency, served and shadow evaluations alike."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2),
	)

	return decisions, pdpLatency
}

// decisionVerdict renders an allow/deny verdict for records and attributes.
func decisionVerdict(allowed bool) string {
	if allowed {
		return "allow"
	}

	return "deny"
}

// decisionClass names the decision's reason class, derived from the check.go
// error taxonomy via errors.Is — never from message strings.  The vocabulary
// is CLOSED (it doubles as a metric attribute): "policy" is a verdict from
// the policies (an allow, or an explicit deny — for a dual-check decision,
// EITHER side policy-denying), the rest are the fail-closed classes.
// "impersonation" is NARROWED with A14 to the type-gate refusal only (an
// impersonated principal type that cannot be impersonated); valid
// impersonations classify like any other decision.  An unclassified error is
// a failure to obtain a verdict, which is exactly what "unavailable" means
// (check.go's catch-all mapping).
func decisionClass(err error) string {
	switch {
	case err == nil, goerrors.Is(err, ErrPolicyDenied):
		return "policy"
	case goerrors.Is(err, ErrImpersonationNotSupported):
		return "impersonation"
	case goerrors.Is(err, ErrResolutionFailed):
		return "resolution"
	default:
		return "unavailable"
	}
}

// decisionSubject reads the ONLY two identity fields any decision or shadow
// record may carry — the subject identifier and the account type — from the
// authorization info.  A missing info yields empty fields, never an invented
// identity.  This closed, credential-free read is the whole surface: tokens,
// passports and claims are structurally unreachable from here.
func decisionSubject(ctx context.Context) (string, string) {
	var subject, actorType string

	if info, err := authorization.FromContext(ctx); err == nil && info.Userinfo != nil {
		subject = info.Userinfo.Sub

		if authz := info.Userinfo.HttpsunikornCloudOrgauthz; authz != nil {
			actorType = string(authz.Acctype)
		}
	}

	return subject, actorType
}

// resultPolicyCorrelate extracts the in-band policy version/scope the PDP
// echoes for one result entry.  Same A15 seam as shadowPolicyCorrelate
// (shadow.go): empty against today's PDP — identity's coarse checks request
// no version, and the PDP echoes the request — and upgraded in place to the
// policy-store hash when A15 builds that signal.
func resultPolicyCorrelate(response *sdk.CheckResourcesResponse, i int) (string, string) {
	if response == nil || i >= len(response.Results) {
		return "", ""
	}

	resource := response.Results[i].GetResource()

	return resource.GetPolicyVersion(), resource.GetScope()
}

// recordDecisions emits one audit record and one counter increment per
// (resource, action) entry of a served CheckMany evaluation — the flat,
// greppable batch shape (a batch-wide failure denies every entry, so every
// entry gets a deny record with the shared reason class).  An impersonated
// decision (A14) is still ONE record and ONE increment per entry — never one
// per dual-check side — with the AND-ed outcome; its record carries exactly
// two extra fields, the design's (impersonated-sub, actor) pair: the
// impersonated subject and its principal type, while "subject" stays the
// acting service (matching the legacy cache-key convention).  The latency
// field is the whole decision (resolution + PDP + mapping); the PDP-only
// round trips are the histogram's, recorded in check.go.  Counter attributes
// are the CLOSED (decision × class) vocabulary ONLY: subject or endpoint
// attributes would be an open-vocabulary cardinality explosion.
func (r *RBAC) recordDecisions(ctx context.Context, checks []CheckRequest, allowed []bool, response *sdk.CheckResourcesResponse, err error, elapsed time.Duration) {
	subject, actorType := decisionSubject(ctx)
	class := decisionClass(err)
	logger := log.FromContext(ctx)

	// The same detection predicate the decision path uses: type-gate
	// refusals are impersonated decisions too and carry the pair.
	var impersonatedFields []any

	if p := impersonationFromContext(ctx); p != nil {
		impersonatedFields = []any{
			"impersonated_subject", p.Actor,
			"impersonated_type", string(p.Type),
		}
	}

	for i, check := range checks {
		verdict := err == nil && allowed[i]

		// The correlate is only claimed for obtained verdicts: on a failure
		// the response is absent or untrusted (mapResults refused it).
		var version, scope string
		if err == nil {
			version, scope = resultPolicyCorrelate(response, i)
		}

		fields := []any{
			"subject", subject,
			"actor_type", actorType,
		}

		fields = append(fields, impersonatedFields...)

		fields = append(fields,
			"endpoint", check.Resource.Kind,
			"resource_id", check.Resource.ID,
			"operation", string(check.Action),
			"organization_id", check.Resource.OrganizationID,
			"project_id", check.Resource.ProjectID,
			"decision", decisionVerdict(verdict),
			"reason", class,
			"policy_version", version,
			"policy_scope", scope,
			"latency", elapsed,
		)

		if verdict {
			logger.V(1).Info(decisionMessage, fields...)
		} else {
			logger.Info(decisionMessage, fields...)
		}

		r.decisions.Add(ctx, 1, metric.WithAttributes(
			attribute.String("decision", decisionVerdict(verdict)),
			attribute.String("class", class),
		))
	}
}
