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
	"slices"
	"strings"

	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// This file is the A6 dual-path dispatch seam: the Allow* facade can serve
// its decisions either from the legacy in-process ACL walk (handler.go) or
// from the Cerbos decision API (check.go), selected by an engine seeded into
// the request context.  The legacy path is retained verbatim — the A7 shadow
// comparator (shadow.go) runs it live alongside the Cerbos path — and it
// only goes at the A12 cutover.

// ErrInvalidEngineMode rejects engine mode values outside the whitelist.
var ErrInvalidEngineMode = goerrors.New("invalid authorization engine mode")

// EngineMode selects which engine serves Allow* decisions.  A12 adds
// per-kind authoritative flags on top.
type EngineMode string

const (
	// EngineLegacy serves decisions from the local ACL walk.  The default.
	EngineLegacy EngineMode = "legacy"

	// EngineShadow serves decisions from the local ACL walk while ALSO
	// evaluating the Cerbos path and logging verdict divergence (see
	// shadow.go).  The served verdict is always legacy's.
	EngineShadow EngineMode = "shadow"

	// EngineCerbos serves decisions from the Cerbos PDP via Check/CheckMany.
	EngineCerbos EngineMode = "cerbos"
)

var _ pflag.Value = (*EngineMode)(nil)

// Set implements pflag.Value with whitelist validation.
func (m *EngineMode) Set(value string) error {
	mode := EngineMode(value)

	if mode != EngineLegacy && mode != EngineShadow && mode != EngineCerbos {
		return fmt.Errorf("%w: %q (valid values: %s, %s, %s)", ErrInvalidEngineMode, value, EngineLegacy, EngineShadow, EngineCerbos)
	}

	*m = mode

	return nil
}

// String implements pflag.Value.
func (m *EngineMode) String() string {
	return string(*m)
}

// Type implements pflag.Value.
func (*EngineMode) Type() string {
	return "engineMode"
}

type engineKeyType int

const engineKey engineKeyType = iota

// NewEngineContext seeds the decision engine (and, through its options, the
// engine mode) for Allow* dispatch.  Contexts WITHOUT it — every downstream
// service (they never construct an RBAC, let alone a PDP), NewSuperContext,
// and every pre-existing test that seeds only an ACL — ALWAYS take the
// legacy path.  That absence-default is the compatibility contract of the
// migration: dispatch is a structural fail-safe, not a configuration one.
func NewEngineContext(ctx context.Context, engine *RBAC) context.Context {
	return context.WithValue(ctx, engineKey, engine)
}

// EngineFromContext returns the seeded decision engine, or nil when the
// context carries none (which means: legacy path, see NewEngineContext).
func EngineFromContext(ctx context.Context) *RBAC {
	engine, _ := ctx.Value(engineKey).(*RBAC)

	return engine
}

// mode returns the engine mode the RBAC was configured with, defaulting to
// legacy for a missing or unset option (downstream services never register
// the flag).
func (r *RBAC) mode() EngineMode {
	if r.options != nil && (r.options.AuthorizationEngine == EngineCerbos || r.options.AuthorizationEngine == EngineShadow) {
		return r.options.AuthorizationEngine
	}

	return EngineLegacy
}

// engineForDispatch returns the context's decision engine when — and only
// when — the Cerbos path must serve the decision: an engine was seeded and
// its mode is cerbos.  Impersonated requests are served too, via the A14
// dual check (decideImpersonated in check.go); an invalid impersonated
// principal TYPE fails closed inside the decision API
// (ErrImpersonationNotSupported), mirroring the legacy hard error rather
// than falling back to the legacy path.
func engineForDispatch(ctx context.Context) *RBAC {
	engine := EngineFromContext(ctx)

	if engine == nil || engine.mode() != EngineCerbos {
		return nil
	}

	return engine
}

// PolicyStoreHasher supplies the current policy-store fingerprint, the
// coarse-decision cache-key dimension that busts every entry on a policy
// republish.  The concrete provider (pkg/authz/cerbos.PolicyStoreHasher)
// read-throughs the controller-owned policies ConfigMap; this interface keeps
// the cache tests injectable without Kubernetes.  Current reports ok=false
// when no hash is available yet — the caller then bypasses the cache.
type PolicyStoreHasher interface {
	Current(ctx context.Context) (string, bool)
}

// WithPolicyStoreHash injects the policy-store hasher that keys the
// coarse-decision cache, returning the receiver for chaining at construction
// (mirrors WithCerbos).  Without one the cache is inert: decisionCacheKey
// reports bypass and every decision consults the PDP, so every construction
// that does not opt in — downstream services, tests — is unaffected.
func (r *RBAC) WithPolicyStoreHash(h PolicyStoreHasher) *RBAC {
	r.policyHasher = h

	return r
}

// allowCoarse serves one coarse Allow* decision, from the coarse-decision
// cache when possible and otherwise from the PDP.  It maps every deny-shaped
// sentinel (ErrPolicyDenied, ErrDecisionUnavailable, ErrResolutionFailed — all
// fail-closed) to the same HTTPForbidden form the legacy walk produces: call
// sites branch on err == nil and the error mapper on the HTTP status, so the
// shape is load-bearing.  The sentinel stays visible through errors.Is for
// A7's comparator and A10's metrics.
//
// It is reached ONLY in cerbos mode (engineForDispatch), so this is the single
// cache site: the shadow path (shadowCompare) and the remote batch path
// (A8's CheckMany handler) never call it and are never cached.  Only DEFINITE
// verdicts are cached (allow, or a policy deny); transient failures are never
// cached, so a PDP outage cannot poison a later retry.  Cache hits skip the A10
// decision log and the PDP-served counter (a hit is not a new PDP decision) but
// are counted in the coarse-cache hit/miss counter for cache observability.
func (r *RBAC) allowCoarse(ctx context.Context, resource Resource, operation openapi.AclOperation) error {
	// Fail-closed impersonation type gate FIRST, mirroring decide: an invalid
	// impersonated principal type must be refused BEFORE any cache lookup, so
	// a cached allow — keyed on the actor, not the principal type — can never
	// be served to a principal type that cannot be impersonated.
	if p := impersonationFromContext(ctx); p != nil {
		if err := impersonationTypeGate(p); err != nil {
			return coarseForbidden(resource, operation, err)
		}
	}

	key, ok := r.decisionCacheKey(ctx, resource, operation)

	if ok {
		if allowed, hit := r.decisionCache.Get(key); hit {
			r.recordCacheOutcome(ctx, true)

			if allowed {
				return nil
			}

			// A cached deny is reconstructed to the exact ErrPolicyDenied
			// shape a fresh deny carries (see Check), so a hit is
			// indistinguishable from a miss to callers.
			return coarseForbidden(resource, operation, fmt.Errorf("%w: operation '%s' on endpoint '%s'", ErrPolicyDenied, operation, resource.Kind))
		}
	}

	err := r.Check(ctx, resource, operation)

	if ok {
		// A miss: the cache was consulted but did not serve.  Record the
		// outcome, then cache ONLY definite verdicts.  A transient failure
		// (ErrDecisionUnavailable/ErrResolutionFailed) is never cached: the
		// next call must retry the PDP rather than serve a poisoned deny.
		r.recordCacheOutcome(ctx, false)

		switch {
		case err == nil:
			r.decisionCache.Add(key, true, r.decisionCacheTTL)
		case goerrors.Is(err, ErrPolicyDenied):
			r.decisionCache.Add(key, false, r.decisionCacheTTL)
		}
	}

	if err != nil {
		return coarseForbidden(resource, operation, err)
	}

	return nil
}

// coarseForbidden maps a coarse decision error to the HTTPForbidden form the
// legacy walk produces, preserving the wrapped sentinel for errors.Is.
func coarseForbidden(resource Resource, operation openapi.AclOperation, err error) error {
	return errors.HTTPForbidden(fmt.Sprintf("operation is not allowed by rbac: operation '%s' on endpoint '%s' is not permitted", operation, resource.Kind)).WithError(err)
}

// decisionCacheKey builds the coarse-decision cache key and reports whether the
// cache is usable for this request (ok=false ⇒ bypass).  It mirrors the ACL
// cache key (pkg/middleware/openapi aclCacheKey) in delimiter style but keys on
// the FULL coarse authorization scope plus the policy-store hash, so:
//
//   - a policy republish changes the hash, so no entry keyed on the previous
//     store can ever serve a stale verdict (the bust guarantee);
//   - an impersonated request carries the calling subject, the actor, the
//     actor's principal TYPE and organization set, and a distinct
//     "impersonated|" discriminator, so it can never collide with a direct
//     request, nor can two distinct impersonated principals that merely share
//     an actor string (over- or under-granting).
//
// The impersonation predicate is the SAME impersonationFromContext the decision
// path uses (not the raw principal helpers), so the key can never disagree with
// how decide will treat the request — a marker without an actor is direct on
// both sides.  Bypass (ok=false) whenever the store hash is unavailable (no
// hasher, or no successful read yet) or the subject cannot be read; the miss
// path then fails closed in Check anyway.  The resource ID is intentionally
// absent (coarse-only; allowCoarse never carries a specific instance).
func (r *RBAC) decisionCacheKey(ctx context.Context, resource Resource, operation openapi.AclOperation) (string, bool) {
	if r.policyHasher == nil {
		return "", false
	}

	hash, hok := r.policyHasher.Current(ctx)
	if !hok {
		return "", false
	}

	info, err := authorization.FromContext(ctx)
	if err != nil || info.Userinfo == nil {
		return "", false
	}

	scope := resource.Kind + "|" + resource.OrganizationID + "|" + resource.ProjectID
	action := string(operation)

	if p := impersonationFromContext(ctx); p != nil {
		// The impersonated verdict resolves the actor's bindings from its
		// principal TYPE and organization set (impersonatedInfo ->
		// ResolveBindings, check.go/bindings.go), both caller-asserted per
		// request: Type selects the resolution source (User subjects vs
		// Service-account IDs) and the org set scopes membership.  Both must
		// key the entry, or two distinct impersonated principals sharing an
		// actor string would collide on one cached verdict.  The org set is
		// sorted so a semantically identical set always yields one key.
		orgs := slices.Clone(p.OrganizationIDs)
		slices.Sort(orgs)

		return "impersonated|" + info.Userinfo.Sub + "|" + p.Actor + "|" + string(p.Type) + "|" + strings.Join(orgs, ",") + "|" + scope + "|" + action + "|" + hash, true
	}

	return "direct|" + info.Userinfo.Sub + "|" + scope + "|" + action + "|" + hash, true
}
