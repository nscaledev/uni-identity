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

package rbac_test

import (
	"context"
	"sync"
	"testing"

	sdk "github.com/cerbos/cerbos-sdk-go/cerbos"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	"github.com/stretchr/testify/require"

	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// These tests pin the A15 coarse-decision cache BEHAVIOUR at the allowCoarse
// choke point: hits skip the PDP, a republish (hash flip) is never masked by a
// stale allow, transient failures are never cached, an unavailable hash
// bypasses, and the shadow path is untouched.  They ride the same parity
// fixture + capturePDP call-counting fake the rest of the rbac suite uses.

// stubHasher is a settable PolicyStoreHasher: the tests flip hash to simulate
// a policy republish, or set ok=false to simulate an unavailable store.
type stubHasher struct {
	hash string
	ok   bool
}

func (h *stubHasher) Current(context.Context) (string, bool) {
	return h.hash, h.ok
}

// allowResponse is a canned PDP allow for one coarse check on kind/action, for
// the step-driven fakePDP (which does not synthesize verdicts from the batch).
func allowResponse(kind, action string) *sdk.CheckResourcesResponse {
	return pdpResponse(pdpResult(kind, cerbos.CoarseResourceID, map[string]effectv1.Effect{
		action: effectv1.Effect_EFFECT_ALLOW,
	}))
}

func TestDecisionCacheHitAvoidsPDP(t *testing.T) {
	t.Parallel()

	// Two identical coarse checks under the same policy hash: the first is a
	// miss that consults the PDP and caches the allow, the second is a hit.
	pdp := &capturePDP{allow: true}
	engine := newDispatchEngine(t, rbac.EngineCerbos, pdp).WithPolicyStoreHash(&stubHasher{hash: "H1", ok: true})

	ctx := rbac.NewEngineContext(aliceContext(t), engine)

	require.NoError(t, rbac.AllowOrganizationScope(ctx, "identity:groups", openapi.Create, parityOrgA))
	require.NoError(t, rbac.AllowOrganizationScope(ctx, "identity:groups", openapi.Create, parityOrgA))

	require.Equal(t, 1, pdp.calls, "the second identical check must be served from the cache, not the PDP")
}

func TestDecisionCacheNoStaleAllowPastRepublish(t *testing.T) {
	t.Parallel()

	// The headline correctness guarantee: a revoking republish must never be
	// masked by a cached allow.  An allow cached under hash H1 must NOT be
	// served once the store hash flips to H2 (a republish) and the policy now
	// denies — the flip makes the H1 entry unreachable, forcing a fresh PDP
	// consult that returns the deny.
	pdp := &capturePDP{allow: true}
	hasher := &stubHasher{hash: "H1", ok: true}
	engine := newDispatchEngine(t, rbac.EngineCerbos, pdp).WithPolicyStoreHash(hasher)

	ctx := rbac.NewEngineContext(aliceContext(t), engine)

	// Allowed under H1, cached.
	require.NoError(t, rbac.AllowOrganizationScope(ctx, "identity:groups", openapi.Create, parityOrgA))
	require.Equal(t, 1, pdp.calls)

	// Republish: the store hash flips and the policy now revokes the grant.
	hasher.hash = "H2"
	pdp.allow = false

	err := rbac.AllowOrganizationScope(ctx, "identity:groups", openapi.Create, parityOrgA)
	require.Error(t, err)
	require.True(t, coreerrors.IsForbidden(err))
	require.ErrorIs(t, err, rbac.ErrPolicyDenied)
	require.Equal(t, 2, pdp.calls, "the republish must force a fresh PDP consult, not serve the stale H1 allow")

	// The revoked verdict is now itself cached under H2: a repeat is served
	// from the cache (still a deny, same ErrPolicyDenied shape as a fresh
	// one), with no further PDP consult.
	repeat := rbac.AllowOrganizationScope(ctx, "identity:groups", openapi.Create, parityOrgA)
	require.True(t, coreerrors.IsForbidden(repeat))
	require.ErrorIs(t, repeat, rbac.ErrPolicyDenied)
	require.Equal(t, 2, pdp.calls, "a cached deny is served without another PDP consult")
}

func TestDecisionCacheNeverCachesFailures(t *testing.T) {
	t.Parallel()

	// A transient failure (ErrDecisionUnavailable) must never be cached: the
	// next call must retry the PDP rather than serve a poisoned deny.  The PDP
	// errors on the first call, then would allow.
	pdp := &fakePDP{steps: []fakePDPStep{
		{err: errFakeTransport},
		{response: allowResponse("identity:groups", "create")},
	}}
	engine := newDispatchEngine(t, rbac.EngineCerbos, pdp).WithPolicyStoreHash(&stubHasher{hash: "H1", ok: true})

	ctx := rbac.NewEngineContext(aliceContext(t), engine)

	err := rbac.AllowOrganizationScope(ctx, "identity:groups", openapi.Create, parityOrgA)
	require.Error(t, err)
	require.True(t, coreerrors.IsForbidden(err))
	require.ErrorIs(t, err, rbac.ErrDecisionUnavailable)
	require.Equal(t, 1, pdp.calls)

	// The failure was not cached, so the retry consults the PDP again — and
	// now succeeds.
	require.NoError(t, rbac.AllowOrganizationScope(ctx, "identity:groups", openapi.Create, parityOrgA))
	require.Equal(t, 2, pdp.calls, "a transient failure must not be cached")
}

func TestDecisionCacheBypassesWhenHashUnavailable(t *testing.T) {
	t.Parallel()

	// With no available store hash (fail-safe: no successful read yet), every
	// check bypasses the cache and consults the PDP.
	pdp := &capturePDP{allow: true}
	engine := newDispatchEngine(t, rbac.EngineCerbos, pdp).WithPolicyStoreHash(&stubHasher{ok: false})

	ctx := rbac.NewEngineContext(aliceContext(t), engine)

	require.NoError(t, rbac.AllowOrganizationScope(ctx, "identity:groups", openapi.Create, parityOrgA))
	require.NoError(t, rbac.AllowOrganizationScope(ctx, "identity:groups", openapi.Create, parityOrgA))

	require.Equal(t, 2, pdp.calls, "an unavailable hash must bypass the cache, so every check consults the PDP")
}

// concurrentAllowPDP is stateless (unlike capturePDP/fakePDP, which mutate
// call counters and slices), so it is safe to share across goroutines under
// -race.  It returns a fresh allow response per call.
type concurrentAllowPDP struct{}

func (concurrentAllowPDP) CheckResources(context.Context, *sdk.Principal, *sdk.ResourceBatch) (*sdk.CheckResourcesResponse, error) {
	return allowResponse("identity:groups", "create"), nil
}

func TestDecisionCacheConcurrentAccessIsRaceFree(t *testing.T) {
	t.Parallel()

	// A single engine — one shared cache and one shared hasher — hammered
	// concurrently.  The other cache tests use per-test instances, so -race
	// never exercises concurrent access to the shared LRU (Get/Add) and hasher
	// (Current) that production actually uses; this one does.
	engine := newDispatchEngine(t, rbac.EngineCerbos, concurrentAllowPDP{}).WithPolicyStoreHash(&stubHasher{hash: "H1", ok: true})
	ctx := rbac.NewEngineContext(aliceContext(t), engine)

	const goroutines = 64

	errs := make([]error, goroutines)

	var wg sync.WaitGroup

	for i := range errs {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			errs[i] = rbac.AllowOrganizationScope(ctx, "identity:groups", openapi.Create, parityOrgA)
		}(i)
	}

	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}
}

func TestDecisionCacheShadowPathUnaffected(t *testing.T) {
	t.Parallel()

	// Regression guard: the cache lives ONLY on the cerbos-mode allowCoarse
	// path.  A shadow-mode engine — even with a hasher attached — must still
	// evaluate the PDP on the shadow side for every dispatched check, so
	// caching cannot dampen the A7 divergence coverage.
	pdp := &capturePDP{allow: true}
	engine := newDispatchEngine(t, rbac.EngineShadow, pdp).WithPolicyStoreHash(&stubHasher{hash: "H1", ok: true})

	ctx := rbac.NewEngineContext(rbac.NewContext(aliceContext(t), globalACL("identity:organizations", openapi.Read)), engine)

	require.NoError(t, rbac.AllowGlobalScope(ctx, "identity:organizations", openapi.Read))
	require.NoError(t, rbac.AllowGlobalScope(ctx, "identity:organizations", openapi.Read))

	require.Equal(t, 2, pdp.calls, "shadow mode must evaluate the PDP every time; the cache never touches this path")
}
