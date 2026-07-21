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

	"github.com/stretchr/testify/require"

	authorizer "github.com/unikorn-cloud/identity/pkg/middleware/openapi/remote"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// These tests pin the Task 3 remote CoarseEngine adapter: RemoteEngine wraps
// this package's CheckMany decision call so a caller of rbac.CoarseEngine
// cannot tell whether the local *RBAC or this remote adapter served the
// verdict — same allow/deny/unavailable sentinel shape either way.  They
// reuse the checkHandler/newCheckAuthorizer/checkAuthContext fixtures from
// decision_test.go, which already stand up a real *Authorizer against a
// stubbed identity decision endpoint.

// TestRemoteEngineAllowCoarse pins the single-resource convenience: an allow
// verdict is a nil error, a policy deny is errors.Is(err, rbac.ErrPolicyDenied),
// and a decision-endpoint failure is errors.Is(err, rbac.ErrDecisionUnavailable)
// — rbac's OWN sentinels, even though the failure travels here as this
// package's ErrDecisionUnavailable (decision.go's CheckMany never touches
// pkg/rbac).
func TestRemoteEngineAllowCoarse(t *testing.T) {
	t.Parallel()

	resource := rbac.Resource{Kind: "identity:groups", OrganizationID: "org-1"}

	t.Run("allow", func(t *testing.T) {
		t.Parallel()

		h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}}}
		engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

		err := engine.AllowCoarse(checkAuthContext(t, "", false), resource, identityapi.Read)
		require.NoError(t, err)
	})

	t.Run("policy deny", func(t *testing.T) {
		t.Parallel()

		h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: false}}}
		engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

		err := engine.AllowCoarse(checkAuthContext(t, "", false), resource, identityapi.Read)
		require.ErrorIs(t, err, rbac.ErrPolicyDenied)
	})

	t.Run("decision unavailable", func(t *testing.T) {
		t.Parallel()

		h := &checkHandler{status: http.StatusInternalServerError}
		engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

		err := engine.AllowCoarse(checkAuthContext(t, "", false), resource, identityapi.Read)
		require.ErrorIs(t, err, rbac.ErrDecisionUnavailable)
	})
}

// TestRemoteEngineAllowCoarseManyImpersonation pins Fix B: AllowCoarseMany
// marks the outbound check as impersonated when — and only when — the
// AUTHENTICATED caller is a bearer principal (authorization.Info.SystemAccount
// == false), never off the propagated X-Principal's Type.  X-Principal carries
// the user as attribution on attributed service-to-service calls too, so
// keying off its Type would wrongly force intersect(user, caller) and deny
// service-privilege ops the caller holds but the user lacks.  A system-account
// (mTLS) caller stays attribution-only unless it already carries an inbound
// X-Impersonate, which must flow through unchanged (case c below) — this gate
// only ADDS marking for bearer callers, it never strips an existing one.
func TestRemoteEngineAllowCoarseManyImpersonation(t *testing.T) {
	t.Parallel()

	resource := rbac.Resource{Kind: "identity:groups", OrganizationID: "org-1"}

	t.Run("bearer caller is impersonated", func(t *testing.T) {
		t.Parallel()

		h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}}}
		engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

		ctx := checkSystemAccountAuthContext(t, false)

		_, err := engine.AllowCoarseMany(ctx, []rbac.Resource{resource}, identityapi.Read)
		require.NoError(t, err)

		require.Equal(t, "true", h.gotImpersonate, "a bearer caller (SystemAccount=false) must be impersonated on the outbound check")
	})

	t.Run("system-account caller is attribution-only", func(t *testing.T) {
		t.Parallel()

		h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}}}
		engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

		ctx := checkSystemAccountAuthContext(t, true)

		_, err := engine.AllowCoarseMany(ctx, []rbac.Resource{resource}, identityapi.Read)
		require.NoError(t, err)

		require.Empty(t, h.gotImpersonate, "a system-account caller (SystemAccount=true) must stay attribution-only, never forced into impersonation")
	})

	t.Run("system-account caller with inbound impersonate flows through", func(t *testing.T) {
		t.Parallel()

		h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}}}
		engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

		// An inbound X-Impersonate hop (e.g. a proxy already delegating)
		// arrives pre-marked; the gate must let it flow through rather than
		// stripping it just because the caller itself is a system account.
		ctx := principal.NewImpersonateContext(checkSystemAccountAuthContext(t, true))

		_, err := engine.AllowCoarseMany(ctx, []rbac.Resource{resource}, identityapi.Read)
		require.NoError(t, err)

		require.Equal(t, "true", h.gotImpersonate, "an inbound X-Impersonate must flow through unchanged, never stripped for a system-account caller")
	})
}

// TestRemoteEngineAllowCoarseManyBatchOrder pins the batch primitive: verdicts
// come back positionally matched to the request order (mirroring CheckMany's
// own result-order contract, already pinned by
// TestRemoteCheckManyResultsInOrder in decision_test.go).
func TestRemoteEngineAllowCoarseManyBatchOrder(t *testing.T) {
	t.Parallel()

	h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}, {Allowed: false}}}
	engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

	allowed, err := engine.AllowCoarseMany(checkAuthContext(t, "", false), []rbac.Resource{
		{Kind: "identity:groups", OrganizationID: "org-1"},
		{Kind: "identity:roles", OrganizationID: "org-1"},
	}, identityapi.Read)

	require.NoError(t, err)
	require.Equal(t, []bool{true, false}, allowed)
}

// TestRemoteEngineAllowCoarseManyChunksAtWireCap pins the batch chunking: a
// batch larger than the wire cap (maxChecksPerRequest — 50, mirroring
// server.spec.yaml's authorizationCheckList maxItems and the PDP's own
// maxResourcesPerRequest) is split across several CheckMany round trips instead
// of being sent as one over-cap request identity would reject wholesale. Every
// verdict comes back, in order, across the chunk boundaries.
func TestRemoteEngineAllowCoarseManyChunksAtWireCap(t *testing.T) {
	t.Parallel()

	// One check per request is denied by organization id, placed in the SECOND
	// chunk, so a correct split-and-concatenate is provable per index.
	h := &checkHandler{echoPerCheck: true, denyOrganizationID: "deny-me"}
	engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

	const (
		resources   = 120 // 50 + 50 + 20 at a wire cap of 50
		deniedIndex = 75  // in the second chunk (indices 50..99)
	)

	batch := make([]rbac.Resource, resources)
	for i := range batch {
		batch[i] = rbac.Resource{Kind: "identity:groups", OrganizationID: "org-1"}
	}

	batch[deniedIndex].OrganizationID = "deny-me"

	allowed, err := engine.AllowCoarseMany(checkAuthContext(t, "", false), batch, identityapi.Read)
	require.NoError(t, err)
	require.Len(t, allowed, resources, "every resource in an over-cap batch must get a verdict")
	require.Equal(t, []int{50, 50, 20}, h.batchSizes, "the batch must be split into wire-cap-sized chunks, not sent as one over-cap request")

	for i, a := range allowed {
		require.Equal(t, i != deniedIndex, a, "verdict for index %d must survive the chunk split in order", i)
	}
}
