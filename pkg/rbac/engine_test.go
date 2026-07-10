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
	"testing"

	sdk "github.com/cerbos/cerbos-sdk-go/cerbos"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// These tests pin the A6 dual-path dispatch seam: the Allow* facade serves
// the Cerbos decision if and only if a decision engine was seeded into the
// context AND its mode is cerbos (impersonated requests included since the
// A14 dual check).  Every other combination — crucially the total absence of
// an engine, which is every downstream service, NewSuperContext and every
// pre-existing test — takes the legacy ACL walk unchanged.  That
// absence-default is the compatibility contract.

// capturePDP is a canned PolicyDecisionPoint that records the batches it was
// asked to check and echoes a uniform allow/deny verdict for every action,
// so dispatch tests can assert the exact coarse request shapes.
type capturePDP struct {
	// err, when set, is returned verbatim (PDP unavailability).
	err error

	// allow is the verdict echoed for every requested action.
	allow bool

	calls   int
	batches []*sdk.ResourceBatch
}

func (f *capturePDP) CheckResources(_ context.Context, _ *sdk.Principal, batch *sdk.ResourceBatch) (*sdk.CheckResourcesResponse, error) {
	f.calls++
	f.batches = append(f.batches, batch)

	if f.err != nil {
		return nil, f.err
	}

	effect := effectv1.Effect_EFFECT_DENY
	if f.allow {
		effect = effectv1.Effect_EFFECT_ALLOW
	}

	results := make([]*responsev1.CheckResourcesResponse_ResultEntry, len(batch.Batch))

	for i, entry := range batch.Batch {
		actions := make(map[string]effectv1.Effect, len(entry.GetActions()))

		for _, action := range entry.GetActions() {
			actions[action] = effect
		}

		results[i] = pdpResult(entry.GetResource().GetKind(), entry.GetResource().GetId(), actions)
	}

	return pdpResponse(results...), nil
}

// batchEntry returns the single resource entry of the i-th captured batch,
// asserting the facade sent exactly one coarse check per Allow* call.
func batchEntry(t *testing.T, pdp *capturePDP, i int) *requestv1.CheckResourcesRequest_ResourceEntry {
	t.Helper()

	require.Greater(t, len(pdp.batches), i)
	require.Len(t, pdp.batches[i].Batch, 1)

	return pdp.batches[i].Batch[0]
}

// newDispatchEngine builds an RBAC over the parity fixture's dataset with the
// given engine mode and PDP.
func newDispatchEngine(t *testing.T, mode rbac.EngineMode, pdp rbac.PolicyDecisionPoint) *rbac.RBAC {
	t.Helper()

	fx := newParityFixture(t)

	options := &rbac.Options{
		AuthorizationEngine: mode,
	}

	return rbac.New(fx.client, parityNamespace, options).WithCerbos(pdp)
}

// globalACL grants exactly one operation on one endpoint at global scope, for
// observing which path (ACL walk or PDP) served a decision.
func globalACL(endpoint string, operation openapi.AclOperation) *openapi.Acl {
	return &openapi.Acl{
		Global: &openapi.AclEndpoints{
			{
				Name:       endpoint,
				Operations: openapi.AclOperations{operation},
			},
		},
	}
}

func TestEngineModeFlag(t *testing.T) {
	t.Parallel()

	t.Run("accepts the whitelisted values", func(t *testing.T) {
		t.Parallel()

		var mode rbac.EngineMode

		require.NoError(t, mode.Set("legacy"))
		require.Equal(t, rbac.EngineLegacy, mode)

		require.NoError(t, mode.Set("cerbos"))
		require.Equal(t, rbac.EngineCerbos, mode)
	})

	t.Run("rejects anything else naming the valid values", func(t *testing.T) {
		t.Parallel()

		mode := rbac.EngineLegacy

		err := mode.Set("bogus")
		require.Error(t, err)
		require.ErrorContains(t, err, "legacy")
		require.ErrorContains(t, err, "cerbos")
		require.Equal(t, rbac.EngineLegacy, mode, "a rejected value must not alter the mode")
	})

	t.Run("registers with a legacy default", func(t *testing.T) {
		t.Parallel()

		options := &rbac.Options{}
		flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
		options.AddFlags(flags)

		require.NoError(t, flags.Parse(nil))
		require.Equal(t, rbac.EngineLegacy, options.AuthorizationEngine)

		require.NoError(t, flags.Parse([]string{"--authorization-engine=cerbos"}))
		require.Equal(t, rbac.EngineCerbos, options.AuthorizationEngine)

		require.Error(t, flags.Parse([]string{"--authorization-engine=bogus"}))
	})
}

func TestAllowDispatchCerbosModeCoarseShapes(t *testing.T) {
	t.Parallel()

	pdp := &capturePDP{allow: true}
	engine := newDispatchEngine(t, rbac.EngineCerbos, pdp)

	ctx := rbac.NewEngineContext(aliceContext(t), engine)

	// Global scope: kind only — no organization, no project, coarse ID.
	require.NoError(t, rbac.AllowGlobalScope(ctx, "identity:organizations", openapi.Read))

	entry := batchEntry(t, pdp, 0)
	require.Equal(t, "identity:organizations", entry.GetResource().GetKind())
	require.Equal(t, cerbos.CoarseResourceID, entry.GetResource().GetId())
	require.Empty(t, entry.GetResource().GetAttr(), "a global check must carry no scope attributes")
	require.Equal(t, []string{"read"}, entry.GetActions())

	// Organization scope: the organization attribute only — the project
	// attribute must be ABSENT, not empty (the no-flow-up invariant).
	require.NoError(t, rbac.AllowOrganizationScope(ctx, "identity:groups", openapi.Create, parityOrgA))

	entry = batchEntry(t, pdp, 1)
	require.Equal(t, "identity:groups", entry.GetResource().GetKind())
	require.Equal(t, cerbos.CoarseResourceID, entry.GetResource().GetId())

	attrs := entry.GetResource().GetAttr()
	require.Len(t, attrs, 1)
	require.Equal(t, parityOrgA, attrs["organization"].GetStringValue())
	require.NotContains(t, attrs, "project", "an organization check must not set the project attribute")

	// Project scope: both attributes.
	require.NoError(t, rbac.AllowProjectScope(ctx, "compute:clusters", openapi.Delete, parityOrgA, parityProjectX))

	entry = batchEntry(t, pdp, 2)
	require.Equal(t, "compute:clusters", entry.GetResource().GetKind())
	require.Equal(t, cerbos.CoarseResourceID, entry.GetResource().GetId())

	attrs = entry.GetResource().GetAttr()
	require.Len(t, attrs, 2)
	require.Equal(t, parityOrgA, attrs["organization"].GetStringValue())
	require.Equal(t, parityProjectX, attrs["project"].GetStringValue())

	// The typed and reader variants dispatch through the same seam.
	require.NoError(t, rbac.AllowOrganizationScopeID(ctx, "identity:groups", openapi.Create, ids.MustParseOrganizationID(organizationID)))

	entry = batchEntry(t, pdp, 3)
	require.Equal(t, organizationID, entry.GetResource().GetAttr()["organization"].GetStringValue())

	require.Equal(t, 4, pdp.calls)
}

func TestAllowDispatchLegacyModeServesACL(t *testing.T) {
	t.Parallel()

	// The PDP would deny everything: proof the verdict came from the ACL.
	pdp := &capturePDP{}
	engine := newDispatchEngine(t, rbac.EngineLegacy, pdp)

	ctx := rbac.NewEngineContext(rbac.NewContext(aliceContext(t), globalACL("cookie", openapi.Read)), engine)

	require.NoError(t, rbac.AllowGlobalScope(ctx, "cookie", openapi.Read))

	err := rbac.AllowGlobalScope(ctx, "cookie", openapi.Delete)
	require.Error(t, err)
	require.True(t, coreerrors.IsForbidden(err))

	require.Zero(t, pdp.calls, "legacy mode must never consult the PDP")
}

func TestAllowDispatchAbsentEngineDefaultsToLegacy(t *testing.T) {
	t.Parallel()

	// A cerbos-mode engine EXISTS (the server configured one) but was never
	// seeded into this context — downstream services, NewSuperContext and
	// pre-existing tests all look like this.  The ACL walk must serve.
	pdp := &capturePDP{allow: true}
	newDispatchEngine(t, rbac.EngineCerbos, pdp)

	ctx := rbac.NewContext(aliceContext(t), globalACL("candy", openapi.Read))

	require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))
	require.Error(t, rbac.AllowGlobalScope(ctx, "wibble", openapi.Read))

	require.Zero(t, pdp.calls, "an un-seeded context must never consult the PDP")
}

func TestAllowDispatchDenyMapping(t *testing.T) {
	t.Parallel()

	// Every deny-shaped sentinel must surface as the same HTTPForbidden form
	// the legacy walk produces — call sites branch on err == nil and the
	// error mapper on the HTTP status — while staying errors.Is-transparent
	// for A7's comparator and A10's metrics.
	legacyDeny := rbac.AllowGlobalScope(rbac.NewContext(t.Context(), globalACL("candy", openapi.Read)), "candy", openapi.Delete)
	require.True(t, coreerrors.IsForbidden(legacyDeny))
	require.ErrorContains(t, legacyDeny, "operation is not allowed by rbac")

	t.Run("policy deny", func(t *testing.T) {
		t.Parallel()

		engine := newDispatchEngine(t, rbac.EngineCerbos, &capturePDP{})

		err := rbac.AllowGlobalScope(rbac.NewEngineContext(aliceContext(t), engine), "identity:organizations", openapi.Read)
		require.True(t, coreerrors.IsForbidden(err))
		require.ErrorContains(t, err, "operation is not allowed by rbac")
		require.ErrorIs(t, err, rbac.ErrPolicyDenied)
		require.NotErrorIs(t, err, rbac.ErrDecisionUnavailable)
	})

	t.Run("decision unavailable", func(t *testing.T) {
		t.Parallel()

		engine := newDispatchEngine(t, rbac.EngineCerbos, &capturePDP{err: errFakeTransport})

		err := rbac.AllowGlobalScope(rbac.NewEngineContext(aliceContext(t), engine), "identity:organizations", openapi.Read)
		require.True(t, coreerrors.IsForbidden(err))
		require.ErrorContains(t, err, "operation is not allowed by rbac")
		require.ErrorIs(t, err, rbac.ErrDecisionUnavailable)
	})

	t.Run("resolution failed", func(t *testing.T) {
		t.Parallel()

		engine := newDispatchEngine(t, rbac.EngineCerbos, &capturePDP{allow: true})

		// No authorization info in the context: bindings resolution fails
		// before the PDP is asked.
		err := rbac.AllowGlobalScope(rbac.NewEngineContext(t.Context(), engine), "identity:organizations", openapi.Read)
		require.True(t, coreerrors.IsForbidden(err))
		require.ErrorContains(t, err, "operation is not allowed by rbac")
		require.ErrorIs(t, err, rbac.ErrResolutionFailed)
	})
}

func TestAllowDispatchImpersonatedServesDualCheck(t *testing.T) {
	t.Parallel()

	// The seeded ACL grants only read, the PDP allows everything: an allowed
	// delete proves the AND-ed dual-check verdict served — not the legacy
	// intersection walk, which would deny it.
	pdp := &capturePDP{allow: true}
	engine := newDispatchEngine(t, rbac.EngineCerbos, pdp)

	// The exact legacy impersonation predicate: a principal in context, the
	// impersonation marker, and a non-empty actor.  Since A14 cerbos mode
	// serves impersonated traffic via the dual check: two PDP calls per
	// decision (the impersonated principal AND the acting service).
	ctx := rbac.NewEngineContext(rbac.NewContext(aliceContext(t), globalACL("candy", openapi.Read)), engine)
	ctx = principal.NewContext(ctx, &principal.Principal{Actor: "impersonated@example.com", Type: openapi.User})
	ctx = principal.NewImpersonateContext(ctx)

	require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))
	require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Delete))
	require.Equal(t, 4, pdp.calls, "an impersonated decision is two PDP calls, one per dual-check side")

	// Parity with the legacy detection: the marker without an actor is not
	// impersonation, so the Cerbos path serves it as a direct request with
	// a single PDP call.
	freshPDP := &capturePDP{allow: true}
	freshEngine := newDispatchEngine(t, rbac.EngineCerbos, freshPDP)

	ctx = rbac.NewEngineContext(aliceContext(t), freshEngine)
	ctx = principal.NewContext(ctx, &principal.Principal{Type: openapi.User})
	ctx = principal.NewImpersonateContext(ctx)

	require.NoError(t, rbac.AllowGlobalScope(ctx, "identity:organizations", openapi.Read))
	require.Equal(t, 1, freshPDP.calls)
}

func TestAllowProjectScopeCreateStaysLegacy(t *testing.T) {
	t.Parallel()

	// The PDP would deny everything; the ACL grants at global scope.  Create
	// must serve from the legacy walk END TO END — its nested scope checks
	// included — because its project-existence orchestration only moves to
	// Cerbos with A9.  A nil identity client proves the global-trust
	// shortcut is also untouched.
	pdp := &capturePDP{}
	engine := newDispatchEngine(t, rbac.EngineCerbos, pdp)

	ctx := rbac.NewEngineContext(rbac.NewContext(aliceContext(t), globalACL("candy", openapi.Create)), engine)

	require.NoError(t, rbac.AllowProjectScopeCreate(ctx, nil, "candy", openapi.Create, organizationID, projectID))
	require.Zero(t, pdp.calls, "AllowProjectScopeCreate must stay legacy-only until A9")
}

func TestAllowRoleStaysLegacy(t *testing.T) {
	t.Parallel()

	// The PDP would deny everything; the ACL grants the role's permissions
	// at organization scope.  AllowRole's grantability walk stays thin-Go
	// by design (A16 owns its parity), nested scope checks included.
	pdp := &capturePDP{}
	engine := newDispatchEngine(t, rbac.EngineCerbos, pdp)

	ctx := rbac.NewEngineContext(rbac.NewContext(aliceContext(t), aclFixture()), engine)

	role := &unikornv1.Role{
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Organization: []unikornv1.RoleScope{
					{Name: resourceType1, Operations: []unikornv1.Operation{unikornv1.Read}},
				},
			},
		},
	}

	require.NoError(t, rbac.AllowRole(ctx, role, ids.MustParseOrganizationID(organizationID)))
	require.Zero(t, pdp.calls, "AllowRole must stay legacy-only (A16 owns grantability parity)")
}
