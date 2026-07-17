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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// These tests pin the F2 decision stash's contract (decision_stash.go): a
// context seeded with NewDecisionAccumulatorContext (production caller:
// pkg/middleware/audit) collects one Decision per Allow* dispatch,
// reflecting the SAME verdict Allow* itself returned, so the audit record
// can show a denied mutation's referenced resource even though the request
// failed. A context that never seeded one — every non-middleware caller,
// and every pre-existing rbac test — must be entirely unaffected: that is
// the "purely additive" contract decision_stash.go documents.

// TestDecisionAccumulatorRecordsAllowAndDeny proves the primary contract at
// the dispatchCoarse choke point: it is hit by AllowGlobalScope,
// AllowOrganizationScope and AllowProjectScope (and therefore their …ID/
// …Reader delegates), so one assertion per family is enough to prove the
// seam, not the delegation (already covered by the pre-existing dispatch
// tests in handler_test.go/remote_dispatch_test.go).
func TestDecisionAccumulatorRecordsAllowAndDeny(t *testing.T) {
	t.Parallel()

	t.Run("an allow appends an allow/policy decision with no resource id", func(t *testing.T) {
		t.Parallel()

		acl := globalACL("candy", openapi.Read)
		ctx := rbac.NewDecisionAccumulatorContext(rbac.NewContext(t.Context(), acl))

		require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))

		decisions := rbac.DecisionsFromContext(ctx)
		require.Equal(t, []rbac.Decision{
			{
				ResourceKind: "candy",
				ResourceID:   "",
				Action:       "read",
				Decision:     "allow",
				Reason:       "policy",
			},
		}, decisions)
	})

	t.Run("a deny appends a deny/policy decision", func(t *testing.T) {
		t.Parallel()

		acl := globalACL("candy", openapi.Read)
		ctx := rbac.NewDecisionAccumulatorContext(rbac.NewContext(t.Context(), acl))

		require.Error(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Create))

		decisions := rbac.DecisionsFromContext(ctx)
		require.Equal(t, []rbac.Decision{
			{
				ResourceKind: "candy",
				ResourceID:   "",
				Action:       "create",
				Decision:     "deny",
				Reason:       "policy",
			},
		}, decisions)
	})

	t.Run("AllowOrganizationScope appends through the same seam", func(t *testing.T) {
		t.Parallel()

		acl := &openapi.Acl{
			Organizations: &openapi.AclOrganizationList{
				{
					Id:        organizationID,
					Endpoints: &openapi.AclEndpoints{{Name: "candy", Operations: openapi.AclOperations{openapi.Read}}},
				},
			},
		}
		ctx := rbac.NewDecisionAccumulatorContext(rbac.NewContext(t.Context(), acl))

		require.NoError(t, rbac.AllowOrganizationScope(ctx, "candy", openapi.Read, organizationID))

		decisions := rbac.DecisionsFromContext(ctx)
		require.Len(t, decisions, 1)
		require.Equal(t, "candy", decisions[0].ResourceKind)
		require.Equal(t, "allow", decisions[0].Decision)
		require.Equal(t, "policy", decisions[0].Reason)
	})

	t.Run("AllowProjectScope appends through the same seam", func(t *testing.T) {
		t.Parallel()

		acl := aclFixture()
		ctx := rbac.NewDecisionAccumulatorContext(rbac.NewContext(t.Context(), acl))

		require.NoError(t, rbac.AllowProjectScope(ctx, resourceType2, openapi.Read, organizationID, projectID))

		decisions := rbac.DecisionsFromContext(ctx)
		require.Len(t, decisions, 1)
		require.Equal(t, resourceType2, decisions[0].ResourceKind)
		require.Equal(t, "allow", decisions[0].Decision)
	})

	t.Run("multiple dispatches append in order", func(t *testing.T) {
		t.Parallel()

		acl := globalACL("candy", openapi.Read)
		ctx := rbac.NewDecisionAccumulatorContext(rbac.NewContext(t.Context(), acl))

		require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))
		require.Error(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Delete))

		decisions := rbac.DecisionsFromContext(ctx)
		require.Len(t, decisions, 2)
		require.Equal(t, "read", decisions[0].Action)
		require.Equal(t, "allow", decisions[0].Decision)
		require.Equal(t, "delete", decisions[1].Action)
		require.Equal(t, "deny", decisions[1].Decision)
	})
}

// TestDecisionAccumulatorAbsentIsNoOp proves appendDecision's no-op
// contract: a context that never seeded an accumulator takes the unchanged
// code path. This is the "op with no accumulator (non-middleware path)
// still behaves" case: Allow*'s return value must be exactly as it was
// before F2, and there is nothing to read back.
func TestDecisionAccumulatorAbsentIsNoOp(t *testing.T) {
	t.Parallel()

	acl := globalACL("candy", openapi.Read)
	ctx := rbac.NewContext(t.Context(), acl)

	require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))
	require.Error(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Create))
	require.Nil(t, rbac.DecisionsFromContext(ctx), "a context that never seeded an accumulator must read back nothing")
}

// TestDecisionAccumulatorAllowProjectScopeCreate proves the second hook
// site: AllowProjectScopeCreate deliberately never calls dispatchCoarse
// (see its own NOTE in handler.go), so it carries its own appendDecision
// call rather than inheriting one.
func TestDecisionAccumulatorAllowProjectScopeCreate(t *testing.T) {
	t.Parallel()

	t.Run("allow", func(t *testing.T) {
		t.Parallel()

		acl := aclFixture()
		ctx := rbac.NewDecisionAccumulatorContext(rbac.NewContext(t.Context(), acl))

		// Granted directly at project scope (aclFixture), so the live
		// project-existence API call is never reached: client may be nil.
		require.NoError(t, rbac.AllowProjectScopeCreate(ctx, nil, resourceType2, openapi.Read, organizationID, projectID))

		decisions := rbac.DecisionsFromContext(ctx)
		require.Equal(t, []rbac.Decision{
			{
				ResourceKind: resourceType2,
				ResourceID:   "",
				Action:       "read",
				Decision:     "allow",
				Reason:       "policy",
			},
		}, decisions)
	})

	t.Run("deny", func(t *testing.T) {
		t.Parallel()

		acl := aclFixture()
		ctx := rbac.NewDecisionAccumulatorContext(rbac.NewContext(t.Context(), acl))

		// resourceType1 only grants Read (organization scope); Create fails
		// the organization-scope walk and returns before any client call.
		err := rbac.AllowProjectScopeCreate(ctx, nil, resourceType1, openapi.Create, organizationID, projectID)
		require.Error(t, err)

		decisions := rbac.DecisionsFromContext(ctx)
		require.Equal(t, []rbac.Decision{
			{
				ResourceKind: resourceType1,
				ResourceID:   "",
				Action:       "create",
				Decision:     "deny",
				Reason:       "policy",
			},
		}, decisions)
	})
}

// TestDecisionAccumulatorUnavailableClassification proves the F2 design
// choice documented on decisionOutcome (decision_stash.go): the KNOWN
// fail-closed sentinels classify "unavailable", distinct from an explicit
// policy "deny" — even though both are, to an Allow* caller, indistinguishable
// non-nil errors (decision_log.go's "deny-shape parity"). This is what the
// accumulator adds over the raw error: an audit reader can tell "the policy
// said no" apart from "no verdict was reached".
func TestDecisionAccumulatorUnavailableClassification(t *testing.T) {
	t.Parallel()

	acl := globalACL("candy", openapi.Read)

	tests := []struct {
		name         string
		sentinel     error
		wantDecision string
		wantReason   string
	}{
		{
			name:         "a resolution failure classifies unavailable/resolution",
			sentinel:     rbac.ErrResolutionFailed,
			wantDecision: "unavailable",
			wantReason:   "resolution",
		},
		{
			name:         "a decision-unavailable failure classifies unavailable/unavailable",
			sentinel:     rbac.ErrDecisionUnavailable,
			wantDecision: "unavailable",
			wantReason:   "unavailable",
		},
		{
			name:         "an impersonation type-gate refusal classifies unavailable/impersonation",
			sentinel:     rbac.ErrImpersonationNotSupported,
			wantDecision: "unavailable",
			wantReason:   "impersonation",
		},
		{
			name:         "an explicit policy deny classifies deny/policy, never unavailable",
			sentinel:     rbac.ErrPolicyDenied,
			wantDecision: "deny",
			wantReason:   "policy",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fake := &fakeRemoteEngine{err: rbac.CoarseForbidden(rbac.Resource{Kind: "candy"}, openapi.Read, test.sentinel)}
			ctx := rbac.NewDecisionAccumulatorContext(rbac.NewRemoteEngineContext(rbac.NewContext(t.Context(), acl), fake, rbac.RemoteEnforce))

			require.Error(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))

			decisions := rbac.DecisionsFromContext(ctx)
			require.Len(t, decisions, 1)
			require.Equal(t, test.wantDecision, decisions[0].Decision)
			require.Equal(t, test.wantReason, decisions[0].Reason)
		})
	}
}
