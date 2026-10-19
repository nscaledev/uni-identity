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

package aggregation_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/aggregation"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const testOrganizationID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"

func scope(name string, ops ...unikornv1.Operation) unikornv1.RoleScope {
	return unikornv1.RoleScope{Name: name, Operations: ops}
}

type roleOption func(*unikornv1.Role)

func newRole(id string, opts ...roleOption) *unikornv1.Role {
	role := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:        id,
			Labels:      map[string]string{coreconstants.NameLabel: id},
			Annotations: map[string]string{coreconstants.DescriptionAnnotation: "the " + id + " role"},
		},
	}

	for _, o := range opts {
		o(role)
	}

	return role
}

func org(scopes ...unikornv1.RoleScope) roleOption {
	return func(r *unikornv1.Role) { r.Spec.Scopes.Organization = scopes }
}

func project(scopes ...unikornv1.RoleScope) roleOption {
	return func(r *unikornv1.Role) { r.Spec.Scopes.Project = scopes }
}

func global(scopes ...unikornv1.RoleScope) roleOption {
	return func(r *unikornv1.Role) { r.Spec.Scopes.Global = scopes }
}

func protected() roleOption {
	return func(r *unikornv1.Role) { r.Spec.Protected = true }
}

func aggregateTo(names ...string) roleOption {
	return func(r *unikornv1.Role) {
		for _, name := range names {
			r.Labels[unikornv1.AggregateToLabel(name)] = "true"
		}
	}
}

// aggregates makes the role select aggregate-to-<its own name> and ref refs.
func aggregates(flatten bool, refs ...string) roleOption {
	return func(r *unikornv1.Role) {
		r.Spec.AggregationRule = &unikornv1.RoleAggregationRule{
			RoleSelectors: []metav1.LabelSelector{
				{MatchLabels: map[string]string{unikornv1.AggregateToLabel(r.Name): "true"}},
			},
			RoleRefs:              refs,
			FlattenToOrganization: flatten,
		}
	}
}

func lastStatus(scopes unikornv1.RoleScopes) roleOption {
	return func(r *unikornv1.Role) { r.Status.EffectiveScopes = &scopes }
}

// recorded adds a source to the role's last status, as the controller
// records it.
func recorded(id string, scopes unikornv1.RoleScopes) roleOption {
	return func(r *unikornv1.Role) {
		r.Status.AggregatedFrom = append(r.Status.AggregatedFrom, unikornv1.RoleAggregationSource{
			ID:         id,
			ScopesHash: aggregation.Hash(scopes),
			Scopes:     &scopes,
		})
	}
}

func catalogue(roles ...*unikornv1.Role) map[string]*unikornv1.Role {
	out := map[string]*unikornv1.Role{}

	for _, r := range roles {
		out[r.Name] = r
	}

	return out
}

func sourceIDs(result *aggregation.Result) []string {
	out := make([]string, 0, len(result.AggregatedFrom))

	for _, s := range result.AggregatedFrom {
		out = append(out, s.ID)
	}

	return out
}

func TestBaseRefAndSelector(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("administrator-base", protected(), org(scope("identity:groups", unikornv1.Create, unikornv1.Read))),
		newRole("administrator", aggregates(true, "administrator-base")),
		newRole("fleet-operator", aggregateTo("administrator"), org(scope("radar:topology", unikornv1.Read))),
		newRole("unlabelled", org(scope("radar:secret", unikornv1.Read))),
	)

	result := aggregation.Compute(t.Context(), roles)["administrator"]
	require.NotNil(t, result)

	require.Equal(t, []unikornv1.RoleScope{
		scope("identity:groups", unikornv1.Create, unikornv1.Read),
		scope("radar:topology", unikornv1.Read),
	}, result.EffectiveScopes.Organization)
	require.Empty(t, result.EffectiveScopes.Global)
	require.Empty(t, result.EffectiveScopes.Project)

	require.Equal(t, []string{"administrator-base", "fleet-operator"}, sourceIDs(result))
	require.Equal(t, "fleet-operator", result.AggregatedFrom[1].Name)
	require.Equal(t, "the fleet-operator role", result.AggregatedFrom[1].Description)
	require.Equal(t, aggregation.Hash(roles["fleet-operator"].Spec.Scopes), result.AggregatedFrom[1].ScopesHash)

	require.Equal(t, corev1.ConditionTrue, result.Available.Status)
	require.Equal(t, unikornv1.RoleReasonAggregated, result.Available.Reason)
	require.Equal(t, corev1.ConditionTrue, result.Grantable.Status)
}

func TestFlattenToOrganization(t *testing.T) {
	t.Parallel()

	source := newRole("project-writer", aggregateTo("administrator", "user"),
		org(scope("svc:things", unikornv1.Read)),
		project(scope("svc:things", unikornv1.Create, unikornv1.Delete)),
	)

	roles := catalogue(
		source,
		newRole("administrator", aggregates(true)),
		newRole("user", aggregates(false)),
	)

	results := aggregation.Compute(t.Context(), roles)

	// Flattened: the mutating project scope lands at organization scope, so
	// it applies across the whole organization.
	admin := results["administrator"].EffectiveScopes
	require.Equal(t, []unikornv1.RoleScope{
		scope("svc:things", unikornv1.Create, unikornv1.Delete, unikornv1.Read),
	}, admin.Organization)
	require.Empty(t, admin.Project)

	// Not flattened: the project scope stays at project scope.
	user := results["user"].EffectiveScopes
	require.Equal(t, []unikornv1.RoleScope{scope("svc:things", unikornv1.Read)}, user.Organization)
	require.Equal(t, []unikornv1.RoleScope{scope("svc:things", unikornv1.Create, unikornv1.Delete)}, user.Project)

	require.Equal(t, corev1.ConditionTrue, results["administrator"].Grantable.Status)
	require.Equal(t, corev1.ConditionTrue, results["user"].Grantable.Status)
}

func TestChain(t *testing.T) {
	t.Parallel()

	// reader -> auditor and user; auditor and user -> administrator.
	roles := catalogue(
		newRole("reader", aggregates(false), aggregateTo("auditor", "user")),
		newRole("user", aggregates(false), aggregateTo("administrator")),
		newRole("auditor", aggregates(true), aggregateTo("administrator")),
		newRole("administrator", aggregates(true)),
		newRole("fleet-reader", aggregateTo("reader"), project(scope("radar:topology", unikornv1.Read))),
	)

	results := aggregation.Compute(t.Context(), roles)

	want := []unikornv1.RoleScope{scope("radar:topology", unikornv1.Read)}

	require.Equal(t, want, results["reader"].EffectiveScopes.Project)
	require.Equal(t, want, results["user"].EffectiveScopes.Project)
	require.Equal(t, want, results["auditor"].EffectiveScopes.Organization)
	require.Equal(t, want, results["administrator"].EffectiveScopes.Organization)

	for name, result := range results {
		require.Equalf(t, corev1.ConditionTrue, result.Available.Status, "%s: %s", name, result.Available.Message)
		require.Equalf(t, corev1.ConditionTrue, result.Grantable.Status, "%s: %s", name, result.Grantable.Message)
	}
}

func TestRemovingSourceShrinks(t *testing.T) {
	t.Parallel()

	admin := newRole("administrator", aggregates(true),
		lastStatus(unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("radar:topology", unikornv1.Read)}}))

	result := aggregation.Compute(t.Context(), catalogue(admin))["administrator"]

	require.Empty(t, result.EffectiveScopes.Organization)
	require.Empty(t, result.AggregatedFrom)
	require.Equal(t, corev1.ConditionTrue, result.Available.Status)
}

// TestMissingRoleRefKeepsRecordedScopes checks a missing roleRef keeps
// giving the scopes last recorded for it, while live sources give their
// current scopes, including one labelled since the role got stuck.
func TestMissingRoleRefKeepsRecordedScopes(t *testing.T) {
	t.Parallel()

	base := unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("identity:groups", unikornv1.Read)}}

	roles := catalogue(
		newRole("administrator", aggregates(true, "administrator-base"), lastStatus(base), recorded("administrator-base", base)),
		newRole("fleet-operator", aggregateTo("administrator"), org(scope("radar:topology", unikornv1.Read))),
	)

	result := aggregation.Compute(t.Context(), roles)["administrator"]

	require.Equal(t, []unikornv1.RoleScope{
		scope("identity:groups", unikornv1.Read),
		scope("radar:topology", unikornv1.Read),
	}, result.EffectiveScopes.Organization)
	require.Equal(t, []string{"administrator-base", "fleet-operator"}, sourceIDs(result))
	require.Equal(t, corev1.ConditionFalse, result.Available.Status)
	require.Equal(t, unikornv1.RoleReasonMissingRoleRef, result.Available.Reason)
	require.Contains(t, result.Available.Message, "administrator-base")
	require.Equal(t, corev1.ConditionTrue, result.Grantable.Status)
}

// TestStuckRoleDropsRemovedScopes checks a role stuck on a missing roleRef
// still loses a scope a selector source dropped, and every scope of a
// selector source that was deleted.
func TestStuckRoleDropsRemovedScopes(t *testing.T) {
	t.Parallel()

	last := unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{
		scope("identity:groups", unikornv1.Read),
		scope("svc:danger", unikornv1.Delete),
		scope("svc:deleted", unikornv1.Read),
	}}

	roles := catalogue(
		newRole("administrator", aggregates(true, "administrator-base", "typo"), lastStatus(last),
			recorded("fleet-operator", unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("svc:danger", unikornv1.Delete)}}),
			recorded("old-service", unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("svc:deleted", unikornv1.Read)}}),
		),
		newRole("administrator-base", protected(), org(scope("identity:groups", unikornv1.Read))),
		newRole("fleet-operator", aggregateTo("administrator"), org(scope("svc:safe", unikornv1.Read))),
	)

	result := aggregation.Compute(t.Context(), roles)["administrator"]

	require.Equal(t, unikornv1.RoleReasonMissingRoleRef, result.Available.Reason)
	require.Equal(t, []unikornv1.RoleScope{
		scope("identity:groups", unikornv1.Read),
		scope("svc:safe", unikornv1.Read),
	}, result.EffectiveScopes.Organization)
	require.Equal(t, []string{"administrator-base", "fleet-operator"}, sourceIDs(result))
}

func TestCycleKeepsLastScopes(t *testing.T) {
	t.Parallel()

	lastA := unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("svc:a", unikornv1.Read)}}
	lastB := unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("svc:b", unikornv1.Read)}}

	roles := catalogue(
		newRole("a", aggregates(false, "b"), lastStatus(lastA)),
		newRole("b", aggregates(false, "a"), lastStatus(lastB)),
		newRole("above", aggregates(false, "a")),
	)

	results := aggregation.Compute(t.Context(), roles)

	// Each role in the cycle takes the other's last scopes.
	require.Equal(t, lastB, results["a"].EffectiveScopes)
	require.Equal(t, lastA, results["b"].EffectiveScopes)
	require.Equal(t, unikornv1.RoleReasonCycle, results["a"].Available.Reason)
	require.Equal(t, unikornv1.RoleReasonCycle, results["b"].Available.Reason)

	// A role above the cycle is not in it, and takes the kept scopes.
	require.Equal(t, corev1.ConditionTrue, results["above"].Available.Status)
	require.Equal(t, lastA.Organization, results["above"].EffectiveScopes.Organization)
}

func TestSelfSelectionIgnored(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("administrator", aggregates(true), aggregateTo("administrator")),
	)

	result := aggregation.Compute(t.Context(), roles)["administrator"]

	require.Equal(t, corev1.ConditionTrue, result.Available.Status)
	require.Empty(t, result.AggregatedFrom)
}

func TestProtectedAndGlobalNeverSelected(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("administrator", aggregates(true)),
		newRole("platform-thing", protected(), aggregateTo("administrator"), org(scope("svc:secret", unikornv1.Read))),
		newRole("global-thing", aggregateTo("administrator"), global(scope("svc:everything", unikornv1.Delete))),
	)

	result := aggregation.Compute(t.Context(), roles)["administrator"]

	require.Empty(t, result.EffectiveScopes.Organization)
	require.Empty(t, result.EffectiveScopes.Global)
	require.ElementsMatch(t, []string{"global-thing (has global scopes)", "platform-thing (protected)"}, result.Skipped)
	require.Contains(t, result.Available.Message, "skipped")
}

func TestGlobalScopesFromRefsDropped(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("administrator-base", protected(), global(scope("svc:everything", unikornv1.Delete)), org(scope("svc:org", unikornv1.Read))),
		newRole("administrator", aggregates(true, "administrator-base")),
	)

	result := aggregation.Compute(t.Context(), roles)["administrator"]

	require.Empty(t, result.EffectiveScopes.Global)
	require.Equal(t, []unikornv1.RoleScope{scope("svc:org", unikornv1.Read)}, result.EffectiveScopes.Organization)
}

func TestLabelledRoleNeverChangesPublicAdministrator(t *testing.T) {
	t.Parallel()

	publicAdmin := newRole("public-administrator", org(scope("identity:groups", unikornv1.Read)))

	roles := catalogue(
		publicAdmin,
		newRole("fleet-operator", aggregateTo("public-administrator", "administrator"), org(scope("radar:topology", unikornv1.Read))),
		newRole("administrator", aggregates(true)),
	)

	results := aggregation.Compute(t.Context(), roles)

	require.NotContains(t, results, "public-administrator")
	require.Equal(t, []unikornv1.RoleScope{scope("identity:groups", unikornv1.Read)}, publicAdmin.EffectiveScopes().Organization)
}

// TestEmptySelectorRefused checks a refused selector uses the roles it last
// selected that still exist, with their current scopes, and nothing new.
func TestEmptySelectorRefused(t *testing.T) {
	t.Parallel()

	admin := newRole("administrator",
		lastStatus(unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("svc:a", unikornv1.Read), scope("svc:gone", unikornv1.Read)}}),
		recorded("fleet", unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("svc:a", unikornv1.Read)}}),
		recorded("gone", unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("svc:gone", unikornv1.Read)}}),
	)
	admin.Spec.AggregationRule = &unikornv1.RoleAggregationRule{RoleSelectors: []metav1.LabelSelector{{}}}

	roles := catalogue(
		admin,
		newRole("fleet", org(scope("svc:c", unikornv1.Read))),
		newRole("anything", org(scope("svc:b", unikornv1.Read))),
	)

	result := aggregation.Compute(t.Context(), roles)["administrator"]

	require.Equal(t, corev1.ConditionFalse, result.Available.Status)
	require.Equal(t, unikornv1.RoleReasonInvalidSelector, result.Available.Reason)
	require.Equal(t, []unikornv1.RoleScope{scope("svc:c", unikornv1.Read)}, result.EffectiveScopes.Organization)
	require.Equal(t, []string{"fleet"}, sourceIDs(result))
}

func TestHashIsOrderIndependent(t *testing.T) {
	t.Parallel()

	a := unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{
		scope("b", unikornv1.Read, unikornv1.Create),
		scope("a", unikornv1.Delete),
	}}
	b := unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{
		scope("a", unikornv1.Delete),
		scope("b", unikornv1.Create, unikornv1.Read),
	}}

	require.Equal(t, aggregation.Hash(a), aggregation.Hash(b))
	require.NotEqual(t, aggregation.Hash(a), aggregation.Hash(unikornv1.RoleScopes{}))
}

func TestEffectiveScopesFailsClosed(t *testing.T) {
	t.Parallel()

	role := newRole("administrator", aggregates(true), org(scope("svc:ignored", unikornv1.Read)))

	require.Empty(t, role.EffectiveScopes().Organization)
}

func refsOnly(refs ...string) roleOption {
	return func(r *unikornv1.Role) {
		r.Spec.AggregationRule = &unikornv1.RoleAggregationRule{RoleRefs: refs}
	}
}

// TestCycleThroughFinishedRole checks every role in a cycle is flagged, even
// when the cycle is reached through a role that was already computed:
// a -> c -> b -> a.
func TestCycleThroughFinishedRole(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("a", refsOnly("b", "c")),
		newRole("b", refsOnly("a")),
		newRole("c", refsOnly("b")),
	)

	results := aggregation.Compute(t.Context(), roles)

	for _, id := range []string{"a", "b", "c"} {
		require.Equalf(t, unikornv1.RoleReasonCycle, results[id].Available.Reason, "%s should be in the cycle", id)
	}
}

// TestBadRefOnConversionKeepsScopes checks that turning a role with
// hand-written scopes into an aggregating one with a bad ref does not empty
// it before the controller has ever written status.
func TestBadRefOnConversionKeepsScopes(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("administrator", org(scope("identity:groups", unikornv1.Create)), refsOnly("typo")),
	)

	result := aggregation.Compute(t.Context(), roles)["administrator"]

	require.Equal(t, unikornv1.RoleReasonMissingRoleRef, result.Available.Reason)
	require.Equal(t, []unikornv1.RoleScope{scope("identity:groups", unikornv1.Create)}, result.EffectiveScopes.Organization)
}

// TestGlobalScopesInStatusAreNeverKept checks global scopes someone wrote
// into status are dropped, both when the controller keeps the last scopes
// and when a reader asks for the effective scopes.
func TestGlobalScopesInStatusAreNeverKept(t *testing.T) {
	t.Parallel()

	tampered := lastStatus(unikornv1.RoleScopes{Global: []unikornv1.RoleScope{scope("identity:organizations", unikornv1.Create)}})

	roles := catalogue(newRole("a", refsOnly("missing"), tampered))

	require.Empty(t, aggregation.Compute(t.Context(), roles)["a"].EffectiveScopes.Global)
	require.Empty(t, newRole("a", refsOnly("x"), tampered).EffectiveScopes().Global)
}

// TestMatchExpressionSelectorRefused checks a selector that could match
// every role is refused, not only the empty selector.
func TestMatchExpressionSelectorRefused(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("agg"),
		newRole("x", org(scope("radar:secret", unikornv1.Delete))),
	)

	roles["agg"].Spec.AggregationRule = &unikornv1.RoleAggregationRule{
		RoleSelectors: []metav1.LabelSelector{{MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "nope", Operator: metav1.LabelSelectorOpDoesNotExist},
		}}},
	}

	result := aggregation.Compute(t.Context(), roles)["agg"]

	require.Equal(t, unikornv1.RoleReasonInvalidSelector, result.Available.Reason)
	require.Empty(t, result.AggregatedFrom)
	require.Empty(t, result.EffectiveScopes.Organization)
}

// TestNonAggregateLabelSelectorRefused checks a selector on any other label
// is refused.
func TestNonAggregateLabelSelectorRefused(t *testing.T) {
	t.Parallel()

	admin := newRole("administrator")
	admin.Spec.AggregationRule = &unikornv1.RoleAggregationRule{
		RoleSelectors: []metav1.LabelSelector{{MatchLabels: map[string]string{coreconstants.NameLabel: "fleet-operator"}}},
	}

	roles := catalogue(admin, newRole("fleet-operator", org(scope("radar:topology", unikornv1.Read))))

	require.Equal(t, unikornv1.RoleReasonInvalidSelector, aggregation.Compute(t.Context(), roles)["administrator"].Available.Reason)
}

// TestUnreconciledAggregatingRoleIsNotGrantable checks a caller with no
// scopes cannot grant an aggregating role the controller has not
// reconciled, which would otherwise pass because it holds nothing yet.
func TestUnreconciledAggregatingRoleIsNotGrantable(t *testing.T) {
	t.Parallel()

	organizations := openapi.AclOrganizationList{{Id: testOrganizationID}}
	ctx := rbac.NewContext(t.Context(), &openapi.Acl{Organizations: &organizations})

	err := rbac.AllowRole(ctx, newRole("administrator", refsOnly("administrator-base")), ids.MustParseOrganizationID(testOrganizationID))
	require.Error(t, err)
}

// TestStaleGenerationIsNotGrantable checks a role whose aggregationRule
// changed since the controller last wrote status cannot be granted until it
// catches up.
func TestStaleGenerationIsNotGrantable(t *testing.T) {
	t.Parallel()

	role := newRole("administrator", refsOnly("administrator-base"), lastStatus(unikornv1.RoleScopes{}))
	role.Generation = 2
	role.Status.Conditions = []metav1.Condition{{Type: "Available", Status: metav1.ConditionTrue, ObservedGeneration: 1}}

	require.False(t, role.AggregationReady())

	role.Status.Conditions[0].ObservedGeneration = 2

	require.True(t, role.AggregationReady())

	// A stuck role (Available=False) with empty kept scopes is not grantable.
	role.Status.Conditions[0].Status = metav1.ConditionFalse

	require.False(t, role.AggregationReady())
}

// TestStuckRoleWithKeptScopesIsGrantable checks a stuck role is grantable
// against its kept scopes, which are what its holders hold, so adding members
// to an admin group keeps working while it is stuck.
func TestStuckRoleWithKeptScopesIsGrantable(t *testing.T) {
	t.Parallel()

	kept := unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("identity:groups", unikornv1.Read)}}

	role := newRole("administrator", refsOnly("typo"), lastStatus(kept))
	role.Status.Conditions = []metav1.Condition{{Type: "Available", Status: metav1.ConditionFalse, Reason: unikornv1.RoleReasonMissingRoleRef}}

	require.True(t, role.AggregationReady())

	acl := func(endpoints ...openapi.AclEndpoint) *openapi.Acl {
		organizations := openapi.AclOrganizationList{{Id: testOrganizationID, Endpoints: &endpoints}}

		return &openapi.Acl{Organizations: &organizations}
	}

	organizationID := ids.MustParseOrganizationID(testOrganizationID)

	holder := rbac.NewContext(t.Context(), acl(openapi.AclEndpoint{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Read}}))
	require.NoError(t, rbac.AllowRole(holder, role, organizationID))

	nobody := rbac.NewContext(t.Context(), acl())
	require.Error(t, rbac.AllowRole(nobody, role, organizationID))

	// A status from an older generation is still not trusted.
	role.Generation = 2

	require.False(t, role.AggregationReady())
}

// TestLabelledGlobalRoleIsNotGrantable checks a role labelled for
// aggregation that has global scopes is skipped, and Grantable names it,
// because no org admin can ever grant it.
func TestLabelledGlobalRoleIsNotGrantable(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("administrator", aggregates(true)),
		newRole("svc-global", aggregateTo("administrator"), global(scope("svc:everything", unikornv1.Read))),
	)

	result := aggregation.Compute(t.Context(), roles)["administrator"]

	require.Equal(t, corev1.ConditionTrue, result.Available.Status)
	require.Equal(t, corev1.ConditionFalse, result.Grantable.Status)
	require.Contains(t, result.Grantable.Message, "svc-global")
}

// TestDeletingSourceIsNotUsed checks a source held by a finalizer while it is
// deleted stops counting at once.
func TestDeletingSourceIsNotUsed(t *testing.T) {
	t.Parallel()

	deleting := newRole("fleet-operator", aggregateTo("administrator"), org(scope("radar:topology", unikornv1.Read)))
	now := metav1.Now()
	deleting.DeletionTimestamp = &now

	result := aggregation.Compute(t.Context(), catalogue(newRole("administrator", aggregates(true)), deleting))["administrator"]

	require.Empty(t, result.EffectiveScopes.Organization)
}

// TestBootstrapRolesKeepsAdminsWorking checks that before the controller has
// run, the ACL build gives a converted role what its base role holds.
func TestBootstrapRolesKeepsAdminsWorking(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("administrator-base", protected(), org(scope("identity:groups", unikornv1.Create)), global(scope("svc:everything", unikornv1.Read))),
		newRole("administrator", aggregates(true, "administrator-base")),
	)

	unikornv1.BootstrapRoles(roles)

	scopes := roles["administrator"].EffectiveScopes()
	require.Equal(t, []unikornv1.RoleScope{scope("identity:groups", unikornv1.Create)}, scopes.Organization)
	require.Empty(t, scopes.Global)
}

// TestComputeDoesNotMutateInput checks Compute never writes to the roles it is
// given, and gives the same result whatever the role IDs sort as.
func TestComputeDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	run := func(other string) (unikornv1.RoleScopes, map[string]*unikornv1.Role) {
		roles := catalogue(
			newRole(other, refsOnly("m")),
			newRole("m", refsOnly(other, "pb")),
			newRole("pb", org(scope("svc:pb", unikornv1.Read))),
		)

		return aggregation.Compute(t.Context(), roles)["m"].EffectiveScopes, roles
	}

	before, roles := run("a")
	after, _ := run("z")

	for id, role := range roles {
		require.Nilf(t, role.Status.EffectiveScopes, "%s was written by Compute", id)
	}

	require.Equal(t, before, after)
	require.Equal(t, []unikornv1.RoleScope{scope("svc:pb", unikornv1.Read)}, before.Organization)
}

// TestStuckRoleRefsStuckRole checks a stuck role that refs another stuck role
// with no status gets what that role's live refs hold, not an empty value
// left behind by working out the first role's bootstrap scopes.
func TestStuckRoleRefsStuckRole(t *testing.T) {
	t.Parallel()

	want := []unikornv1.RoleScope{scope("identity:groups", unikornv1.Create)}

	t.Run("missing refs", func(t *testing.T) {
		t.Parallel()

		roles := catalogue(
			newRole("base", org(want...)),
			newRole("a", refsOnly("z", "typo-a")),
			newRole("z", refsOnly("base", "typo-z")),
		)

		results := aggregation.Compute(t.Context(), roles)

		require.Equal(t, want, results["z"].EffectiveScopes.Organization)
		require.Equal(t, want, results["a"].EffectiveScopes.Organization)
		require.Nil(t, roles["z"].Status.EffectiveScopes)
	})

	t.Run("cycle", func(t *testing.T) {
		t.Parallel()

		roles := catalogue(
			newRole("base", org(want...)),
			newRole("a", refsOnly("z")),
			newRole("z", refsOnly("a", "base")),
		)

		results := aggregation.Compute(t.Context(), roles)

		require.Equal(t, want, results["z"].EffectiveScopes.Organization)
		require.Equal(t, want, results["a"].EffectiveScopes.Organization)
		require.Nil(t, roles["z"].Status.EffectiveScopes)
	})
}

// TestSourceHashIgnoresGlobalScopes checks a source's hash covers only the
// scopes it contributed, so a change to its dropped global scopes is no
// change.
func TestSourceHashIgnoresGlobalScopes(t *testing.T) {
	t.Parallel()

	compute := func(global ...unikornv1.RoleScope) *aggregation.Result {
		roles := catalogue(
			newRole("administrator-base", protected(), org(scope("identity:groups", unikornv1.Read)), func(r *unikornv1.Role) { r.Spec.Scopes.Global = global }),
			newRole("administrator", aggregates(true, "administrator-base")),
		)

		return aggregation.Compute(t.Context(), roles)["administrator"]
	}

	without := compute()
	with := compute(scope("identity:organizations", unikornv1.Create))

	require.Equal(t, without.EffectiveScopes, with.EffectiveScopes)
	require.Equal(t, without.AggregatedFrom, with.AggregatedFrom)
	require.Nil(t, with.AggregatedFrom[0].Scopes.Global)
}
