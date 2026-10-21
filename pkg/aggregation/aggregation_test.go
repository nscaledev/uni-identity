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
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
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

var adminID = unikornv1.ChartRoleID("administrator") //nolint:gochecknoglobals

// chartRole gives the role its chart ID, which an aggregating role needs to use its base role.
func chartRole(name string, opts ...roleOption) *unikornv1.Role {
	role := newRole(name, opts...)
	role.Name = unikornv1.ChartRoleID(name)

	return role
}

func baseID(name string) string {
	return unikornv1.ChartRoleID(name + unikornv1.BaseRoleSuffix)
}

func baseRole(name string, opts ...roleOption) *unikornv1.Role {
	role := newRole(baseID(name), append([]roleOption{protected()}, opts...)...)
	role.Labels[coreconstants.NameLabel] = name + unikornv1.BaseRoleSuffix

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

func labelledIDs(result *aggregation.Result) []string {
	out := make([]string, 0, len(result.Labelled))

	for _, l := range result.Labelled {
		out = append(out, l.ID)
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
		baseRole("administrator", org(scope("identity:groups", unikornv1.Create, unikornv1.Read))),
		chartRole("administrator", aggregates(true, baseID("administrator"))),
		newRole("fleet-operator", aggregateTo("administrator"), org(scope("radar:topology", unikornv1.Read))),
		newRole("unlabelled", org(scope("radar:secret", unikornv1.Read))),
	)

	result := aggregation.Compute(roles)[adminID]
	require.NotNil(t, result)

	require.Equal(t, []unikornv1.RoleScope{
		scope("identity:groups", unikornv1.Create, unikornv1.Read),
		scope("radar:topology", unikornv1.Read),
	}, result.EffectiveScopes.Organization)
	require.Empty(t, result.EffectiveScopes.Global)
	require.Empty(t, result.EffectiveScopes.Project)

	require.Equal(t, []string{baseID("administrator"), "fleet-operator"}, sourceIDs(result))
	require.Equal(t, "fleet-operator", result.AggregatedFrom[1].Name)
	require.Equal(t, "the fleet-operator role", result.AggregatedFrom[1].Description)
	require.Equal(t, aggregation.Hash(roles["fleet-operator"].Spec.Scopes), result.AggregatedFrom[1].ScopesHash)

	require.Equal(t, corev1.ConditionTrue, result.Available.Status)
	require.Equal(t, unikornv1.RoleReasonAggregated, result.Available.Reason)

	require.Equal(t, []string{"fleet-operator"}, labelledIDs(result))
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

	results := aggregation.Compute(roles)

	admin := results["administrator"].EffectiveScopes
	require.Equal(t, []unikornv1.RoleScope{
		scope("svc:things", unikornv1.Create, unikornv1.Delete, unikornv1.Read),
	}, admin.Organization)
	require.Empty(t, admin.Project)

	user := results["user"].EffectiveScopes
	require.Equal(t, []unikornv1.RoleScope{scope("svc:things", unikornv1.Read)}, user.Organization)
	require.Equal(t, []unikornv1.RoleScope{scope("svc:things", unikornv1.Create, unikornv1.Delete)}, user.Project)
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

	results := aggregation.Compute(roles)

	want := []unikornv1.RoleScope{scope("radar:topology", unikornv1.Read)}

	require.Equal(t, want, results["reader"].EffectiveScopes.Project)
	require.Equal(t, want, results["user"].EffectiveScopes.Project)
	require.Equal(t, want, results["auditor"].EffectiveScopes.Organization)
	require.Equal(t, want, results["administrator"].EffectiveScopes.Organization)

	for name, result := range results {
		require.Equalf(t, corev1.ConditionTrue, result.Available.Status, "%s: %s", name, result.Available.Message)
	}
}

func TestRemovingSourceShrinks(t *testing.T) {
	t.Parallel()

	admin := newRole("administrator", aggregates(true),
		lastStatus(unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("radar:topology", unikornv1.Read)}}))

	roles := catalogue(admin)

	result := aggregation.Compute(roles)["administrator"]

	require.Empty(t, result.EffectiveScopes.Organization)
	require.Empty(t, result.AggregatedFrom)
	require.Equal(t, corev1.ConditionTrue, result.Available.Status)

	aggregation.Resolve(roles)
	require.Empty(t, admin.EffectiveScopes().Organization)
}

func TestMissingRoleRefGivesNothing(t *testing.T) {
	t.Parallel()

	base := unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("identity:groups", unikornv1.Read)}}

	roles := catalogue(
		chartRole("administrator", aggregates(true, baseID("administrator")), lastStatus(base), recorded(baseID("administrator"), base)),
		newRole("fleet-operator", aggregateTo("administrator"), org(scope("radar:topology", unikornv1.Read))),
	)

	result := aggregation.Compute(roles)[adminID]

	require.Equal(t, []unikornv1.RoleScope{scope("radar:topology", unikornv1.Read)}, result.EffectiveScopes.Organization)
	require.Equal(t, []string{"fleet-operator"}, sourceIDs(result))
	require.Equal(t, corev1.ConditionFalse, result.Available.Status)
	require.Equal(t, unikornv1.RoleReasonMissingRoleRef, result.Available.Reason)
	require.Contains(t, result.Available.Message, baseID("administrator"))
}

func TestStuckRoleDropsRemovedScopes(t *testing.T) {
	t.Parallel()

	last := unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{
		scope("identity:groups", unikornv1.Read),
		scope("svc:danger", unikornv1.Delete),
		scope("svc:deleted", unikornv1.Read),
	}}

	roles := catalogue(
		chartRole("administrator", aggregates(true, baseID("administrator"), "typo"), lastStatus(last),
			recorded("fleet-operator", unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("svc:danger", unikornv1.Delete)}}),
			recorded("old-service", unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("svc:deleted", unikornv1.Read)}}),
		),
		baseRole("administrator", org(scope("identity:groups", unikornv1.Read))),
		newRole("fleet-operator", aggregateTo("administrator"), org(scope("svc:safe", unikornv1.Read))),
	)

	result := aggregation.Compute(roles)[adminID]

	require.Equal(t, unikornv1.RoleReasonMissingRoleRef, result.Available.Reason)
	require.Equal(t, []unikornv1.RoleScope{
		scope("identity:groups", unikornv1.Read),
		scope("svc:safe", unikornv1.Read),
	}, result.EffectiveScopes.Organization)
	require.Equal(t, []string{baseID("administrator"), "fleet-operator"}, sourceIDs(result))
}

func TestCycleUsesOnlyOutsideSources(t *testing.T) {
	t.Parallel()

	lastA := unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("svc:a", unikornv1.Read)}}
	lastB := unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("svc:b", unikornv1.Read)}}
	outside := []unikornv1.RoleScope{scope("svc:x", unikornv1.Read)}

	roles := catalogue(
		newRole("a", aggregates(false, "b", "x"), lastStatus(lastA)),
		newRole("b", aggregates(false, "a"), lastStatus(lastB)),
		newRole("x", org(outside...)),
		newRole("above", aggregates(false, "a")),
	)

	results := aggregation.Compute(roles)

	require.Equal(t, outside, results["a"].EffectiveScopes.Organization)
	require.Equal(t, outside, results["b"].EffectiveScopes.Organization)
	require.Equal(t, []string{"x"}, sourceIDs(results["b"]))
	require.Equal(t, unikornv1.RoleReasonCycle, results["a"].Available.Reason)
	require.Equal(t, unikornv1.RoleReasonCycle, results["b"].Available.Reason)

	require.Equal(t, corev1.ConditionTrue, results["above"].Available.Status)
	require.Equal(t, outside, results["above"].EffectiveScopes.Organization)
}

func TestSelfSelectionIgnored(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("administrator", aggregates(true), aggregateTo("administrator")),
	)

	result := aggregation.Compute(roles)["administrator"]

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

	result := aggregation.Compute(roles)["administrator"]

	require.Empty(t, result.EffectiveScopes.Organization)
	require.Empty(t, result.EffectiveScopes.Global)
	require.ElementsMatch(t, []string{"global-thing (has global scopes)", "platform-thing (protected)"}, result.Skipped)
	require.Contains(t, result.Available.Message, "skipped")
}

func TestGlobalScopesFromRefsDropped(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		baseRole("administrator", global(scope("svc:everything", unikornv1.Delete)), org(scope("svc:org", unikornv1.Read))),
		chartRole("administrator", aggregates(true, baseID("administrator"))),
	)

	result := aggregation.Compute(roles)[adminID]

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

	results := aggregation.Compute(roles)

	require.NotContains(t, results, "public-administrator")
	require.Equal(t, []unikornv1.RoleScope{scope("identity:groups", unikornv1.Read)}, publicAdmin.EffectiveScopes().Organization)
}

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

	result := aggregation.Compute(roles)["administrator"]

	require.Equal(t, corev1.ConditionFalse, result.Available.Status)
	require.Equal(t, unikornv1.RoleReasonInvalidSelector, result.Available.Reason)
	require.Empty(t, result.EffectiveScopes.Organization)
	require.Empty(t, result.AggregatedFrom)
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

func TestCycleThroughFinishedRole(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("a", refsOnly("b", "c")),
		newRole("b", refsOnly("a")),
		newRole("c", refsOnly("b")),
	)

	results := aggregation.Compute(roles)

	for _, id := range []string{"a", "b", "c"} {
		require.Equalf(t, unikornv1.RoleReasonCycle, results[id].Available.Reason, "%s should be in the cycle", id)
	}
}

func TestBadRefOnConversionFailsClosed(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("administrator", org(scope("identity:groups", unikornv1.Create)), refsOnly("typo")),
	)

	result := aggregation.Compute(roles)["administrator"]

	require.Equal(t, unikornv1.RoleReasonMissingRoleRef, result.Available.Reason)
	require.Empty(t, result.EffectiveScopes.Organization)

	aggregation.Resolve(roles)

	require.Empty(t, roles["administrator"].EffectiveScopes().Organization)
	require.False(t, roles["administrator"].AggregationReady())
}

func TestGlobalScopesInStatusAreNeverKept(t *testing.T) {
	t.Parallel()

	tampered := lastStatus(unikornv1.RoleScopes{Global: []unikornv1.RoleScope{scope("identity:organizations", unikornv1.Create)}})

	roles := catalogue(newRole("a", refsOnly("missing"), tampered))

	require.Empty(t, aggregation.Compute(roles)["a"].EffectiveScopes.Global)
	require.Empty(t, newRole("a", refsOnly("x"), tampered).EffectiveScopes().Global)

	aggregation.Resolve(roles)
	require.Empty(t, roles["a"].EffectiveScopes().Global)
}

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

	result := aggregation.Compute(roles)["agg"]

	require.Equal(t, unikornv1.RoleReasonInvalidSelector, result.Available.Reason)
	require.Empty(t, result.AggregatedFrom)
	require.Empty(t, result.EffectiveScopes.Organization)
}

func TestNonAggregateLabelSelectorRefused(t *testing.T) {
	t.Parallel()

	admin := newRole("administrator")
	admin.Spec.AggregationRule = &unikornv1.RoleAggregationRule{
		RoleSelectors: []metav1.LabelSelector{{MatchLabels: map[string]string{coreconstants.NameLabel: "fleet-operator"}}},
	}

	roles := catalogue(admin, newRole("fleet-operator", org(scope("radar:topology", unikornv1.Read))))

	require.Equal(t, unikornv1.RoleReasonInvalidSelector, aggregation.Compute(roles)["administrator"].Available.Reason)
}

func holderACL(t *testing.T, endpoints ...openapi.AclEndpoint) context.Context {
	t.Helper()

	organizations := openapi.AclOrganizationList{{Id: testOrganizationID, Endpoints: &endpoints}}

	return rbac.NewContext(t.Context(), &openapi.Acl{Organizations: &organizations})
}

func endpoint(name string, ops ...openapi.AclOperation) openapi.AclEndpoint {
	return openapi.AclEndpoint{Name: name, Operations: ops}
}

func availableStatus(scopes unikornv1.RoleScopes) roleOption {
	return func(r *unikornv1.Role) {
		r.Status.EffectiveScopes = &scopes
		r.Status.Conditions = []metav1.Condition{{
			Type:               string(unikornv1core.ConditionAvailable),
			Status:             metav1.ConditionTrue,
			Reason:             unikornv1.RoleReasonAggregated,
			ObservedGeneration: r.Generation,
		}}
	}
}

func TestUnresolvedAggregatingRoleIsNotGrantable(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		baseRole("administrator", org(scope("identity:groups", unikornv1.Read))),
		chartRole("administrator", refsOnly(baseID("administrator")), org(scope("identity:groups", unikornv1.Read)),
			availableStatus(unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("identity:groups", unikornv1.Read)}})),
	)

	admin := roles[adminID]
	organizationID := ids.MustParseOrganizationID(testOrganizationID)
	holder := holderACL(t, endpoint("identity:groups", openapi.Read))

	require.Empty(t, admin.EffectiveScopes().Organization)
	require.False(t, admin.AggregationReady())
	require.Error(t, rbac.AllowRole(holder, admin, organizationID))

	aggregation.Resolve(roles)

	require.Equal(t, []unikornv1.RoleScope{scope("identity:groups", unikornv1.Read)}, admin.EffectiveScopes().Organization)
	require.NoError(t, rbac.AllowRole(holder, admin, organizationID))
}

func TestStatusConditionsAreNotTrusted(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		baseRole("administrator", org(scope("identity:groups", unikornv1.Read))),
		newRole("stuck", refsOnly("typo"), availableStatus(unikornv1.RoleScopes{})),
		chartRole("working", refsOnly(baseID("working"))),
		baseRole("working", org(scope("identity:groups", unikornv1.Read))),
	)

	roles[unikornv1.ChartRoleID("working")].Status.Conditions = []metav1.Condition{{
		Type:   string(unikornv1core.ConditionAvailable),
		Status: metav1.ConditionFalse,
		Reason: unikornv1.RoleReasonMissingRoleRef,
	}}

	aggregation.Resolve(roles)

	require.False(t, roles["stuck"].AggregationReady())
	require.True(t, roles[unikornv1.ChartRoleID("working")].AggregationReady())
}

func TestStuckRoleIsNeverGrantable(t *testing.T) {
	t.Parallel()

	kept := unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("identity:groups", unikornv1.Read)}}

	roles := catalogue(
		baseRole("administrator", org(kept.Organization...)),
		chartRole("administrator", refsOnly(baseID("administrator"), "typo"), availableStatus(kept)),
	)

	aggregation.Resolve(roles)

	admin := roles[adminID]
	require.Equal(t, kept.Organization, admin.EffectiveScopes().Organization)
	require.False(t, admin.AggregationReady())

	everything := holderACL(t,
		endpoint("identity:groups", openapi.Create, openapi.Read, openapi.Update, openapi.Delete),
		endpoint("identity:organizations", openapi.Create, openapi.Read, openapi.Update, openapi.Delete),
	)

	require.Error(t, rbac.AllowRole(everything, admin, ids.MustParseOrganizationID(testOrganizationID)))
}

func TestLabelledGlobalRoleKeepsGlobalScopes(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("administrator", aggregates(true)),
		newRole("svc-global", aggregateTo("administrator"), global(scope("svc:everything", unikornv1.Read))),
	)

	result := aggregation.Compute(roles)["administrator"]

	require.Equal(t, corev1.ConditionTrue, result.Available.Status)
	require.Empty(t, result.EffectiveScopes.Global)
	require.Equal(t, []string{"svc-global"}, labelledIDs(result))
	require.Equal(t, []unikornv1.RoleScope{scope("svc:everything", unikornv1.Read)}, result.Labelled[0].Scopes.Global)
}

func TestDeletingSourceIsNotUsed(t *testing.T) {
	t.Parallel()

	deleting := newRole("fleet-operator", aggregateTo("administrator"), org(scope("radar:topology", unikornv1.Read)))
	now := metav1.Now()
	deleting.DeletionTimestamp = &now

	result := aggregation.Compute(catalogue(newRole("administrator", aggregates(true)), deleting))["administrator"]

	require.Empty(t, result.EffectiveScopes.Organization)
}

func TestResolveGivesConvertedRoleItsBase(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		baseRole("administrator", org(scope("identity:groups", unikornv1.Create)), global(scope("svc:everything", unikornv1.Read))),
		chartRole("administrator", aggregates(true, baseID("administrator"))),
	)

	aggregation.Resolve(roles)

	admin := roles[adminID]
	scopes := admin.EffectiveScopes()
	require.Equal(t, []unikornv1.RoleScope{scope("identity:groups", unikornv1.Create)}, scopes.Organization)
	require.Empty(t, scopes.Global)
	require.True(t, admin.AggregationReady())
	require.Nil(t, admin.Status.EffectiveScopes, "Resolve never writes status")
}

func TestComputeDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	run := func(other string) (unikornv1.RoleScopes, map[string]*unikornv1.Role) {
		roles := catalogue(
			newRole(other, refsOnly("m")),
			newRole("m", refsOnly(other, "pb")),
			newRole("pb", org(scope("svc:pb", unikornv1.Read))),
		)

		return aggregation.Compute(roles)["m"].EffectiveScopes, roles
	}

	before, roles := run("a")
	after, _ := run("z")

	for id, role := range roles {
		require.Nilf(t, role.Status.EffectiveScopes, "%s was written by Compute", id)
		require.Nilf(t, role.Computed, "%s was resolved by Compute", id)
	}

	require.Equal(t, before, after)
	require.Equal(t, []unikornv1.RoleScope{scope("svc:pb", unikornv1.Read)}, before.Organization)
}

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

		results := aggregation.Compute(roles)

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

		results := aggregation.Compute(roles)

		require.Equal(t, want, results["z"].EffectiveScopes.Organization)
		require.Equal(t, want, results["a"].EffectiveScopes.Organization)
		require.Nil(t, roles["z"].Status.EffectiveScopes)
	})
}

func TestSourceHashIgnoresGlobalScopes(t *testing.T) {
	t.Parallel()

	compute := func(global ...unikornv1.RoleScope) *aggregation.Result {
		roles := catalogue(
			baseRole("administrator", org(scope("identity:groups", unikornv1.Read)), func(r *unikornv1.Role) { r.Spec.Scopes.Global = global }),
			chartRole("administrator", aggregates(true, baseID("administrator"))),
		)

		return aggregation.Compute(roles)[adminID]
	}

	without := compute()
	with := compute(scope("identity:organizations", unikornv1.Create))

	require.Equal(t, without.EffectiveScopes, with.EffectiveScopes)
	require.Equal(t, without.AggregatedFrom, with.AggregatedFrom)
	require.Nil(t, with.AggregatedFrom[0].Scopes.Global)
}
