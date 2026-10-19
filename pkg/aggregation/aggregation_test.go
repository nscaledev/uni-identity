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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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

func TestNotGrantableNamesRole(t *testing.T) {
	t.Parallel()

	// administrator is stuck on its last scopes (its base role is missing),
	// then a service labels a new role.  administrator does not hold the new
	// role's scopes, so it cannot grant it, and Grantable says which one.
	last := unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("identity:groups", unikornv1.Read)}}

	roles := catalogue(
		newRole("administrator", aggregates(true, "administrator-base"), lastStatus(last)),
		newRole("fleet-operator", aggregateTo("administrator"), org(scope("radar:topology", unikornv1.Read))),
	)

	result := aggregation.Compute(t.Context(), roles)["administrator"]

	require.Equal(t, corev1.ConditionFalse, result.Grantable.Status)
	require.Equal(t, unikornv1.RoleReasonNotGrantable, result.Grantable.Reason)
	require.Contains(t, result.Grantable.Message, "fleet-operator")
}

func TestMissingRoleRefKeepsLastScopes(t *testing.T) {
	t.Parallel()

	last := unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("identity:groups", unikornv1.Read)}}

	roles := catalogue(
		newRole("administrator", aggregates(true, "administrator-base"), lastStatus(last)),
		newRole("fleet-operator", aggregateTo("administrator"), org(scope("radar:topology", unikornv1.Read))),
	)

	result := aggregation.Compute(t.Context(), roles)["administrator"]

	require.Equal(t, last, result.EffectiveScopes)
	require.Equal(t, corev1.ConditionFalse, result.Available.Status)
	require.Equal(t, unikornv1.RoleReasonMissingRoleRef, result.Available.Reason)
	require.Contains(t, result.Available.Message, "administrator-base")
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

	require.Equal(t, lastA, results["a"].EffectiveScopes)
	require.Equal(t, lastB, results["b"].EffectiveScopes)
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

func TestEmptySelectorRefused(t *testing.T) {
	t.Parallel()

	last := unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("svc:a", unikornv1.Read)}}

	admin := newRole("administrator", lastStatus(last))
	admin.Spec.AggregationRule = &unikornv1.RoleAggregationRule{RoleSelectors: []metav1.LabelSelector{{}}}

	roles := catalogue(admin, newRole("anything", org(scope("svc:b", unikornv1.Read))))

	result := aggregation.Compute(t.Context(), roles)["administrator"]

	require.Equal(t, corev1.ConditionFalse, result.Available.Status)
	require.Equal(t, last, result.EffectiveScopes)
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
