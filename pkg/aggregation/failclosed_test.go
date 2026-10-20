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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/aggregation"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// These tests check the computation never takes scopes from an aggregating
// role's status: whoever can write status can't change what a role holds,
// and a source that goes away stops giving at once.

// writeBack runs Compute and writes every result to status, as the
// controller does, then resolves the roles as the identity server does, so
// EffectiveScopes is what holders hold.
func writeBack(t *testing.T, roles map[string]*unikornv1.Role) {
	t.Helper()

	for id, r := range aggregation.Compute(roles) {
		scopes := r.EffectiveScopes
		roles[id].Status.EffectiveScopes = &scopes
		roles[id].Status.AggregatedFrom = r.AggregatedFrom

		meta.SetStatusCondition(&roles[id].Status.Conditions, metav1.Condition{
			Type:               string(unikornv1core.ConditionAvailable),
			Status:             metav1.ConditionStatus(r.Available.Status),
			Reason:             r.Available.Reason,
			ObservedGeneration: roles[id].Generation,
		})
	}

	aggregation.Resolve(roles)
}

func evilScopes() unikornv1.RoleScopes {
	return unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{
		scope("identity:organizations", unikornv1.Create, unikornv1.Delete, unikornv1.Read, unikornv1.Update),
	}}
}

// TestStatusTamperUnderMissingRefIsDropped checks scopes written into status
// under a missing roleRef are never held or recorded again.
func TestStatusTamperUnderMissingRefIsDropped(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("reader", aggregates(false, baseID("reader"), "typo"), recorded("typo", evilScopes())),
		baseRole("reader", org(scope("identity:groups", unikornv1.Read))),
	)

	for range 3 {
		writeBack(t, roles)
	}

	require.Equal(t, []unikornv1.RoleScope{scope("identity:groups", unikornv1.Read)}, roles["reader"].EffectiveScopes().Organization)
	require.Equal(t, []string{baseID("reader")}, sourceIDs(&aggregation.Result{AggregatedFrom: roles["reader"].Status.AggregatedFrom}))
}

// TestDeletedRefStopsGiving checks a deleted roleRef stops giving its scopes
// at the next compute.
func TestDeletedRefStopsGiving(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("admin", aggregates(false, "svc")),
		newRole("svc", org(scope("svc:danger", unikornv1.Delete))),
	)

	writeBack(t, roles)
	require.Contains(t, roles["admin"].EffectiveScopes().Organization, scope("svc:danger", unikornv1.Delete))

	delete(roles, "svc")

	for range 3 {
		writeBack(t, roles)
	}

	require.Empty(t, roles["admin"].EffectiveScopes().Organization)
	require.Empty(t, roles["admin"].Status.AggregatedFrom)
}

// TestCycleDoesNotSustainTamperedStatus checks a cycle neither keeps scopes
// someone wrote into a member's status nor a scope its outside source
// dropped, whether the whole graph or one role at a time is written.
func TestCycleDoesNotSustainTamperedStatus(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("a", aggregates(false, "b", "x")),
		newRole("b", aggregates(false, "a")),
		newRole("x", org(scope("svc:old", unikornv1.Delete))),
	)

	writeBack(t, roles)

	evil := evilScopes()
	roles["b"].Status.EffectiveScopes = &evil

	writeBack(t, roles)

	for _, id := range []string{"a", "b"} {
		require.NotContainsf(t, roles[id].EffectiveScopes().Organization, evil.Organization[0], "%s kept tampered scopes", id)
	}

	roles["x"].Spec.Scopes = unikornv1.RoleScopes{}
	roles["b"].Status.EffectiveScopes = &evil

	// One role per reconcile, as the controller does.
	for _, id := range []string{"a", "b"} {
		scopes := aggregation.Compute(roles)[id].EffectiveScopes
		roles[id].Status.EffectiveScopes = &scopes
	}

	aggregation.Resolve(roles)

	for _, id := range []string{"a", "b"} {
		require.Emptyf(t, roles[id].EffectiveScopes().Organization, "%s kept scopes", id)
		require.Emptyf(t, roles[id].Status.EffectiveScopes.Organization, "%s recorded scopes", id)
	}
}

// TestCycleDropsScopeAtOnce checks a scope an outside source drops is gone
// from every role in the cycle after one compute.
func TestCycleDropsScopeAtOnce(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("a", refsOnly("b", "c")),
		newRole("b", refsOnly("a")),
		newRole("c", org(scope("svc:keep", unikornv1.Read), scope("svc:drop", unikornv1.Delete))),
	)

	writeBack(t, roles)
	require.Contains(t, roles["b"].EffectiveScopes().Organization, scope("svc:drop", unikornv1.Delete))

	roles["c"].Spec.Scopes.Organization = []unikornv1.RoleScope{scope("svc:keep", unikornv1.Read)}

	results := aggregation.Compute(roles)

	for _, id := range []string{"a", "b"} {
		require.Equalf(t, []unikornv1.RoleScope{scope("svc:keep", unikornv1.Read)}, results[id].EffectiveScopes.Organization, "%s", id)
		require.Equalf(t, unikornv1.RoleReasonCycle, results[id].Available.Reason, "%s", id)
	}
}

// TestInvalidSelectorIgnoresStatus checks a refused selector does not use
// roles named in status, even live ones that never opted in.
func TestInvalidSelectorIgnoresStatus(t *testing.T) {
	t.Parallel()

	reader := newRole("reader", recorded("administrator", unikornv1.RoleScopes{}))
	reader.Spec.AggregationRule = &unikornv1.RoleAggregationRule{RoleSelectors: []metav1.LabelSelector{{}}}

	roles := catalogue(reader, newRole("administrator", func(r *unikornv1.Role) { r.Spec.Scopes = evilScopes() }))

	writeBack(t, roles)
	writeBack(t, roles)

	require.Empty(t, roles["reader"].EffectiveScopes().Organization)
	require.Empty(t, roles["reader"].Status.AggregatedFrom)
}

// TestProtectedRefOnlyForOwnBase checks an aggregating role may only use a
// protected role through roleRefs when it is its own base role, so another
// labelled aggregating role can't pass protected scopes on.
func TestProtectedRefOnlyForOwnBase(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("administrator", aggregates(false, baseID("administrator"))),
		baseRole("administrator", org(scope("identity:groups", unikornv1.Read))),
		newRole("sneaky", aggregates(false, "system-account"), aggregateTo("administrator")),
		newRole("system-account", protected(), org(scope("svc:internal", unikornv1.Delete))),
	)

	results := aggregation.Compute(roles)

	require.Equal(t, []unikornv1.RoleScope{scope("identity:groups", unikornv1.Read)}, results["administrator"].EffectiveScopes.Organization)
	require.Equal(t, corev1.ConditionTrue, results["administrator"].Available.Status)

	sneaky := results["sneaky"]
	require.Empty(t, sneaky.EffectiveScopes.Organization)
	require.Empty(t, sneaky.AggregatedFrom)
	require.Equal(t, unikornv1.RoleReasonInvalidRoleRef, sneaky.Available.Reason)
	require.Contains(t, sneaky.Available.Message, "system-account")

	// What holders hold follows the same rule.
	aggregation.Resolve(roles)

	require.Empty(t, roles["sneaky"].EffectiveScopes().Organization)
	require.False(t, roles["sneaky"].AggregationReady())
	require.Equal(t, []unikornv1.RoleScope{scope("identity:groups", unikornv1.Read)}, roles["administrator"].EffectiveScopes().Organization)
	require.True(t, roles["administrator"].AggregationReady())
}

// TestStuckRoleIgnoresSpecScopes checks an aggregating role's own
// spec.scopes are never held once the controller computes it, stuck or not.
func TestStuckRoleIgnoresSpecScopes(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("admin", aggregates(false, "base"), org(scope("svc:extra", unikornv1.Delete))),
		newRole("base", org(scope("svc:a", unikornv1.Read))),
	)

	writeBack(t, roles)
	require.Equal(t, []unikornv1.RoleScope{scope("svc:a", unikornv1.Read)}, roles["admin"].EffectiveScopes().Organization)

	roles["admin"].Spec.AggregationRule.RoleRefs = append(roles["admin"].Spec.AggregationRule.RoleRefs, "typo")

	writeBack(t, roles)
	require.Equal(t, []unikornv1.RoleScope{scope("svc:a", unikornv1.Read)}, roles["admin"].EffectiveScopes().Organization)
}

// TestInvalidSelectorMessageIsStable checks a selector with several bad
// labels gives the same message every time, naming them all in order.
func TestInvalidSelectorMessageIsStable(t *testing.T) {
	t.Parallel()

	admin := newRole("administrator")
	admin.Spec.AggregationRule = &unikornv1.RoleAggregationRule{RoleSelectors: []metav1.LabelSelector{{MatchLabels: map[string]string{
		"e": "5", "a": "1", unikornv1.AggregateToLabel("administrator"): "true", "c": "3", "b": "2", "d": "4",
	}}}}

	roles := catalogue(admin)

	first := aggregation.Compute(roles)["administrator"].Available.Message
	require.Contains(t, first, "a=1, b=2, c=3, d=4, e=5")

	for range 200 {
		require.Equal(t, first, aggregation.Compute(roles)["administrator"].Available.Message)
	}
}

// TestRefMatchedBySelectorIsNotSkipped checks a role used through roleRefs
// is not also reported as skipped when a selector matches it.
func TestRefMatchedBySelectorIsNotSkipped(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("administrator", aggregates(false, baseID("administrator"))),
		baseRole("administrator", aggregateTo("administrator"), org(scope("identity:groups", unikornv1.Read))),
	)

	result := aggregation.Compute(roles)["administrator"]

	require.Empty(t, result.Skipped)
	require.NotContains(t, result.Available.Message, "skipped")
	require.Equal(t, []string{baseID("administrator")}, sourceIDs(result))
}

// TestInvalidLabelKeyMessageIsStable checks aggregate-to-* selector keys that
// are not valid label keys are all named, in order, every time.  Selector
// parsing stops at the first bad key in map order, which is random.
func TestInvalidLabelKeyMessageIsStable(t *testing.T) {
	t.Parallel()

	long := unikornv1.AggregateToLabel(strings.Repeat("x", 64))

	admin := newRole("administrator")
	admin.Spec.AggregationRule = &unikornv1.RoleAggregationRule{RoleSelectors: []metav1.LabelSelector{{MatchLabels: map[string]string{
		unikornv1.AggregateToLabel("c d"): "true",
		long:                              "true",
		unikornv1.AggregateToLabel("a b"): "true",
	}}}}

	roles := catalogue(admin)

	first := aggregation.Compute(roles)["administrator"].Available
	require.Equal(t, unikornv1.RoleReasonInvalidSelector, first.Reason)
	require.Contains(t, first.Message, unikornv1.AggregateToLabel("a b")+"=true, "+unikornv1.AggregateToLabel("c d")+"=true, "+long+"=true")

	for range 200 {
		require.Equal(t, first.Message, aggregation.Compute(roles)["administrator"].Available.Message)
	}
}

// TestCycleMessageNamesOtherProblems checks a role in a cycle still reports
// its missing and refused roleRefs and its bad selector.
func TestCycleMessageNamesOtherProblems(t *testing.T) {
	t.Parallel()

	b := newRole("b", refsOnly("a"))
	b.Spec.AggregationRule.RoleSelectors = []metav1.LabelSelector{{}}

	roles := catalogue(
		newRole("a", refsOnly("b", "typo-2", "system-account", "typo-1")),
		b,
		newRole("system-account", protected(), org(scope("svc:internal", unikornv1.Delete))),
	)

	results := aggregation.Compute(roles)

	a := results["a"].Available
	require.Equal(t, unikornv1.RoleReasonCycle, a.Reason)
	require.Contains(t, a.Message, "missing roles, they give nothing: typo-1, typo-2")
	require.Contains(t, a.Message, "not a-base, they give nothing: system-account")

	require.Equal(t, unikornv1.RoleReasonCycle, results["b"].Available.Reason)
	require.Contains(t, results["b"].Available.Message, aggregation.ErrInvalidSelector.Error())
}

// TestSpoofedBaseRefGivesNothing checks a protected role that copies the
// base role's name label, but not its ID, gives nothing.
func TestSpoofedBaseRefGivesNothing(t *testing.T) {
	t.Parallel()

	spoof := newRole("system-account", protected(), org(scope("svc:internal", unikornv1.Delete)))
	spoof.Labels[coreconstants.NameLabel] = "administrator-base"

	roles := catalogue(newRole("administrator", aggregates(false, "system-account")), spoof)

	result := aggregation.Compute(roles)["administrator"]
	require.Empty(t, result.EffectiveScopes.Organization)
	require.Equal(t, unikornv1.RoleReasonInvalidRoleRef, result.Available.Reason)

	aggregation.Resolve(roles)
	require.Empty(t, roles["administrator"].EffectiveScopes().Organization)
	require.False(t, roles["administrator"].AggregationReady())
}
