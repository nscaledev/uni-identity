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

//nolint:testpackage // The test drives the unexported reconciler and watch mapping directly.
package role

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const namespace = "unikorn-identity"

func newRole(id string, labels map[string]string, spec unikornv1.RoleSpec) *unikornv1.Role {
	all := map[string]string{coreconstants.NameLabel: id}

	for k, v := range labels {
		all[k] = v
	}

	return &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: id, Labels: all},
		Spec:       spec,
	}
}

var adminID = unikornv1.ChartRoleID("administrator") //nolint:gochecknoglobals

func adminRole() *unikornv1.Role {
	admin := newRole(adminID, nil, unikornv1.RoleSpec{
		AggregationRule: &unikornv1.RoleAggregationRule{
			RoleSelectors: []metav1.LabelSelector{
				{MatchLabels: map[string]string{unikornv1.AggregateToLabel("administrator"): "true"}},
			},
			FlattenToOrganization: true,
		},
	})
	admin.Labels[coreconstants.NameLabel] = "administrator"

	return admin
}

var adminBaseID = unikornv1.ChartRoleID("administrator-base") //nolint:gochecknoglobals

func adminBase() *unikornv1.Role {
	base := newRole(adminBaseID, nil, unikornv1.RoleSpec{
		Protected: true,
		Scopes: unikornv1.RoleScopes{
			Organization: []unikornv1.RoleScope{{Name: "identity:groups", Operations: []unikornv1.Operation{unikornv1.Read}}},
		},
	})
	base.Labels[coreconstants.NameLabel] = "administrator-base"

	return base
}

func fleetOperator() *unikornv1.Role {
	return newRole("fleet-operator", map[string]string{unikornv1.AggregateToLabel("administrator"): "true"}, unikornv1.RoleSpec{
		Scopes: unikornv1.RoleScopes{
			Organization: []unikornv1.RoleScope{{Name: "radar:topology", Operations: []unikornv1.Operation{unikornv1.Read}}},
		},
	})
}

func setup(t *testing.T, objects ...client.Object) (*Reconciler, client.Client, *events.FakeRecorder) {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	cli := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&unikornv1.Role{}).
		WithObjects(objects...).
		Build()

	recorder := events.NewFakeRecorder(100)

	return &Reconciler{client: cli, recorder: recorder}, cli, recorder
}

func reconcileRole(t *testing.T, r *Reconciler, name string) {
	t.Helper()

	result, err := r.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}})
	require.NoError(t, err)
	require.Zero(t, result.RequeueAfter)
}

func getRole(t *testing.T, cli client.Client, name string) *unikornv1.Role {
	t.Helper()

	role := &unikornv1.Role{}
	require.NoError(t, cli.Get(t.Context(), types.NamespacedName{Namespace: namespace, Name: name}, role))

	return role
}

func drain(recorder *events.FakeRecorder) []string {
	var events []string

	for {
		select {
		case e := <-recorder.Events:
			events = append(events, e)
		default:
			return events
		}
	}
}

func TestReconcileWritesStatusAndRecordsChange(t *testing.T) {
	t.Parallel()

	r, cli, recorder := setup(t, adminRole(), fleetOperator())

	reconcileRole(t, r, adminID)

	admin := getRole(t, cli, adminID)

	require.Equal(t, []unikornv1.RoleScope{
		{Name: "radar:topology", Operations: []unikornv1.Operation{unikornv1.Read}},
	}, admin.Status.EffectiveScopes.Organization)
	require.Len(t, admin.Status.AggregatedFrom, 1)
	require.Equal(t, "fleet-operator", admin.Status.AggregatedFrom[0].Name)

	available, err := unikornv1core.GetCondition(admin.Status.Conditions, unikornv1core.ConditionAvailable)
	require.NoError(t, err)
	require.Equal(t, metav1.ConditionTrue, available.Status)

	grantable, err := unikornv1core.GetCondition(admin.Status.Conditions, unikornv1.RoleConditionGrantable)
	require.NoError(t, err)
	require.Equal(t, metav1.ConditionTrue, grantable.Status)

	events := drain(recorder)
	require.Len(t, events, 1)
	require.Contains(t, events[0], EventReasonEffectiveScopesChanged)
	require.Contains(t, events[0], "fleet-operator")
	require.Contains(t, events[0], "added")
	require.Contains(t, events[0], admin.Status.AggregatedFrom[0].ScopesHash)

	require.Nil(t, admin.Spec.Scopes.Organization)
}

func TestReconcileIsIdempotent(t *testing.T) {
	t.Parallel()

	r, cli, recorder := setup(t, adminRole(), fleetOperator())

	reconcileRole(t, r, adminID)
	drain(recorder)

	before := getRole(t, cli, adminID).ResourceVersion

	reconcileRole(t, r, adminID)

	require.Equal(t, before, getRole(t, cli, adminID).ResourceVersion, "no write when nothing changed")
	require.Empty(t, drain(recorder))
}

func TestReconcileRecordsSourceScopeChange(t *testing.T) {
	t.Parallel()

	r, cli, recorder := setup(t, adminRole(), fleetOperator())

	reconcileRole(t, r, adminID)

	oldHash := getRole(t, cli, adminID).Status.AggregatedFrom[0].ScopesHash

	drain(recorder)

	fleet := getRole(t, cli, "fleet-operator")
	fleet.Spec.Scopes.Organization[0].Operations = []unikornv1.Operation{unikornv1.Read, unikornv1.Update}
	require.NoError(t, cli.Update(t.Context(), fleet))

	reconcileRole(t, r, adminID)

	admin := getRole(t, cli, adminID)
	newHash := admin.Status.AggregatedFrom[0].ScopesHash
	require.NotEqual(t, oldHash, newHash)

	events := drain(recorder)
	require.Len(t, events, 1)
	require.Contains(t, events[0], "changed")
	require.Contains(t, events[0], oldHash)
	require.Contains(t, events[0], newHash)
}

func TestReconcileRemovedSourceShrinksAdmin(t *testing.T) {
	t.Parallel()

	r, cli, recorder := setup(t, adminRole(), fleetOperator())

	reconcileRole(t, r, adminID)
	drain(recorder)

	require.NoError(t, cli.Delete(t.Context(), fleetOperator()))

	reconcileRole(t, r, adminID)

	admin := getRole(t, cli, adminID)
	require.NotNil(t, admin.Status.EffectiveScopes)
	require.Empty(t, admin.Status.EffectiveScopes.Organization)
	require.Empty(t, admin.Status.AggregatedFrom)

	events := drain(recorder)
	require.Len(t, events, 1)
	require.Contains(t, events[0], "removed")
}

func TestReconcileClearsStatusWhenNoLongerAggregating(t *testing.T) {
	t.Parallel()

	stale := unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{{Name: "svc:stale", Operations: []unikornv1.Operation{unikornv1.Read}}}}

	role := newRole("plain", nil, unikornv1.RoleSpec{})
	role.Status.EffectiveScopes = &stale

	r, cli, _ := setup(t, role)

	reconcileRole(t, r, "plain")

	require.Nil(t, getRole(t, cli, "plain").Status.EffectiveScopes)
}

func TestReconcileMissingRoleIsNotAnError(t *testing.T) {
	t.Parallel()

	r, _, _ := setup(t)

	reconcileRole(t, r, "gone")
}

func TestWatchEnqueuesEveryAggregatingRole(t *testing.T) {
	t.Parallel()

	user := newRole("user", nil, unikornv1.RoleSpec{AggregationRule: &unikornv1.RoleAggregationRule{}})

	_, cli, _ := setup(t, adminRole(), user, fleetOperator(), newRole("unrelated", nil, unikornv1.RoleSpec{}))

	requests := aggregatingRoles(t.Context(), cli, fleetOperator())

	names := make([]string, 0, len(requests))
	for _, request := range requests {
		names = append(names, request.Name)
	}

	require.ElementsMatch(t, []string{"fleet-operator", adminID, "user"}, names)
	require.NotContains(t, strings.Join(names, ","), "unrelated")
}

func TestReconcileWarnsOnceWhenStuck(t *testing.T) {
	t.Parallel()

	admin := adminRole()
	admin.Spec.AggregationRule.RoleRefs = []string{adminBaseID}

	r, cli, recorder := setup(t, admin)

	reconcileRole(t, r, adminID)

	events := drain(recorder)
	require.Len(t, events, 1)
	require.Contains(t, events[0], "Warning")
	require.Contains(t, events[0], unikornv1.RoleReasonMissingRoleRef)

	available, err := unikornv1core.GetCondition(getRole(t, cli, adminID).Status.Conditions, unikornv1core.ConditionAvailable)
	require.NoError(t, err)
	require.Equal(t, getRole(t, cli, adminID).Generation, available.ObservedGeneration)

	reconcileRole(t, r, adminID)

	require.Empty(t, drain(recorder), "a role that stays stuck does not warn again")
}

func TestReconcileDeletedRefGivesNothing(t *testing.T) {
	t.Parallel()

	admin := adminRole()
	admin.Spec.AggregationRule.RoleRefs = []string{adminBaseID}

	base := adminBase()

	r, cli, _ := setup(t, admin, base, fleetOperator())

	reconcileRole(t, r, adminID)

	require.Equal(t, base.Spec.Scopes.Organization, getRole(t, cli, adminID).Status.EffectiveScopes.Organization[:1])

	require.NoError(t, cli.Delete(t.Context(), base))
	require.NoError(t, cli.Delete(t.Context(), fleetOperator()))

	// Twice, so the second run reads the status the first one wrote.
	reconcileRole(t, r, adminID)
	reconcileRole(t, r, adminID)

	admin = getRole(t, cli, adminID)

	require.NotNil(t, admin.Status.EffectiveScopes)
	require.Empty(t, admin.Status.EffectiveScopes.Organization)
	require.Empty(t, admin.Status.AggregatedFrom)

	available, err := unikornv1core.GetCondition(admin.Status.Conditions, unikornv1core.ConditionAvailable)
	require.NoError(t, err)
	require.Equal(t, unikornv1.RoleReasonMissingRoleRef, available.Reason)
}

func TestReconcileInvalidSelectorWritesOnce(t *testing.T) {
	t.Parallel()

	admin := adminRole()
	admin.Spec.AggregationRule.RoleSelectors = []metav1.LabelSelector{{MatchLabels: map[string]string{
		"a": "1", "b": "2", "c": "3", "d": "4", "e": "5", "f": "6",
	}}}

	r, cli, recorder := setup(t, admin)

	reconcileRole(t, r, adminID)

	before := getRole(t, cli, adminID).ResourceVersion

	require.Len(t, drain(recorder), 1)

	for range 30 {
		reconcileRole(t, r, adminID)
	}

	require.Equal(t, before, getRole(t, cli, adminID).ResourceVersion, "status written again")
	require.Empty(t, drain(recorder))
}

func TestReconcileInvalidLabelKeyWritesOnce(t *testing.T) {
	t.Parallel()

	admin := adminRole()
	admin.Spec.AggregationRule.RoleSelectors = []metav1.LabelSelector{{MatchLabels: map[string]string{
		unikornv1.AggregateToLabel("a b"):                   "true",
		unikornv1.AggregateToLabel("c d"):                   "true",
		unikornv1.AggregateToLabel(strings.Repeat("x", 64)): "true",
	}}}

	r, cli, recorder := setup(t, admin)

	reconcileRole(t, r, adminID)

	before := getRole(t, cli, adminID).ResourceVersion

	require.Len(t, drain(recorder), 1)

	for range 30 {
		reconcileRole(t, r, adminID)
	}

	require.Equal(t, before, getRole(t, cli, adminID).ResourceVersion, "status written again")
	require.Empty(t, drain(recorder))
}

func TestReconcileFirstStatusRecordsEverySource(t *testing.T) {
	t.Parallel()

	admin := adminRole()
	admin.Spec.AggregationRule.RoleRefs = []string{adminBaseID}

	r, _, recorder := setup(t, admin, adminBase(), fleetOperator())

	reconcileRole(t, r, adminID)

	events := drain(recorder)
	require.Len(t, events, 2)

	for _, id := range []string{adminBaseID, "fleet-operator"} {
		require.True(t, slices.ContainsFunc(events, func(e string) bool {
			return strings.Contains(e, EventReasonEffectiveScopesChanged) && strings.Contains(e, id) && strings.Contains(e, "added")
		}), "no added event for %s: %v", id, events)
	}
}

func TestReconcileWritesGrantableFalse(t *testing.T) {
	t.Parallel()

	global := newRole("svc-global", map[string]string{unikornv1.AggregateToLabel("administrator"): "true"}, unikornv1.RoleSpec{
		Scopes: unikornv1.RoleScopes{
			Global: []unikornv1.RoleScope{{Name: "svc:everything", Operations: []unikornv1.Operation{unikornv1.Read}}},
		},
	})

	r, cli, recorder := setup(t, adminRole(), global)

	reconcileRole(t, r, adminID)

	conditions := getRole(t, cli, adminID).Status.Conditions

	available, err := unikornv1core.GetCondition(conditions, unikornv1core.ConditionAvailable)
	require.NoError(t, err)
	require.Equal(t, metav1.ConditionTrue, available.Status)

	grantable, err := unikornv1core.GetCondition(conditions, unikornv1.RoleConditionGrantable)
	require.NoError(t, err)
	require.Equal(t, metav1.ConditionFalse, grantable.Status)
	require.Equal(t, unikornv1.RoleReasonNotGrantable, grantable.Reason)
	require.Contains(t, grantable.Message, "svc-global")

	events := drain(recorder)
	require.Len(t, events, 1)
	require.Contains(t, events[0], "Warning "+unikornv1.RoleReasonNotGrantable)

	reconcileRole(t, r, adminID)
	require.Empty(t, drain(recorder))
}

func TestReconcileChangeIgnoresGlobalScopesInStatus(t *testing.T) {
	t.Parallel()

	r, cli, recorder := setup(t, adminRole(), fleetOperator())

	reconcileRole(t, r, adminID)
	drain(recorder)

	admin := getRole(t, cli, adminID)
	admin.Status.EffectiveScopes.Global = []unikornv1.RoleScope{{Name: "svc:tampered", Operations: []unikornv1.Operation{unikornv1.Delete}}}
	require.NoError(t, cli.Status().Update(t.Context(), admin))

	reconcileRole(t, r, adminID)

	require.Nil(t, getRole(t, cli, adminID).Status.EffectiveScopes.Global)
	require.Empty(t, drain(recorder))
}

func TestStuckWarningIsCapped(t *testing.T) {
	t.Parallel()

	admin := adminRole()

	for i := range 100 {
		admin.Spec.AggregationRule.RoleRefs = append(admin.Spec.AggregationRule.RoleRefs, fmt.Sprintf("missing-role-with-a-long-name-%03d", i))
	}

	r, _, recorder := setup(t, admin)

	reconcileRole(t, r, adminID)

	events := drain(recorder)
	require.Len(t, events, 1)

	note := strings.TrimPrefix(events[0], "Warning "+unikornv1.RoleReasonMissingRoleRef+" ")
	require.LessOrEqual(t, len(note), maxEventNote)
	require.True(t, strings.HasSuffix(note, "…"))
}

func TestWatchPassesStatusChanges(t *testing.T) {
	t.Parallel()

	old := adminRole()
	updated := old.DeepCopy()

	require.False(t, roleChanged().Update(event.TypedUpdateEvent[*unikornv1.Role]{ObjectOld: old, ObjectNew: updated}))

	updated.Status.EffectiveScopes = &unikornv1.RoleScopes{
		Organization: []unikornv1.RoleScope{{Name: "svc:tampered", Operations: []unikornv1.Operation{unikornv1.Delete}}},
	}

	require.True(t, roleChanged().Update(event.TypedUpdateEvent[*unikornv1.Role]{ObjectOld: old, ObjectNew: updated}))
}

func TestReconcileDeletingRoleRecordsNothingHeld(t *testing.T) {
	t.Parallel()

	admin := adminRole()
	admin.Spec.AggregationRule.RoleRefs = []string{adminBaseID}
	admin.Finalizers = []string{"test.unikorn-cloud.org/hold"}

	r, cli, recorder := setup(t, admin, adminBase(), fleetOperator())

	reconcileRole(t, r, adminID)

	available, err := unikornv1core.GetCondition(getRole(t, cli, adminID).Status.Conditions, unikornv1core.ConditionAvailable)
	require.NoError(t, err)
	require.Equal(t, metav1.ConditionTrue, available.Status)

	drain(recorder)

	require.NoError(t, cli.Delete(t.Context(), getRole(t, cli, adminID)))

	reconcileRole(t, r, adminID)

	deleting := getRole(t, cli, adminID)
	require.False(t, deleting.DeletionTimestamp.IsZero())
	require.NotNil(t, deleting.Status.EffectiveScopes)
	require.Empty(t, deleting.Status.EffectiveScopes.Organization)
	require.Empty(t, deleting.Status.EffectiveScopes.Project)
	require.Empty(t, deleting.Status.AggregatedFrom)

	for _, conditionType := range []unikornv1core.ConditionType{unikornv1core.ConditionAvailable, unikornv1.RoleConditionGrantable} {
		condition, err := unikornv1core.GetCondition(deleting.Status.Conditions, conditionType)
		require.NoError(t, err)
		require.Equal(t, metav1.ConditionFalse, condition.Status, conditionType)
		require.Equal(t, unikornv1.RoleReasonDeleting, condition.Reason, conditionType)
		require.Equal(t, "role is being deleted, it holds nothing", condition.Message, conditionType)
	}

	events := drain(recorder)
	require.Equal(t, 1, strings.Count(strings.Join(events, "\n"), "Warning "), events)

	before := deleting.ResourceVersion

	reconcileRole(t, r, adminID)

	require.Equal(t, before, getRole(t, cli, adminID).ResourceVersion)
}
