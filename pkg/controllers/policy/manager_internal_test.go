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

package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/event"
)

func testRole(generation int64) *unikornv1.Role {
	return &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "identity",
			Name:       "role-a",
			Generation: generation,
		},
	}
}

// TestRolePredicatePassesLifecycleEvents pins the event set that re-triggers
// policy generation.  The generated store must shrink when a Role disappears,
// so this VERIFIES (not assumes) that the generation-changed predicate, which
// only overrides UpdateFunc, passes Create and Delete events.
func TestRolePredicatePassesLifecycleEvents(t *testing.T) {
	t.Parallel()

	p := rolePredicate()

	require.True(t, p.Create(event.TypedCreateEvent[*unikornv1.Role]{Object: testRole(1)}), "role creation must trigger a publish")
	require.True(t, p.Delete(event.TypedDeleteEvent[*unikornv1.Role]{Object: testRole(1)}), "role deletion must trigger a publish that shrinks the store")

	require.False(t, p.Update(event.TypedUpdateEvent[*unikornv1.Role]{ObjectOld: testRole(1), ObjectNew: testRole(1)}), "metadata churn must not republish")
	require.True(t, p.Update(event.TypedUpdateEvent[*unikornv1.Role]{ObjectOld: testRole(1), ObjectNew: testRole(2)}), "spec changes must republish")
}

// TestEveryRoleEventCollapsesToOneRequest pins the fan-in contract: whatever
// Role an event is about, the same synthetic request is enqueued, so the
// workqueue dedups bursts into single store regenerations.
func TestEveryRoleEventCollapsesToOneRequest(t *testing.T) {
	t.Parallel()

	a := enqueuePolicyStore(t.Context(), testRole(1))

	other := testRole(1)
	other.Name = "role-b"

	b := enqueuePolicyStore(t.Context(), other)

	require.Len(t, a, 1)
	require.Equal(t, a, b)
	require.Equal(t, policyStoreRequestName, a[0].Name)
}

func testConfigMap(namespace, name string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
	}
}

// TestConfigMapPredicateMatchesOnlyManagedStore pins that the ConfigMap watch
// fires only for the controller-owned policy store object.  The namespace-scoped
// informer still observes every ConfigMap in the identity namespace, so the
// predicate must match name AND namespace: a delete of the managed store (which
// leaves Cerbos serving deny-by-default) must re-trigger a publish, while churn
// on any other ConfigMap must be ignored so it cannot storm the reconciler.
func TestConfigMapPredicateMatchesOnlyManagedStore(t *testing.T) {
	t.Parallel()

	const (
		namespace = "identity"
		name      = "identity-cerbos-policies"
	)

	p := configMapPredicate(namespace, name)
	managed := testConfigMap(namespace, name)

	require.True(t, p.Create(event.TypedCreateEvent[*corev1.ConfigMap]{Object: managed}), "managed store creation must trigger a publish")
	require.True(t, p.Update(event.TypedUpdateEvent[*corev1.ConfigMap]{ObjectOld: managed, ObjectNew: managed}), "managed store mutation must trigger a restore")
	require.True(t, p.Delete(event.TypedDeleteEvent[*corev1.ConfigMap]{Object: managed}), "managed store deletion must trigger recreation")

	require.False(t, p.Create(event.TypedCreateEvent[*corev1.ConfigMap]{Object: testConfigMap(namespace, "other")}), "a different ConfigMap in the namespace must be ignored")
	require.False(t, p.Delete(event.TypedDeleteEvent[*corev1.ConfigMap]{Object: testConfigMap("other-namespace", name)}), "the same name in another namespace must be ignored")
}

// TestConfigMapEventCollapsesToPolicyStoreRequest pins that a managed-ConfigMap
// event enqueues the SAME synthetic fan-in request as a Role event, so drift on
// the store re-enters the one reconcile that regenerates it and the workqueue
// dedups ConfigMap and Role events against each other.
func TestConfigMapEventCollapsesToPolicyStoreRequest(t *testing.T) {
	t.Parallel()

	reqs := enqueueConfigMapPolicyStore(t.Context(), testConfigMap("identity", "identity-cerbos-policies"))

	require.Len(t, reqs, 1)
	require.Equal(t, policyStoreRequestName, reqs[0].Name)
	require.Equal(t, enqueuePolicyStore(t.Context(), testRole(1)), reqs, "ConfigMap and Role events must map to the same fan-in request")
}
