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
