/*
Copyright 2024-2025 the Unikorn Authors.
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

package organizations

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/cachetest"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const clientTestNamespace = "identity"

// newStore returns a store that serves the given objects the way the
// informer cache does.
func newStore(tb testing.TB, objects ...client.Object) *cachetest.Store {
	tb.Helper()

	scheme := runtime.NewScheme()
	require.NoError(tb, unikornv1.AddToScheme(scheme))

	return cachetest.New(tb, scheme, objects...)
}

// newFakeClient returns a client that serves the given objects the way the
// informer cache does.
func newFakeClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	return newStore(t, objects...).Client()
}

// requireGetsSkipCopy asserts that the store recorded at least one Get, and
// that every one requested UnsafeDisableDeepCopy.
func requireGetsSkipCopy(t *testing.T, store *cachetest.Store) {
	t.Helper()

	options := store.GetOptions()
	require.NotEmpty(t, options)

	for _, o := range options {
		require.NotNil(t, o.UnsafeDisableDeepCopy)
		require.True(t, *o.UnsafeDisableDeepCopy)
	}
}

// namespacedOrg returns an organization in the test namespace.
func namespacedOrg(name, id string) *unikornv1.Organization {
	return &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: clientTestNamespace,
			Name:      id,
			Labels:    map[string]string{constants.NameLabel: name},
		},
	}
}

// TestListActiveMembershipsOnce pins the membership-visibility contract.
// Only active memberships are visible, and each organization is listed
// once.
func TestListActiveMembershipsOnce(t *testing.T) {
	t.Parallel()

	email := "alice@example.com"

	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{Namespace: clientTestNamespace, Name: "user-alice"},
		Spec:       unikornv1.UserSpec{Subject: email, State: unikornv1.UserStateActive},
	}

	membership := func(orgID, name string, state unikornv1.UserState) *unikornv1.OrganizationUser {
		return &unikornv1.OrganizationUser{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "org-" + orgID,
				Name:      name,
				Labels: map[string]string{
					constants.OrganizationLabel: orgID,
					constants.UserLabel:         user.Name,
				},
			},
			Spec: unikornv1.OrganizationUserSpec{State: state},
		}
	}

	store := newStore(t, user,
		membership("id-a", "orguser-a", unikornv1.UserStateActive),
		membership("id-b", "orguser-b", unikornv1.UserStateSuspended),
		membership("id-c", "orguser-c1", unikornv1.UserStateActive),
		membership("id-c", "orguser-c2", unikornv1.UserStateActive),
		namespacedOrg("alpha", "id-a"), namespacedOrg("beta", "id-b"), namespacedOrg("gamma", "id-c"))
	c := store.Client()

	ctx := authorization.NewContext(t.Context(), &authorization.Info{
		Userinfo: &openapi.Userinfo{Sub: email, Email: ptr.To(email)},
	})
	ctx = rbac.NewContext(ctx, &openapi.Acl{})

	list, err := New(c, clientTestNamespace).List(ctx, userdb.NewUserDatabase(c, clientTestNamespace), &email, 0)
	require.NoError(t, err)
	require.Len(t, list, 2)
	require.Equal(t, "id-a", list[0].Metadata.Id)
	require.Equal(t, "alpha", list[0].Metadata.Name)
	require.Equal(t, "id-c", list[1].Metadata.Id)
	require.Equal(t, "gamma", list[1].Metadata.Name)

	// The membership branch reads each visible organization with a Get.
	// Pin that every Get skips the deep copy, and that nothing mutated the
	// cache objects during the test.
	requireGetsSkipCopy(t, store)
	store.RequireUnchanged(t)
}

// globalReadContext returns a context whose ACL reads every organization.
func globalReadContext(tb testing.TB) context.Context {
	tb.Helper()

	return rbac.NewContext(tb.Context(), &openapi.Acl{
		Global: &openapi.AclEndpoints{
			{Name: "identity:organizations", Operations: openapi.AclOperations{openapi.Read}},
		},
	})
}

func TestGlobalReadSharesCacheReadOnly(t *testing.T) {
	t.Parallel()

	store := newStore(t, namespacedOrg("beta", "id-1"), namespacedOrg("alpha", "id-2"), namespacedOrg("gamma", "id-3"))
	ctx := globalReadContext(t)
	organizations := New(store.Client(), clientTestNamespace)

	_, err := organizations.List(ctx, nil, nil, 0)
	require.NoError(t, err)

	options := store.ListOptions()
	require.Len(t, options, 1)
	require.Equal(t, clientTestNamespace, options[0].Namespace)
	require.NotNil(t, options[0].UnsafeDisableDeepCopy)
	require.True(t, *options[0].UnsafeDisableDeepCopy)

	store.RequireUnchanged(t)
}

func TestListZeroCapReturnsAll(t *testing.T) {
	t.Parallel()

	c := newFakeClient(t, namespacedOrg("a", "id-1"), namespacedOrg("b", "id-2"), namespacedOrg("c", "id-3"))

	ctx := rbac.NewContext(t.Context(), &openapi.Acl{
		Global: &openapi.AclEndpoints{
			{Name: "identity:organizations", Operations: openapi.AclOperations{openapi.Read}},
		},
	})

	organizations := New(c, clientTestNamespace)

	all, err := organizations.List(ctx, nil, nil, 0)
	require.NoError(t, err)
	require.Len(t, all, 3)

	negative, err := organizations.List(ctx, nil, nil, -1)
	require.NoError(t, err)
	require.Len(t, negative, 3)

	capped, err := organizations.List(ctx, nil, nil, 2)
	require.NoError(t, err)
	require.Len(t, capped, 2)
	require.Equal(t, "id-1", capped[0].Metadata.Id)
	require.Equal(t, "id-2", capped[1].Metadata.Id)
}

// memberFixture returns an active user with an active membership in each
// organization, and a context for that user with an empty ACL.
func memberFixture(t *testing.T, organizationIDs ...string) (context.Context, []client.Object) {
	t.Helper()

	email := "alice@example.com"

	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{Namespace: clientTestNamespace, Name: "user-alice"},
		Spec:       unikornv1.UserSpec{Subject: email, State: unikornv1.UserStateActive},
	}

	objects := []client.Object{user}

	for _, id := range organizationIDs {
		objects = append(objects, &unikornv1.OrganizationUser{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "org-" + id,
				Name:      "orguser-" + id,
				Labels: map[string]string{
					constants.OrganizationLabel: id,
					constants.UserLabel:         user.Name,
				},
			},
			Spec: unikornv1.OrganizationUserSpec{State: unikornv1.UserStateActive},
		})
	}

	ctx := authorization.NewContext(t.Context(), &authorization.Info{
		Userinfo: &openapi.Userinfo{Sub: email, Email: ptr.To(email)},
	})

	return rbac.NewContext(ctx, &openapi.Acl{}), objects
}

func TestListOrdersShuffledInput(t *testing.T) {
	t.Parallel()

	// ID order differs from display name order, so the test fails when the
	// sort is removed or when the display name decides the order.
	c := newFakeClient(t,
		namespacedOrg("delta", "id-1"),
		namespacedOrg("beta", "id-2"),
		namespacedOrg("gamma", "id-3"),
		namespacedOrg("alpha", "id-4"),
	)

	ctx := globalReadContext(t)
	organizations := New(c, clientTestNamespace)
	want := []string{"id-1", "id-2", "id-3", "id-4"}

	// Each List shuffles again, so repeated calls make a sorted input by
	// chance very unlikely.
	for range 20 {
		list, err := organizations.List(ctx, nil, nil, 0)
		require.NoError(t, err)

		got := make([]string, len(list))
		for i := range list {
			got[i] = list[i].Metadata.Id
		}

		require.Equal(t, want, got)
	}
}

// freshOrgsFixture returns organization objects for TestListCapsBothBranches.
// Each subtest calls it separately, since the subtests run in parallel and
// must not share the same object pointers.
func freshOrgsFixture() []client.Object {
	return []client.Object{namespacedOrg("beta", "id-1"), namespacedOrg("alpha", "id-2"), namespacedOrg("gamma", "id-3")}
}

func TestListCapsBothBranches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(t *testing.T) (context.Context, []client.Object)
		first string
		all   []string
	}{
		{
			name: "global read",
			setup: func(t *testing.T) (context.Context, []client.Object) {
				t.Helper()

				return globalReadContext(t), freshOrgsFixture()
			},
			first: "id-1",
			all:   []string{"id-1", "id-2", "id-3"},
		},
		{
			name: "membership",
			setup: func(t *testing.T) (context.Context, []client.Object) {
				t.Helper()

				ctx, objects := memberFixture(t, "id-1", "id-2")

				return ctx, append(freshOrgsFixture(), objects...)
			},
			first: "id-1",
			all:   []string{"id-1", "id-2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, objects := tt.setup(t)
			store := newStore(t, objects...)
			organizations := New(store.Client(), clientTestNamespace)
			udb := userdb.NewUserDatabase(store.Client(), clientTestNamespace)

			capped, err := organizations.List(ctx, udb, nil, 1)
			require.NoError(t, err)
			require.Len(t, capped, 1)
			require.Equal(t, tt.first, capped[0].Metadata.Id)

			all, err := organizations.List(ctx, udb, nil, 0)
			require.NoError(t, err)

			got := make([]string, len(all))
			for i := range all {
				got[i] = all[i].Metadata.Id
			}

			require.Equal(t, tt.all, got)

			store.RequireUnchanged(t)
		})
	}
}
