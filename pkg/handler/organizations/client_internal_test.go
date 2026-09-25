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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
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

func TestListPageBindsFilterIntoCursor(t *testing.T) {
	t.Parallel()

	c := newFakeClient(t,
		namespacedOrg("alpha-team", "id-2"),
		namespacedOrg("alpha-team", "id-1"),
		namespacedOrg("beta", "id-3"),
		namespacedOrg("gamma-team", "id-4"),
	)

	ctx := rbac.NewContext(t.Context(), &openapi.Acl{
		Global: &openapi.AclEndpoints{
			{Name: "identity:organizations", Operations: openapi.AclOperations{openapi.Read}},
		},
	})

	organizations := New(c, clientTestNamespace)

	filter := "team"

	var (
		after *Cursor
		seen  []string
	)

	for range 10 {
		page, err := organizations.ListPage(ctx, nil, &Walk{Filter: filter, After: after, Limit: 1})
		require.NoError(t, err)
		require.Equal(t, 1, page.Pagination.Limit)

		for _, item := range page.Items {
			seen = append(seen, item.Metadata.Id)
		}

		if page.Pagination.NextCursor == nil {
			break
		}

		after, err = DecodeCursor(*page.Pagination.NextCursor)
		require.NoError(t, err)
		require.Equal(t, filter, after.Filter)
		require.Empty(t, after.Email)

		filter = after.Filter
	}

	require.Equal(t, []string{"id-1", "id-2", "id-4"}, seen)
}

func TestListPageRejectsNonPositiveLimit(t *testing.T) {
	t.Parallel()

	_, err := New(newFakeClient(t), clientTestNamespace).ListPage(t.Context(), nil, &Walk{})
	require.ErrorIs(t, err, ErrInvalidOptions)
}

// TestListPageBindsEmailIntoCursor also pins the membership-visibility
// contract.  Only active memberships are visible, each organization is
// listed once, and the cursor carries the email filter across pages.
func TestListPageBindsEmailIntoCursor(t *testing.T) {
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

	organizations := New(c, clientTestNamespace)
	udb := userdb.NewUserDatabase(c, clientTestNamespace)

	first, err := organizations.ListPage(ctx, udb, &Walk{Email: &email, Limit: 1})
	require.NoError(t, err)
	require.Equal(t, 1, first.Pagination.Limit)
	require.Len(t, first.Items, 1)
	require.Equal(t, "id-a", first.Items[0].Metadata.Id)
	require.Equal(t, "alpha", first.Items[0].Metadata.Name)
	require.NotNil(t, first.Pagination.NextCursor)

	after, err := DecodeCursor(*first.Pagination.NextCursor)
	require.NoError(t, err)
	require.Equal(t, email, after.Email)

	second, err := organizations.ListPage(ctx, udb, &Walk{Email: &email, After: after, Limit: 1})
	require.NoError(t, err)
	require.Equal(t, 1, second.Pagination.Limit)
	require.Len(t, second.Items, 1)
	require.Equal(t, "id-c", second.Items[0].Metadata.Id)
	require.Equal(t, "gamma", second.Items[0].Metadata.Name)
	require.Nil(t, second.Pagination.NextCursor)

	list, err := organizations.List(ctx, udb, &email, 0)
	require.NoError(t, err)
	require.Len(t, list, 2)
	require.Equal(t, "id-a", list[0].Metadata.Id)
	require.Equal(t, "id-c", list[1].Metadata.Id)

	// The membership branch reads each visible organization with a Get.
	// Pin that every Get skips the deep copy, and that nothing mutated the
	// cache objects during the test.
	requireGetsSkipCopy(t, store)
	store.RequireUnchanged(t)
}

func TestListPageByIDGlobal(t *testing.T) {
	t.Parallel()

	store := newStore(t, namespacedOrg("beta", "id-b"), namespacedOrg("alpha", "id-a"), namespacedOrg("gamma", "id-c"))
	c := store.Client()

	ctx := rbac.NewContext(t.Context(), &openapi.Acl{
		Global: &openapi.AclEndpoints{
			{Name: "identity:organizations", Operations: openapi.AclOperations{openapi.Read}},
		},
	})

	page, err := New(c, clientTestNamespace).ListPage(ctx, nil, &Walk{IDs: []string{"id-b", "id-a", "id-unknown"}, Limit: 3})
	require.NoError(t, err)
	require.Len(t, page.Items, 2)
	require.Equal(t, "id-a", page.Items[0].Metadata.Id)
	require.Equal(t, "alpha", page.Items[0].Metadata.Name)
	require.Equal(t, "id-b", page.Items[1].Metadata.Id)
	require.Equal(t, 3, page.Pagination.Limit)
	require.Nil(t, page.Pagination.NextCursor)

	// The ID-lookup branch reads each requested organization with a Get.
	// Pin that every Get skips the deep copy, and that nothing mutated the
	// cache objects during the test.
	requireGetsSkipCopy(t, store)
	store.RequireUnchanged(t)
}

func TestListPageByIDMembership(t *testing.T) {
	t.Parallel()

	email := "alice@example.com"

	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{Namespace: clientTestNamespace, Name: "user-alice"},
		Spec:       unikornv1.UserSpec{Subject: email, State: unikornv1.UserStateActive},
	}

	membership := func(orgID string, state unikornv1.UserState) *unikornv1.OrganizationUser {
		return &unikornv1.OrganizationUser{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "org-" + orgID,
				Name:      "orguser-" + orgID,
				Labels: map[string]string{
					constants.OrganizationLabel: orgID,
					constants.UserLabel:         user.Name,
				},
			},
			Spec: unikornv1.OrganizationUserSpec{State: state},
		}
	}

	c := newFakeClient(t, user,
		membership("id-a", unikornv1.UserStateActive),
		membership("id-b", unikornv1.UserStateSuspended),
		namespacedOrg("alpha", "id-a"), namespacedOrg("beta", "id-b"), namespacedOrg("gamma", "id-c"))

	ctx := authorization.NewContext(t.Context(), &authorization.Info{
		Userinfo: &openapi.Userinfo{Sub: email, Email: ptr.To(email)},
	})
	ctx = rbac.NewContext(ctx, &openapi.Acl{})

	page, err := New(c, clientTestNamespace).ListPage(ctx, userdb.NewUserDatabase(c, clientTestNamespace), &Walk{IDs: []string{"id-a", "id-b", "id-c"}, Limit: 3})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	require.Equal(t, "id-a", page.Items[0].Metadata.Id)
	require.Nil(t, page.Pagination.NextCursor)
}

// TestListPageByIDDanglingMembership pins that an ID lookup fails like the
// walk when a membership names a missing organization.  The global branch
// still omits an unknown ID, as TestListPageByIDGlobal shows.
func TestListPageByIDDanglingMembership(t *testing.T) {
	t.Parallel()

	ctx, objects := memberFixture(t, "id-1", "id-missing")
	c := newFakeClient(t, append(objects, namespacedOrg("alpha", "id-1"))...)

	_, err := New(c, clientTestNamespace).ListPage(ctx, userdb.NewUserDatabase(c, clientTestNamespace), &Walk{IDs: []string{"id-missing"}, Limit: 1})
	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}

func TestListPageByIDServiceAccount(t *testing.T) {
	t.Parallel()

	account := &unikornv1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "org-id-a",
			Name:      "sa-1",
			Labels:    map[string]string{constants.OrganizationLabel: "id-a"},
		},
	}

	c := newFakeClient(t, account, namespacedOrg("alpha", "id-a"), namespacedOrg("beta", "id-b"))

	ctx := authorization.NewContext(t.Context(), &authorization.Info{
		ServiceAccount: true,
		Userinfo:       &openapi.Userinfo{Sub: "sa-1"},
	})
	ctx = rbac.NewContext(ctx, &openapi.Acl{})

	page, err := New(c, clientTestNamespace).ListPage(ctx, userdb.NewUserDatabase(c, clientTestNamespace), &Walk{IDs: []string{"id-a", "id-b"}, Limit: 2})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	require.Equal(t, "id-a", page.Items[0].Metadata.Id)
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

func TestListNonPositiveCapReturnsAll(t *testing.T) {
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

// TestListServiceAccountIgnoresEmail pins that a service-account caller
// gets its own organization.  The list ignores an email that names another
// user, even when that user is a member of other organizations.
func TestListServiceAccountIgnoresEmail(t *testing.T) {
	t.Parallel()

	email := "bob@example.com"

	bob := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{Namespace: clientTestNamespace, Name: "user-bob"},
		Spec:       unikornv1.UserSpec{Subject: email, State: unikornv1.UserStateActive},
	}

	membership := &unikornv1.OrganizationUser{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "org-id-2",
			Name:      "orguser-bob",
			Labels: map[string]string{
				constants.OrganizationLabel: "id-2",
				constants.UserLabel:         bob.Name,
			},
		},
		Spec: unikornv1.OrganizationUserSpec{State: unikornv1.UserStateActive},
	}

	account := &unikornv1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "org-id-1",
			Name:      "sa-1",
			Labels:    map[string]string{constants.OrganizationLabel: "id-1"},
		},
	}

	store := newStore(t, bob, membership, account, namespacedOrg("alpha", "id-1"), namespacedOrg("beta", "id-2"))
	c := store.Client()

	ctx := authorization.NewContext(t.Context(), &authorization.Info{
		Userinfo:       &openapi.Userinfo{Sub: account.Name},
		ServiceAccount: true,
	})
	ctx = rbac.NewContext(ctx, &openapi.Acl{})

	list, err := New(c, clientTestNamespace).List(ctx, userdb.NewUserDatabase(c, clientTestNamespace), &email, 0)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, "id-1", list[0].Metadata.Id)
	require.Equal(t, "alpha", list[0].Metadata.Name)

	store.RequireUnchanged(t)
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

func TestGlobalReadSharesCacheReadOnly(t *testing.T) {
	t.Parallel()

	store := newStore(t, namespacedOrg("beta", "id-1"), namespacedOrg("alpha", "id-2"), namespacedOrg("gamma", "id-3"))
	ctx := globalReadContext(t)
	organizations := New(store.Client(), clientTestNamespace)

	_, err := organizations.List(ctx, nil, nil, 0)
	require.NoError(t, err)

	_, err = organizations.ListPage(ctx, nil, &Walk{Limit: 2})
	require.NoError(t, err)

	options := store.ListOptions()
	require.Len(t, options, 2)

	for _, o := range options {
		require.Equal(t, clientTestNamespace, o.Namespace)
		require.NotNil(t, o.UnsafeDisableDeepCopy)
		require.True(t, *o.UnsafeDisableDeepCopy)
	}

	store.RequireUnchanged(t)
}

func TestListOrdersShuffledInput(t *testing.T) {
	t.Parallel()

	// ID order differs from display name order.  List must return ID order
	// and ListPage must return display name order, so a missing or wrong
	// sort fails.
	c := newFakeClient(t,
		namespacedOrg("delta", "id-1"),
		namespacedOrg("beta", "id-2"),
		namespacedOrg("gamma", "id-3"),
		namespacedOrg("alpha", "id-4"),
	)

	ctx := globalReadContext(t)
	organizations := New(c, clientTestNamespace)
	want := []string{"id-1", "id-2", "id-3", "id-4"}
	wantPage := []string{"id-4", "id-2", "id-1", "id-3"}

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

		page, err := organizations.ListPage(ctx, nil, &Walk{Limit: 4})
		require.NoError(t, err)

		got = make([]string, len(page.Items))
		for i := range page.Items {
			got[i] = page.Items[i].Metadata.Id
		}

		require.Equal(t, wantPage, got)
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

func TestConvertItemMatchesRead(t *testing.T) {
	t.Parallel()

	in := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "a142f641-7fd6-4ab9-a875-344c7ebadc53",
			Labels: map[string]string{constants.NameLabel: "acme"},
		},
		Spec: unikornv1.OrganizationSpec{
			Domain:        ptr.To("acme.corp"),
			ProviderScope: ptr.To(unikornv1.ProviderScopeGlobal),
			ProviderID:    ptr.To("b6ec241d-e3b4-4afc-a7aa-500fcb650d8e"),
		},
	}

	readJSON, err := json.Marshal(convert(in))
	require.NoError(t, err)

	item := convertItem(in)
	require.Nil(t, item.Quotas)
	require.Nil(t, item.Projects)
	require.Nil(t, item.ProjectsCount)

	itemJSON, err := json.Marshal(item)
	require.NoError(t, err)
	require.JSONEq(t, string(readJSON), string(itemJSON))
}
