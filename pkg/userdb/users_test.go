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

package userdb_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/cachetest"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestErrUserInactiveWrapsErrResourceReference pins the compatibility contract:
// existing errors.Is(err, ErrResourceReference) callers must keep matching.
func TestErrUserInactiveWrapsErrResourceReference(t *testing.T) {
	t.Parallel()

	require.ErrorIs(t, userdb.ErrUserInactive, userdb.ErrResourceReference)
}

func TestGetUserReturnsOwnedCopy(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	// With deep copies disabled, the cache returns a fresh slice of shallow
	// struct copies.  Their maps and pointers stay shared with the cache.
	store := cachetest.New(t, scheme, &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{Namespace: "identity", Name: "user-alice", Labels: map[string]string{"team": "a"}},
		Spec:       unikornv1.UserSpec{Subject: "alice"},
	})

	db := userdb.NewUserDatabase(store.Client(), "identity")

	user, err := db.GetUser(t.Context(), "alice")
	require.NoError(t, err)
	require.Equal(t, "user-alice", user.Name)

	user.Labels["team"] = "b"

	store.RequireUnchanged(t)

	// The copy-free list is the performance property.  The owned copy makes
	// it safe.  Both must hold.
	options := store.ListOptions()
	require.Len(t, options, 1)
	require.NotNil(t, options[0].UnsafeDisableDeepCopy)
	require.True(t, *options[0].UnsafeDisableDeepCopy)
}

// membershipFor builds an OrganizationUser owned by the given user, in the
// given organization and state.
func membershipFor(userName, organizationID, name string, state unikornv1.UserState) *unikornv1.OrganizationUser {
	return &unikornv1.OrganizationUser{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "org-" + organizationID,
			Name:      name,
			Labels: map[string]string{
				constants.OrganizationLabel: organizationID,
				constants.UserLabel:         userName,
			},
		},
		Spec: unikornv1.OrganizationUserSpec{State: state},
	}
}

func TestActiveOrganizationIDs(t *testing.T) {
	t.Parallel()

	user := &unikornv1.User{ObjectMeta: metav1.ObjectMeta{Name: "user-alice"}}

	tests := []struct {
		name        string
		memberships []*unikornv1.OrganizationUser
		want        []string
	}{
		{
			name: "active only, pending and suspended excluded",
			memberships: []*unikornv1.OrganizationUser{
				membershipFor(user.Name, "a", "orguser-a", unikornv1.UserStateActive),
				membershipFor(user.Name, "b", "orguser-b", unikornv1.UserStatePending),
				membershipFor(user.Name, "c", "orguser-c", unikornv1.UserStateSuspended),
			},
			want: []string{"a"},
		},
		{
			name: "duplicate active memberships for one organization collapse",
			memberships: []*unikornv1.OrganizationUser{
				membershipFor(user.Name, "a", "orguser-a1", unikornv1.UserStateActive),
				membershipFor(user.Name, "a", "orguser-a2", unikornv1.UserStateActive),
			},
			want: []string{"a"},
		},
		{
			name: "output is sorted",
			memberships: []*unikornv1.OrganizationUser{
				membershipFor(user.Name, "b", "orguser-b", unikornv1.UserStateActive),
				membershipFor(user.Name, "a", "orguser-a", unikornv1.UserStateActive),
			},
			want: []string{"a", "b"},
		},
		{
			name:        "no memberships returns an empty, non-nil slice",
			memberships: nil,
			want:        []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scheme := runtime.NewScheme()
			require.NoError(t, unikornv1.AddToScheme(scheme))

			objects := make([]client.Object, len(tt.memberships))
			for i, m := range tt.memberships {
				objects[i] = m
			}

			cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

			db := userdb.NewUserDatabase(cli, "identity")

			got, err := db.ActiveOrganizationIDs(t.Context(), user)
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestGetOrganizationIDsReturnsDeduplicatedActiveSet(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "user-alice"},
		Spec:       unikornv1.UserSpec{Subject: "alice", State: unikornv1.UserStateActive},
	}

	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		user,
		membershipFor(user.Name, "a", "orguser-a1", unikornv1.UserStateActive),
		membershipFor(user.Name, "a", "orguser-a2", unikornv1.UserStateActive),
		membershipFor(user.Name, "b", "orguser-b", unikornv1.UserStateSuspended),
	).Build()

	db := userdb.NewUserDatabase(cli, "identity")

	got, err := db.GetOrganizationIDs(t.Context(), "alice")
	require.NoError(t, err)
	require.Equal(t, []string{"a"}, got)
}
