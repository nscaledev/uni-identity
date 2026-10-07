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

package userdb

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const testNamespace = "identity"

// recorder records the ListOptions of each read that the code under test makes.
type recorder struct {
	lists []client.ListOptions
	gets  []client.ObjectKey
}

func (r *recorder) funcs() interceptor.Funcs {
	return interceptor.Funcs{
		List: func(ctx context.Context, inner client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			options := client.ListOptions{}
			options.ApplyOptions(opts)
			r.lists = append(r.lists, options)

			return inner.List(ctx, list, opts...)
		},
		Get: func(ctx context.Context, inner client.WithWatch, key client.ObjectKey, object client.Object, opts ...client.GetOption) error {
			r.gets = append(r.gets, key)

			return inner.Get(ctx, key, object, opts...)
		},
	}
}

func newTestClient(t *testing.T, r *recorder, objects ...client.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).WithInterceptorFuncs(r.funcs()).Build()
}

func testUser() *unikornv1.User {
	return &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "u1111111-1111-4111-8111-111111111111"},
		Spec:       unikornv1.UserSpec{Subject: "alice@example.com"},
	}
}

func TestGetUserListsLegacyRecordsWithoutCacheOptions(t *testing.T) {
	t.Parallel()

	r := &recorder{}
	d := NewUserDatabase(newTestClient(t, r, testUser()), testNamespace)

	user, err := d.GetUser(t.Context(), "alice@example.com")
	require.NoError(t, err)
	require.Equal(t, "alice@example.com", user.Spec.Subject)
	require.Len(t, r.lists, 2)
	require.Equal(t, unikornv1.UserSubjectIDLabel+"="+unikornv1.GlobalUserName("alice@example.com"), r.lists[0].LabelSelector.String())
	require.Nil(t, r.lists[1].UnsafeDisableDeepCopy)
}

func TestGetUserUsesSubjectIDLabel(t *testing.T) {
	t.Parallel()

	r := &recorder{}
	user := testUser()
	user.Labels = map[string]string{
		unikornv1.UserSubjectIDLabel: unikornv1.GlobalUserName(user.Spec.Subject),
	}
	d := NewUserDatabase(newTestClient(t, r, user), testNamespace)

	result, err := d.GetUser(t.Context(), user.Spec.Subject)
	require.NoError(t, err)
	require.Equal(t, user.Name, result.Name)
	require.Equal(t, []client.ObjectKey{{Namespace: testNamespace, Name: unikornv1.GlobalUserName(user.Spec.Subject)}}, r.gets)
	require.Len(t, r.lists, 1)
	require.True(t, r.lists[0].LabelSelector.Matches(labels.Set(user.Labels)))
}

func TestGetUserUsesCanonicalName(t *testing.T) {
	t.Parallel()

	r := &recorder{}
	user := testUser()
	user.Name = unikornv1.GlobalUserName(user.Spec.Subject)
	d := NewUserDatabase(newTestClient(t, r, user), testNamespace)

	result, err := d.GetUser(t.Context(), "alice@example.com")
	require.NoError(t, err)
	require.Equal(t, "alice@example.com", result.Spec.Subject)
	require.Equal(t, []client.ObjectKey{{Namespace: testNamespace, Name: unikornv1.GlobalUserName(user.Spec.Subject)}}, r.gets)
	require.Len(t, r.lists, 1)
}

func TestGetUserRejectsAmbiguousLegacyRecords(t *testing.T) {
	t.Parallel()

	r := &recorder{}
	first := testUser()
	second := testUser()
	second.Name = "u2222222-2222-4222-8222-222222222222"
	d := NewUserDatabase(newTestClient(t, r, first, second), testNamespace)

	_, err := d.GetUser(t.Context(), "alice@example.com")
	require.ErrorIs(t, err, ErrResourceReference)
	require.Len(t, r.lists, 2)
}

func TestGetOrganizationIDsForUserDoesNotResolveTheUserAgain(t *testing.T) {
	t.Parallel()

	user := testUser()
	user.Spec.State = unikornv1.UserStateActive
	organizationUser := &unikornv1.OrganizationUser{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      "organization-user",
			Labels: map[string]string{
				constants.UserLabel:         user.Name,
				constants.OrganizationLabel: "organization",
			},
		},
		Spec: unikornv1.OrganizationUserSpec{State: unikornv1.UserStateActive},
	}

	r := &recorder{}
	d := NewUserDatabase(newTestClient(t, r, user, organizationUser), testNamespace)

	organizationIDs, err := d.GetOrganizationIDsForUser(t.Context(), user)
	require.NoError(t, err)
	require.Equal(t, []string{"organization"}, organizationIDs)
	require.Len(t, r.lists, 1)
}
