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

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).
		WithIndex(&unikornv1.User{}, SubjectIndexField, SubjectIndexValue).
		WithInterceptorFuncs(r.funcs()).Build()
}

// newTestDatabase reads records and the subject index from one client, as the
// informer cache serves both in the server.
func newTestDatabase(t *testing.T, r *recorder, objects ...client.Object) *UserDatabase {
	t.Helper()

	c := newTestClient(t, r, objects...)

	return NewUserDatabase(c, c, testNamespace)
}

func testUser() *unikornv1.User {
	return &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "u1111111-1111-4111-8111-111111111111"},
		Spec:       unikornv1.UserSpec{Subject: "alice@example.com"},
	}
}

// TestGetUserFindsLegacyRecordsByTheSubjectIndex checks that an unlabelled
// legacy record is found through the subject index, not a list of every user,
// in any case of the claim.
func TestGetUserFindsLegacyRecordsByTheSubjectIndex(t *testing.T) {
	t.Parallel()

	for _, claim := range []string{"alice@example.com", "Alice@Example.com"} {
		r := &recorder{}
		d := newTestDatabase(t, r, testUser())

		user, err := d.GetUser(t.Context(), claim)
		require.NoError(t, err, claim)
		require.Equal(t, "alice@example.com", user.Spec.Subject)
		require.Len(t, r.lists, 2)
		require.Equal(t, unikornv1.UserSubjectIDLabel+"="+unikornv1.GlobalUserName("alice@example.com"), r.lists[0].LabelSelector.String())
		require.Equal(t, SubjectIndexField+"=alice@example.com", r.lists[1].FieldSelector.String())
		require.Equal(t, client.ObjectKeyFromObject(testUser()), r.gets[len(r.gets)-1], "the record is read through the database's own client")
	}
}

// TestGetUserReadsLegacyRecordsThroughItsOwnClient checks that the index only
// names a legacy record: its content comes from the client, which is live for
// the reads that decide a write.
func TestGetUserReadsLegacyRecordsThroughItsOwnClient(t *testing.T) {
	t.Parallel()

	stale := testUser()
	stale.Spec.State = unikornv1.UserStateSuspended

	current := testUser()
	current.Spec.State = unikornv1.UserStateActive

	d := NewUserDatabase(newTestClient(t, &recorder{}, current), newTestClient(t, &recorder{}, stale), testNamespace)

	user, err := d.GetActiveUser(t.Context(), "alice@example.com")
	require.NoError(t, err)
	require.Equal(t, unikornv1.UserStateActive, user.Spec.State)
}

// TestGetServiceAccountReadsByKey checks that a service account is read by its
// organization's namespace and its ID, not found in a list of every account.
func TestGetServiceAccountReadsByKey(t *testing.T) {
	t.Parallel()

	organization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "organization"},
		Status:     unikornv1.OrganizationStatus{Namespace: "organization-ns"},
	}
	serviceAccount := &unikornv1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Namespace: "organization-ns", Name: "service-account"},
	}

	r := &recorder{}
	d := newTestDatabase(t, r, organization, serviceAccount)

	result, err := d.GetServiceAccount(t.Context(), "organization", "service-account")
	require.NoError(t, err)
	require.Equal(t, "service-account", result.Name)
	require.Empty(t, r.lists)
	require.Equal(t, []client.ObjectKey{
		{Namespace: testNamespace, Name: "organization"},
		{Namespace: "organization-ns", Name: "service-account"},
	}, r.gets)

	_, err = d.GetServiceAccount(t.Context(), "organization", "missing")
	require.ErrorIs(t, err, ErrResourceReference)

	_, err = d.GetServiceAccount(t.Context(), "missing", "service-account")
	require.ErrorIs(t, err, ErrResourceReference)
}

func TestGetUserUsesSubjectIDLabel(t *testing.T) {
	t.Parallel()

	r := &recorder{}
	user := testUser()
	user.Labels = map[string]string{
		unikornv1.UserSubjectIDLabel: unikornv1.GlobalUserName(user.Spec.Subject),
	}
	d := newTestDatabase(t, r, user)

	result, err := d.GetUser(t.Context(), user.Spec.Subject)
	require.NoError(t, err)
	require.Equal(t, user.Name, result.Name)
	require.Equal(t, []client.ObjectKey{{Namespace: testNamespace, Name: unikornv1.GlobalUserName(user.Spec.Subject)}}, r.gets)
	require.Len(t, r.lists, 1)
	require.True(t, r.lists[0].LabelSelector.Matches(labels.Set(user.Labels)))
}

// TestGetUserFoldsSubjectForLabelledLegacyRecord checks that a legacy record
// stored before subjects were folded is found by its label from a claim in
// any case, without the list-and-filter fallback.
func TestGetUserFoldsSubjectForLabelledLegacyRecord(t *testing.T) {
	t.Parallel()

	user := testUser()
	user.Spec.Subject = "Bob@Example.com"
	user.Labels = map[string]string{
		unikornv1.UserSubjectIDLabel: unikornv1.GlobalUserName(user.Spec.Subject),
	}

	for _, claim := range []string{"bob@example.com", "Bob@Example.com"} {
		r := &recorder{}
		d := newTestDatabase(t, r, user)

		result, err := d.GetUser(t.Context(), claim)
		require.NoError(t, err, claim)
		require.Equal(t, user.Name, result.Name)
		require.Len(t, r.lists, 1, "a labelled record must not need the compatibility scan")
		require.True(t, r.lists[0].LabelSelector.Matches(labels.Set(user.Labels)))
	}
}

// TestGetUserFoldsSubjectForCanonicalName checks that a claim in another case
// still derives the deterministic name.
func TestGetUserFoldsSubjectForCanonicalName(t *testing.T) {
	t.Parallel()

	r := &recorder{}
	user := testUser()
	user.Spec.Subject = "bob@example.com"
	user.Name = unikornv1.GlobalUserName(user.Spec.Subject)
	d := newTestDatabase(t, r, user)

	result, err := d.GetUser(t.Context(), "Bob@Example.com")
	require.NoError(t, err)
	require.Equal(t, user.Name, result.Name)
	require.Equal(t, unikornv1.GlobalUserName("bob@example.com"), unikornv1.GlobalUserName("Bob@Example.com"))
	require.Empty(t, r.lists)
}

func TestGetUserUsesCanonicalName(t *testing.T) {
	t.Parallel()

	r := &recorder{}
	user := testUser()
	user.Name = unikornv1.GlobalUserName(user.Spec.Subject)
	d := newTestDatabase(t, r, user)

	result, err := d.GetUser(t.Context(), "alice@example.com")
	require.NoError(t, err)
	require.Equal(t, "alice@example.com", result.Spec.Subject)
	require.Equal(t, []client.ObjectKey{{Namespace: testNamespace, Name: unikornv1.GlobalUserName(user.Spec.Subject)}}, r.gets)
	require.Empty(t, r.lists, "a user found by its deterministic name must not need a list")
}

func TestGetUserRejectsAmbiguousLegacyRecords(t *testing.T) {
	t.Parallel()

	r := &recorder{}
	first := testUser()
	second := testUser()
	second.Name = "u2222222-2222-4222-8222-222222222222"
	d := newTestDatabase(t, r, first, second)

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
	d := newTestDatabase(t, r, user, organizationUser)

	organizationIDs, err := d.GetOrganizationIDsForUser(t.Context(), user)
	require.NoError(t, err)
	require.Equal(t, []string{"organization"}, organizationIDs)
	require.Len(t, r.lists, 1)
}
