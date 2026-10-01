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

package groups

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestDeduplicateStrings(t *testing.T) {
	t.Parallel()

	assert.Nil(t, deduplicateStrings(nil))

	raw := []string{"user-a", "user-a", "sa-1", "role-2", "sa-1", "role-2", "user-b"}
	want := []string{"user-a", "sa-1", "role-2", "user-b"}
	got := deduplicateStrings(raw)

	assert.Equal(t, want, got)
}

func TestDeduplicateGroupSubjects(t *testing.T) {
	t.Parallel()

	assert.Nil(t, deduplicateGroupSubjects(nil))

	raw := []unikornv1.GroupSubject{
		{ID: "alice@example.com", Issuer: "https://issuer-a", Email: "first@example.com"},
		{ID: "alice@example.com", Issuer: "https://issuer-a", Email: "second@example.com"},
		{ID: "alice@example.com", Issuer: "https://issuer-b", Email: "other-issuer@example.com"},
		{ID: "bob@example.com", Issuer: "https://issuer-a", Email: "bob@example.com"},
	}

	want := []unikornv1.GroupSubject{
		{ID: "alice@example.com", Issuer: "https://issuer-a", Email: "first@example.com"},
		{ID: "alice@example.com", Issuer: "https://issuer-b", Email: "other-issuer@example.com"},
		{ID: "bob@example.com", Issuer: "https://issuer-a", Email: "bob@example.com"},
	}

	got := deduplicateGroupSubjects(raw)

	assert.Equal(t, want, got)
}

// TestFindUserBySubjectListsWithoutDeepCopy pins the no-copy User list.  A
// group write resolves each subject at this deployment's issuer, and each
// lookup scans every User in the cache, so a copy of each one costs far more
// than the one User the lookup returns.
func TestFindUserBySubjectListsWithoutDeepCopy(t *testing.T) {
	t.Parallel()

	var lists []client.ListOptions

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{Namespace: "identity", Name: "u1111111-1111-4111-8111-111111111111"},
		Spec:       unikornv1.UserSpec{Subject: "alice@example.com"},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(user).WithInterceptorFuncs(interceptor.Funcs{
		List: func(ctx context.Context, inner client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			options := client.ListOptions{}
			options.ApplyOptions(opts)
			lists = append(lists, options)

			return inner.List(ctx, list, opts...)
		},
	}).Build()

	found, err := New(c, "identity", common.IssuerValue{}).findUserBySubject(t.Context(), "alice@example.com")
	require.NoError(t, err)
	require.Equal(t, user.Name, found.Name)
	require.Len(t, lists, 1)
	require.True(t, ptr.Deref(lists[0].UnsafeDisableDeepCopy, false))
}
