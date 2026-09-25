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

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const testNamespace = "identity"

// recorder records the ListOptions of each cache read that the code under
// test makes.
type recorder struct {
	lists []client.ListOptions
}

func (r *recorder) funcs() interceptor.Funcs {
	return interceptor.Funcs{
		List: func(ctx context.Context, inner client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			options := client.ListOptions{}
			options.ApplyOptions(opts)
			r.lists = append(r.lists, options)

			return inner.List(ctx, list, opts...)
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

func TestGetUserListsWithoutDeepCopy(t *testing.T) {
	t.Parallel()

	r := &recorder{}
	d := NewUserDatabase(newTestClient(t, r, testUser()), testNamespace)

	user, err := d.GetUser(t.Context(), "alice@example.com")
	require.NoError(t, err)
	require.Equal(t, "alice@example.com", user.Spec.Subject)
	require.Len(t, r.lists, 1)
	require.True(t, ptr.Deref(r.lists[0].UnsafeDisableDeepCopy, false))
}
