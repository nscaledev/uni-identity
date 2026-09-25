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

package organizations

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	testNamespace = "identity"
	orgA          = "a1111111-1111-4111-8111-111111111111"
	orgB          = "b2222222-2222-4222-8222-222222222222"
	userName      = "u1111111-1111-4111-8111-111111111111"
	subject       = "alice@example.com"
)

// errBoom is a sentinel error for tests that need a non-NotFound failure.
var errBoom = errors.New("boom")

// recorder records the options of each cache read that the code under test
// makes.
type recorder struct {
	lists []client.ListOptions
	gets  []client.GetOptions
}

func (r *recorder) funcs() interceptor.Funcs {
	return interceptor.Funcs{
		List: func(ctx context.Context, inner client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			options := client.ListOptions{}
			options.ApplyOptions(opts)
			r.lists = append(r.lists, options)

			return inner.List(ctx, list, opts...)
		},
		Get: func(ctx context.Context, inner client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			options := client.GetOptions{}
			options.ApplyOptions(opts)
			r.gets = append(r.gets, options)

			return inner.Get(ctx, key, obj, opts...)
		},
	}
}

func newTestClient(t *testing.T, r *recorder, objects ...client.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).WithInterceptorFuncs(r.funcs()).Build()
}

func org(id string) *unikornv1.Organization {
	return &unikornv1.Organization{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: id}}
}

func user() *unikornv1.User {
	return &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: userName},
		Spec:       unikornv1.UserSpec{Subject: subject, State: unikornv1.UserStateActive},
	}
}

func membership(name, orgID string) *unikornv1.OrganizationUser {
	return &unikornv1.OrganizationUser{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "org-" + orgID[:8],
			Name:      name,
			Labels:    map[string]string{constants.UserLabel: userName, constants.OrganizationLabel: orgID},
		},
	}
}

func globalReadContext(t *testing.T) context.Context {
	t.Helper()

	return rbac.NewContext(t.Context(), &openapi.Acl{Global: &openapi.AclEndpoints{
		{Name: "identity:organizations", Operations: openapi.AclOperations{openapi.Read}},
	}})
}

func memberContext(t *testing.T) context.Context {
	t.Helper()

	ctx := rbac.NewContext(t.Context(), &openapi.Acl{})

	return authorization.NewContext(ctx, &authorization.Info{Userinfo: &openapi.Userinfo{Sub: subject}})
}

func requireNoDeepCopy(t *testing.T, r *recorder) {
	t.Helper()

	for _, options := range r.lists {
		require.True(t, ptr.Deref(options.UnsafeDisableDeepCopy, false), "list must disable deep copies")
	}

	for _, options := range r.gets {
		require.True(t, ptr.Deref(options.UnsafeDisableDeepCopy, false), "get must disable deep copies")
	}
}

func TestListGlobalBranchReadsWithoutDeepCopy(t *testing.T) {
	t.Parallel()

	r := &recorder{}
	c := New(newTestClient(t, r, org(orgB), org(orgA)), testNamespace)

	out, err := c.List(globalReadContext(t), nil, nil)
	require.NoError(t, err)
	require.Len(t, out, 2)
	require.Equal(t, orgA, out[0].Metadata.Id)
	require.Equal(t, orgB, out[1].Metadata.Id)
	requireNoDeepCopy(t, r)
}

func TestListMembershipBranchGetsEachOrganization(t *testing.T) {
	t.Parallel()

	r := &recorder{}
	k8s := newTestClient(t, r, org(orgA), org(orgB), user(), membership("m1", orgB), membership("m2", orgB))
	c := New(k8s, testNamespace)

	out, err := c.List(memberContext(t), userdb.NewUserDatabase(k8s, testNamespace), nil)
	require.NoError(t, err)
	require.Len(t, out, 2, "duplicate memberships still return the organization twice")
	require.Equal(t, orgB, out[0].Metadata.Id)
	require.Len(t, r.gets, 2)

	// This test checks only the organization reads. The OrganizationUser list
	// in organizationIDs still makes deep copies.
	for _, options := range r.gets {
		require.True(t, ptr.Deref(options.UnsafeDisableDeepCopy, false), "get must disable deep copies")
	}
}

func TestListMembershipBranchGetErrorIsWrapped(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(user(), membership("m1", orgA)).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, inner client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*unikornv1.Organization); ok {
				return errBoom
			}

			return inner.Get(ctx, key, obj, opts...)
		},
	}).Build()

	_, err := New(k8s, testNamespace).List(memberContext(t), userdb.NewUserDatabase(k8s, testNamespace), nil)
	require.Error(t, err)
	require.ErrorIs(t, err, errBoom)
	require.NotErrorIs(t, err, coreerrors.ErrConsistency)
}

func TestListMembershipBranchSortsByID(t *testing.T) {
	t.Parallel()

	k8s := newTestClient(t, &recorder{}, org(orgA), org(orgB), user(), membership("m1", orgB), membership("m2", orgA))

	out, err := New(k8s, testNamespace).List(memberContext(t), userdb.NewUserDatabase(k8s, testNamespace), nil)
	require.NoError(t, err)
	require.Len(t, out, 2)
	require.Equal(t, orgA, out[0].Metadata.Id)
	require.Equal(t, orgB, out[1].Metadata.Id)
}

func TestListMembershipBranchDanglingMembershipIsInconsistent(t *testing.T) {
	t.Parallel()

	r := &recorder{}
	k8s := newTestClient(t, r, user(), membership("m1", orgA))

	_, err := New(k8s, testNamespace).List(memberContext(t), userdb.NewUserDatabase(k8s, testNamespace), nil)
	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}

func TestConvertSharesNoMemoryWithTheCache(t *testing.T) {
	t.Parallel()

	deleted := metav1.NewTime(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	scope := unikornv1.ProviderScopeGlobal

	in := org(orgA)
	in.DeletionTimestamp = &deleted
	in.Spec.Domain = ptr.To("example.com")
	in.Spec.ProviderScope = &scope
	in.Spec.ProviderID = ptr.To("idp")
	in.Spec.ProviderOptions = &unikornv1.OrganizationProviderOptions{
		Google: &unikornv1.OrganizationProviderGoogleSpec{CustomerID: ptr.To("customer")},
	}

	before := in.DeepCopy()

	out := convert(in)
	require.NotNil(t, out.Metadata.DeletionTime)
	require.NotNil(t, out.Spec.Domain)
	require.NotNil(t, out.Spec.ProviderID)
	require.NotNil(t, out.Spec.GoogleCustomerID)

	*out.Metadata.DeletionTime = time.Time{}
	*out.Spec.Domain = "changed"
	*out.Spec.ProviderID = "changed"
	*out.Spec.GoogleCustomerID = "changed"

	require.Equal(t, before, in, "changing the converted result must not change the source object")
}
