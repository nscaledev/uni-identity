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

// recorder records the options of each read that the code under test makes
// through one reader.
type recorder struct {
	lists []client.ListOptions
	gets  []client.GetOptions

	// organizationGets holds the options of the gets for Organizations.
	organizationGets []client.GetOptions
}

func (r *recorder) reads() int {
	return len(r.lists) + len(r.gets)
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

			if _, ok := obj.(*unikornv1.Organization); ok {
				r.organizationGets = append(r.organizationGets, options)
			}

			return inner.Get(ctx, key, obj, opts...)
		},
	}
}

// newTestClients returns a direct client and a cache over the same objects.
// Each records its reads in its own recorder.
func newTestClients(t *testing.T, direct, cached *recorder, objects ...client.Object) (client.Client, client.Reader) {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	store := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

	return interceptor.NewClient(store, direct.funcs()), interceptor.NewClient(store, cached.funcs())
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

// The global branch returns every organization, so it reads the cache, in the
// identity namespace and without deep copies.
func TestListGlobalBranchReadsTheCache(t *testing.T) {
	t.Parallel()

	direct, cached := &recorder{}, &recorder{}
	k8s, cache := newTestClients(t, direct, cached, org(orgB), org(orgA))

	out, err := New(k8s, testNamespace).List(globalReadContext(t), cache, nil, nil)
	require.NoError(t, err)
	require.Len(t, out, 2)
	require.Equal(t, orgA, out[0].Metadata.Id)
	require.Equal(t, orgB, out[1].Metadata.Id)

	require.Zero(t, direct.reads())
	require.Len(t, cached.lists, 1)
	require.Equal(t, testNamespace, cached.lists[0].Namespace)
	require.True(t, ptr.Deref(cached.lists[0].UnsafeDisableDeepCopy, false))
}

// The membership branch reads directly, so a removed membership takes effect
// at once.
func TestListMembershipBranchReadsDirectly(t *testing.T) {
	t.Parallel()

	direct, cached := &recorder{}, &recorder{}
	k8s, cache := newTestClients(t, direct, cached, org(orgA), org(orgB), user(), membership("m1", orgB), membership("m2", orgB))

	out, err := New(k8s, testNamespace).List(memberContext(t), cache, userdb.NewUserDatabase(k8s, testNamespace), nil)
	require.NoError(t, err)
	require.Len(t, out, 2, "duplicate memberships still return the organization twice")
	require.Equal(t, orgB, out[0].Metadata.Id)

	require.Zero(t, cached.reads())
	require.Len(t, direct.organizationGets, 2, "one organization read per membership")

	for _, options := range direct.organizationGets {
		require.Nil(t, options.UnsafeDisableDeepCopy)
	}
}

// An email filter takes the membership branch even for a global reader.
func TestListEmailFilterReadsDirectly(t *testing.T) {
	t.Parallel()

	direct, cached := &recorder{}, &recorder{}
	k8s, cache := newTestClients(t, direct, cached, org(orgA), user(), membership("m1", orgA))

	ctx := authorization.NewContext(globalReadContext(t), &authorization.Info{Userinfo: &openapi.Userinfo{Sub: subject, Email: ptr.To(subject)}})

	out, err := New(k8s, testNamespace).List(ctx, cache, userdb.NewUserDatabase(k8s, testNamespace), ptr.To(subject))
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Equal(t, orgA, out[0].Metadata.Id)
	require.Zero(t, cached.reads())
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

	_, err := New(k8s, testNamespace).List(memberContext(t), nil, userdb.NewUserDatabase(k8s, testNamespace), nil)
	require.Error(t, err)
	require.ErrorIs(t, err, errBoom)
	require.NotErrorIs(t, err, coreerrors.ErrConsistency)
}

func TestListMembershipBranchSortsByID(t *testing.T) {
	t.Parallel()

	k8s, cache := newTestClients(t, &recorder{}, &recorder{}, org(orgA), org(orgB), user(), membership("m1", orgB), membership("m2", orgA))

	out, err := New(k8s, testNamespace).List(memberContext(t), cache, userdb.NewUserDatabase(k8s, testNamespace), nil)
	require.NoError(t, err)
	require.Len(t, out, 2)
	require.Equal(t, orgA, out[0].Metadata.Id)
	require.Equal(t, orgB, out[1].Metadata.Id)
}

func TestListMembershipBranchDanglingMembershipIsInconsistent(t *testing.T) {
	t.Parallel()

	k8s, cache := newTestClients(t, &recorder{}, &recorder{}, user(), membership("m1", orgA))

	_, err := New(k8s, testNamespace).List(memberContext(t), cache, userdb.NewUserDatabase(k8s, testNamespace), nil)
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
