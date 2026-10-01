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

package users

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/ids"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	internalTestNamespace = "identity"
	internalTestOrgID     = "c1111111-1111-4111-8111-111111111111"
	internalTestOrgNS     = "org-ns"
	internalTestUserID    = "u1111111-1111-4111-8111-111111111111"
	internalTestOrgUserID = "o1111111-1111-4111-8111-111111111111"
	internalTestSubject   = "alice@example.com"
)

// userListRecorder records the options of each User list that the code under
// test makes.  The User list holds every account on the deployment, so
// copying all of it to read a few Users is the cost to avoid.
type userListRecorder struct {
	lists []client.ListOptions
}

func (r *userListRecorder) funcs() interceptor.Funcs {
	return interceptor.Funcs{
		List: func(ctx context.Context, inner client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*unikornv1.UserList); ok {
				options := client.ListOptions{}
				options.ApplyOptions(opts)
				r.lists = append(r.lists, options)
			}

			return inner.List(ctx, list, opts...)
		},
	}
}

func newInternalTestClient(t *testing.T, r *userListRecorder) *Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	objects := []client.Object{
		&unikornv1.Organization{
			ObjectMeta: metav1.ObjectMeta{Namespace: internalTestNamespace, Name: internalTestOrgID},
			Status:     unikornv1.OrganizationStatus{Namespace: internalTestOrgNS},
		},
		&unikornv1.User{
			ObjectMeta: metav1.ObjectMeta{Namespace: internalTestNamespace, Name: internalTestUserID},
			Spec:       unikornv1.UserSpec{Subject: internalTestSubject, State: unikornv1.UserStateActive},
		},
		&unikornv1.OrganizationUser{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: internalTestOrgNS,
				Name:      internalTestOrgUserID,
				Labels: map[string]string{
					constants.OrganizationLabel: internalTestOrgID,
					constants.UserLabel:         internalTestUserID,
				},
			},
			Spec: unikornv1.OrganizationUserSpec{State: unikornv1.UserStateActive},
		},
	}

	// The spec.subject index stands in for the selectable field on the User
	// CRD. One fake serves as both the cache and the uncached reader.
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).WithInterceptorFuncs(r.funcs()).
		WithIndex(&unikornv1.User{}, "spec.subject", func(o client.Object) []string {
			user, ok := o.(*unikornv1.User)
			if !ok {
				return nil
			}

			return []string{user.Spec.Subject}
		}).
		Build()

	return New(c, c, internalTestNamespace, common.IssuerValue{URL: "https://identity.example.com"})
}

// TestGetGlobalUserAsksOnlyForTheSubject pins how the account lookup avoids
// copying every account: it asks for the subject's account only, with the
// spec.subject field selector. It reads without the cache, because the cache
// can still hold an account that was deleted.
func TestGetGlobalUserAsksOnlyForTheSubject(t *testing.T) {
	t.Parallel()

	r := &userListRecorder{}
	c := newInternalTestClient(t, r)

	user, err := c.getGlobalUser(t.Context(), internalTestSubject)
	require.NoError(t, err)
	require.Equal(t, internalTestUserID, user.Name)
	require.Len(t, r.lists, 1)
	require.Equal(t, "spec.subject="+internalTestSubject, r.lists[0].FieldSelector.String())
}

func TestListReadsUsersWithoutDeepCopy(t *testing.T) {
	t.Parallel()

	r := &userListRecorder{}
	c := newInternalTestClient(t, r)

	users, err := c.List(t.Context(), ids.MustParseOrganizationID(internalTestOrgID))
	require.NoError(t, err)
	require.Len(t, users, 1)
	require.Equal(t, internalTestSubject, users[0].Spec.Subject)
	require.Len(t, r.lists, 1)
	require.True(t, ptr.Deref(r.lists[0].UnsafeDisableDeepCopy, false))
}

// TestConvertSharesNoMemoryWithTheCache pins the rule that makes the no-copy
// User list safe: convert copies every value it takes from the User, so the
// response cannot change the cached object.
func TestConvertSharesNoMemoryWithTheCache(t *testing.T) {
	t.Parallel()

	lastAuthentication := metav1.NewTime(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))

	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{Namespace: internalTestNamespace, Name: internalTestUserID},
		Spec: unikornv1.UserSpec{
			Subject: internalTestSubject,
			Sessions: []unikornv1.UserSession{
				{ClientID: "client", LastAuthentication: &lastAuthentication},
			},
		},
	}

	orgUser := &unikornv1.OrganizationUser{
		ObjectMeta: metav1.ObjectMeta{Namespace: internalTestOrgNS, Name: internalTestOrgUserID},
	}

	before := user.DeepCopy()

	out := convert(orgUser, user, &unikornv1.GroupList{})
	require.NotNil(t, out.Status.LastActive)

	*out.Status.LastActive = time.Time{}

	require.Equal(t, before, user, "changing the converted result must not change the source object")
}
