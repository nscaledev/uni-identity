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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/cachetest"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const benchOrganizations = 20000

// membershipEstate returns a user who is a member of 3 organizations, and the
// memberships of the whole estate.
func membershipEstate() (*unikornv1.User, []client.Object) {
	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{Namespace: "identity", Name: "member"},
		Spec:       unikornv1.UserSpec{Subject: "member@example.com", State: unikornv1.UserStateActive},
	}

	objects := []client.Object{user}

	for i := range benchOrganizations {
		for j := range 3 {
			who := fmt.Sprintf("other-%d-%d", i, j)
			if j == 0 && i < 3 {
				who = user.Name
			}

			objects = append(objects, &unikornv1.OrganizationUser{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: fmt.Sprintf("ns-org-%d", i),
					Name:      fmt.Sprintf("membership-%d-%d", i, j),
					Labels: map[string]string{
						constants.OrganizationLabel: fmt.Sprintf("org-%d", i),
						constants.UserLabel:         who,
					},
				},
				Spec: unikornv1.OrganizationUserSpec{State: unikornv1.UserStateActive},
			})
		}
	}

	return user, objects
}

// BenchmarkMembershipLookup measures the token check's membership lookup in an
// estate of 20,000 organizations with 3 members each, the user being a member
// of 3. "indexed" is the code as it is; "label" is the old cluster-wide
// organization-label selector, which the cache answers by walking every cached
// membership. The reader costs what the informer cache costs (see cachetest).
func BenchmarkMembershipLookup(b *testing.B) {
	user, objects := membershipEstate()

	cache, err := cachetest.NewReader(objects, userdb.Indexes()...)
	require.NoError(b, err)

	db := userdb.NewUserDatabase(cache, "identity")

	b.Run("indexed", func(b *testing.B) {
		b.ReportAllocs()

		for range b.N {
			if _, err := db.GetActiveOrganizationUser(b.Context(), "org-1", user); err != nil {
				b.Fatal(err)
			}

			if _, err := db.GetOrganizationIDsForUser(b.Context(), user); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("label", func(b *testing.B) {
		b.ReportAllocs()

		for range b.N {
			selector := labels.SelectorFromSet(labels.Set{constants.OrganizationLabel: "org-1", constants.UserLabel: user.Name})
			result := &unikornv1.OrganizationUserList{}

			if err := cache.List(b.Context(), result, &client.ListOptions{LabelSelector: selector}); err != nil {
				b.Fatal(err)
			}

			selector = labels.SelectorFromSet(labels.Set{constants.UserLabel: user.Name})
			result = &unikornv1.OrganizationUserList{}

			if err := cache.List(b.Context(), result, &client.ListOptions{LabelSelector: selector}); err != nil {
				b.Fatal(err)
			}
		}
	})
}
