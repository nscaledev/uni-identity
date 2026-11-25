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

package main

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/identity/hack/ci/internal/fixturelib"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/users"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/userdb"
	"github.com/unikorn-cloud/identity/pkg/userdb/userdbtest"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	testNamespace = "identity"
	testIssuer    = "https://identity.example.invalid"
	adminRole     = "role-admin"
	userRole      = "role-user"
)

// threeOrgs is two users in one organization, one in two and one in all three.
func threeOrgs() shape {
	return shape{
		orgs: 3, groupsPerOrg: 2, projectsPerOrg: 3, tokens: 4,
		users: []userClass{{1, 2}, {2, 1}, {3, 1}},
	}
}

func testParams() directParams {
	return directParams{namespace: testNamespace, issuer: testIssuer, adminRoleID: adminRole, userRoleID: userRole}
}

func mustBuild(t *testing.T) (records, []user) {
	t.Helper()

	us := plan(threeOrgs())

	r, err := buildRecords(threeOrgs(), us, testParams())
	require.NoError(t, err)

	return r, us
}

func fakeMinter(_ context.Context, name, organizationID string) (string, time.Time, error) {
	return "token-" + organizationID + "-" + name, time.Unix(1_000_000, 0), nil
}

func newTestClient() client.Client {
	// userdb reads through field indexes, so the fake carries them.
	return userdbtest.NewClientBuilder(fixturelib.NewClientScheme()).
		WithStatusSubresource(&unikornv1.Organization{}).
		Build()
}

// An organization looks as the organization controller leaves it, and what
// the request path reads of it (its namespace, in status) is set.
func TestOrganizations(t *testing.T) {
	t.Parallel()

	r, _ := mustBuild(t)

	require.Len(t, r.organizations, 3)
	require.Len(t, r.namespaces, 3)

	names := map[string]bool{}

	for i := range r.organizations {
		org := &r.organizations[i]
		ns := &r.namespaces[i]

		names[org.Name] = true

		require.Equal(t, testNamespace, org.Namespace)
		require.Contains(t, org.Finalizers, constants.Finalizer)
		require.NotEmpty(t, org.Labels[constants.NameLabel])

		// The namespace the status names exists, labelled as the controller
		// labels it, so the controller finds it rather than making another.
		require.Equal(t, ns.Name, org.Status.Namespace)

		want, err := org.ResourceLabels()
		require.NoError(t, err)
		require.Equal(t, map[string]string(want), ns.Labels)

		available, err := unikornv1core.GetAvailableCondition(org)
		require.NoError(t, err)
		require.Equal(t, corev1.ConditionTrue, available.Status)
		require.Equal(t, unikornv1core.ConditionReasonProvisioned, available.Reason)

		healthy, err := unikornv1core.GetHealthyCondition(org)
		require.NoError(t, err)
		require.Equal(t, corev1.ConditionTrue, healthy.Status)
	}

	require.Len(t, names, 3, "names are distinct")
}

// Groups, projects and the service account sit in the organization's
// namespace under its label, where rbac and the handlers list them.
func TestOrganizationContents(t *testing.T) {
	t.Parallel()

	r, _ := mustBuild(t)

	require.Len(t, r.groups, 6)
	require.Len(t, r.projects, 9)
	require.Len(t, r.serviceAccounts, 3)

	for i, org := range r.organizations {
		inOrg := func(m client.Object) {
			require.Equal(t, org.Status.Namespace, m.GetNamespace())
			require.Equal(t, org.Name, m.GetLabels()[constants.OrganizationLabel])
			require.NotEmpty(t, m.GetLabels()[constants.NameLabel])
			require.Equal(t, loadCreator, m.GetAnnotations()[constants.CreatorAnnotation])
		}

		groups := r.groups[i*2 : i*2+2]
		sa := &r.serviceAccounts[i]

		inOrg(sa)

		require.Equal(t, []string{adminRole}, groups[0].Spec.RoleIDs)
		require.Equal(t, []string{userRole}, groups[1].Spec.RoleIDs)
		require.Equal(t, []string{sa.Name}, groups[0].Spec.ServiceAccountIDs)

		for j := range groups {
			inOrg(&groups[j])
		}

		for j := range 3 {
			project := &r.projects[i*3+j]

			inOrg(project)
			require.Len(t, project.Spec.GroupIDs, 2)

			for _, id := range project.Spec.GroupIDs {
				require.True(t, slices.ContainsFunc(groups, func(g unikornv1.Group) bool { return g.Name == id }), "project group %s exists", id)
			}
		}
	}
}

// Users and memberships take the names and labels the users handler gives
// them, so lookups by subject and by label find them.
func TestUsers(t *testing.T) {
	t.Parallel()

	r, us := mustBuild(t)

	require.Len(t, r.users, len(us))

	memberships := 0
	for _, u := range us {
		memberships += len(u.orgs)
	}

	require.Len(t, r.organizationUsers, memberships)
	require.Equal(t, 7, memberships, "2 users in 1 organization, 1 in 2, 1 in 3")

	for i := range r.users {
		user := &r.users[i]

		require.Equal(t, testNamespace, user.Namespace)
		require.Equal(t, unikornv1.GlobalUserName(us[i].email), user.Name)
		require.Equal(t, user.Name, user.Labels[unikornv1.UserSubjectIDLabel])
		require.Equal(t, unikornv1.NormalizeSubject(us[i].email), user.Spec.Subject)
		require.Equal(t, unikornv1.UserStateActive, user.Spec.State)
	}

	for i := range r.organizationUsers {
		ou := &r.organizationUsers[i]

		orgID, err := ids.ParseOrganizationID(ou.Labels[constants.OrganizationLabel])
		require.NoError(t, err)
		require.Equal(t, users.OrganizationUserName(orgID, ou.Labels[constants.UserLabel]), ou.Name)
		require.Equal(t, unikornv1.UserStateActive, ou.Spec.State)
	}
}

// Group membership is recorded as subjects (what rbac reads) and as
// organization user IDs, for every organization a user belongs to.
func TestGroupMembership(t *testing.T) {
	t.Parallel()

	r, us := mustBuild(t)

	for _, u := range us {
		userName := unikornv1.GlobalUserName(u.email)

		for index, org := range r.organizations {
			userGroup := &r.groups[index*2+1]
			adminGroup := &r.groups[index*2]

			expected := slices.Contains(u.orgs, index)

			require.Equal(t, expected, userGroup.Spec.HasMemberByID(u.email), "%s in organization %d", u.email, index)
			require.False(t, adminGroup.Spec.HasMemberByID(u.email))

			orgID, err := ids.ParseOrganizationID(org.Name)
			require.NoError(t, err)
			require.Equal(t, expected, slices.Contains(userGroup.Spec.UserIDs, users.OrganizationUserName(orgID, userName)))
		}
	}

	for _, subject := range r.groups[1].Spec.Subjects {
		require.Equal(t, testIssuer, subject.Issuer)
		require.Equal(t, subject.ID, subject.Email)
	}
}

// Applied to a cluster, the records are found by identity's own user
// database, and by the label and namespace reads of the request path.
func TestApplyAndRead(t *testing.T) {
	t.Parallel()

	r, us := mustBuild(t)
	ctx := t.Context()
	k8s := newTestClient()

	require.NoError(t, mintTokens(ctx, &r, fakeMinter))
	require.NoError(t, apply(ctx, k8s, &r))

	// A rerun converges on the same records, with the new service account
	// tokens.
	again, _ := mustBuild(t)

	require.NoError(t, mintTokens(ctx, &again, func(_ context.Context, name, organizationID string) (string, time.Time, error) {
		return "second-" + organizationID + "-" + name, time.Unix(2_000_000, 0), nil
	}))
	require.NoError(t, apply(ctx, k8s, &again))
	r = again

	db := userdb.NewUserDatabase(k8s, testNamespace)

	for _, u := range us {
		user, err := db.GetActiveUser(ctx, u.email)
		require.NoError(t, err)

		orgIDs, err := db.GetOrganizationIDs(ctx, u.email)
		require.NoError(t, err)
		require.Len(t, orgIDs, len(u.orgs))

		for _, orgID := range orgIDs {
			_, err := db.GetActiveOrganizationUser(ctx, orgID, user)
			require.NoError(t, err)
		}
	}

	for i := range r.organizations {
		org := &unikornv1.Organization{}
		require.NoError(t, k8s.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: r.organizations[i].Name}, org))
		require.Equal(t, r.organizations[i].Status.Namespace, org.Status.Namespace, "status written")
		require.NotEmpty(t, org.Status.Conditions)

		sa, err := db.GetServiceAccount(ctx, org.Name, r.serviceAccounts[i].Name)
		require.NoError(t, err)
		require.Equal(t, "second-"+org.Name+"-"+sa.Name, sa.Spec.AccessToken)

		var projects unikornv1.ProjectList

		selector := labels.SelectorFromSet(labels.Set{constants.OrganizationLabel: org.Name})
		require.NoError(t, k8s.List(ctx, &projects, &client.ListOptions{LabelSelector: selector}))
		require.Len(t, projects.Items, 3)

		var groups unikornv1.GroupList

		require.NoError(t, k8s.List(ctx, &groups, client.InNamespace(org.Status.Namespace)))
		require.Len(t, groups.Items, 2)
	}
}

// The summary the token step reads lines up with the records.
func TestSummary(t *testing.T) {
	t.Parallel()

	r, _ := mustBuild(t)

	require.NoError(t, mintTokens(t.Context(), &r, fakeMinter))

	orgs := r.orgs()
	require.Len(t, orgs, 3)

	for i, o := range orgs {
		require.Equal(t, r.organizations[i].Name, o.id)
		require.Equal(t, r.serviceAccounts[i].Spec.AccessToken, o.saToken)
		require.NotEmpty(t, o.saToken)
		require.Len(t, o.groupIDs, 2)
		require.Equal(t, r.groups[i*2].Name, o.groupIDs[0])
	}
}

// The named datasets are sized as documented.
func TestShapes(t *testing.T) {
	t.Parallel()

	for name, orgs := range map[string]int{"small": 20, "medium": 2000, "web": 20000} {
		shp, ok := shapeFor(name)
		require.True(t, ok)
		require.Equal(t, orgs, shp.orgs)

		us := plan(shp)

		// Users about equal organizations, except in the small dataset.
		if name != "small" {
			require.Len(t, us, orgs)
			require.Equal(t, orgs, shp.tokens, "one token per user")
		}

		for _, u := range us {
			seen := map[int]bool{}

			for _, index := range u.orgs {
				require.Less(t, index, orgs)
				require.False(t, seen[index], "a user joins an organization once")

				seen[index] = true
			}
		}
	}

	_, ok := shapeFor("large")
	require.False(t, ok)
}
