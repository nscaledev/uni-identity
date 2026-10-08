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

package rbac_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestGroupSubjectMatchesAnEntryStoredInAnotherCase pins group-derived authority
// through the migration. A group entry can be stored in either case while stored
// subjects are migrated, and an authenticated subject can arrive in either case,
// so a membership must confer its roles in every combination. A near miss must
// still confer nothing.
func TestGroupSubjectMatchesAnEntryStoredInAnotherCase(t *testing.T) {
	t.Parallel()

	f, c := setupTestEnvironment(t)

	// The group's only membership is a subject entry in the pre-migration case.
	require.NoError(t, c.Create(t.Context(), &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      "group-casing",
		},
		Spec: unikornv1.GroupSpec{
			RoleIDs:  []string{roleAdminID},
			Subjects: []unikornv1.GroupSubject{{ID: "Dana@Example.com"}},
		},
	}))

	for _, subject := range []string{"Dana@Example.com", "dana@example.com", "DANA@EXAMPLE.COM"} {
		acl := getACLForUser(t, f.rbac, subject)
		assert.NotNil(t, acl.Organization, "%s must receive the group's organization scopes", subject)
	}

	acl := getACLForUser(t, f.rbac, "erin@example.com")
	assert.Nil(t, acl.Organization, "a different address must receive nothing")
}

// TestAnEmptySubjectIsInNoGroup pins that RBAC resolves membership the same way
// as the membership grant gates.  Membership lists are not validated against
// real records, so a group can hold a junk entry with an empty ID.
// GroupSpec.HasMemberByID says that an empty subject is a member of no group.
// If RBAC matched the junk entry, a principal with an empty subject would hold
// the group's roles while the grant gate reports that it is not a member.
func TestAnEmptySubjectIsInNoGroup(t *testing.T) {
	t.Parallel()

	f, c := setupTestEnvironment(t)

	require.NoError(t, c.Create(t.Context(), &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      "group-junk-entry",
		},
		Spec: unikornv1.GroupSpec{
			RoleIDs:  []string{roleAdminID},
			Subjects: []unikornv1.GroupSubject{{ID: ""}, {ID: " "}, {ID: "dana@example.com"}},
		},
	}))

	for _, subject := range []string{"", " "} {
		acl := getACLForUser(t, f.rbac, subject)
		assert.Nil(t, acl.Organization, "subject %q must receive nothing", subject)
	}

	// The group still confers its roles on a real member.
	acl := getACLForUser(t, f.rbac, "dana@example.com")
	assert.NotNil(t, acl.Organization, "a member must receive the group's organization scopes")
}

// TestImpersonatedActorSubjectIsFoldedBeforeBindingMatch pins the delegated
// actor.  A global role binding matches its subject exactly, and the chart
// accepts only canonical subjects, so a direct call matches with the folded
// claim.  The actor is the live userinfo.Sub, or else the creator annotation of
// a resource, which the creator principal annotation overrides.  Either can
// carry the case of a token or annotation from before the claim folded.  Without
// the fold, a delegated call loses the binding that the same user gets directly.
func TestImpersonatedActorSubjectIsFoldedBeforeBindingMatch(t *testing.T) {
	t.Parallel()

	const boundRoleID = "role-uni-binding-casing"

	boundRole := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      boundRoleID,
		},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Global: []unikornv1.RoleScope{
					{Name: "identity:organizations", Operations: []unikornv1.Operation{unikornv1.Read}},
				},
			},
		},
	}

	f := setupImpersonationEnvironmentWithBindings(t,
		[]unikornv1.RoleScope{
			{Name: "identity:organizations", Operations: []unikornv1.Operation{unikornv1.Read}},
		},
		rbac.Options{
			GlobalRoleBindings: rbac.GlobalRoleBindingsValue{
				{Issuer: constants.UNISentinel, Subject: userBobSubject, RoleIDs: []string{boundRoleID}},
			},
		},
		boundRole,
	)

	acl := impersonate(t, f, "Bob@Example.com")

	require.NotNil(t, acl.Global, "a mixed-case actor must still match its canonical binding")
	assert.Equal(t, openapi.AclEndpoints{
		{Name: "identity:organizations", Operations: []openapi.AclOperation{openapi.Read}},
	}, *acl.Global)
}
