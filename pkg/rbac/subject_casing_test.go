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

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

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

	// The group's only membership is a subject entry in the pre-migration case,
	// so no legacy userIDs fallback can supply the match.
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

// TestLegacyUserIDsMembershipResolvesAUserStoredInAnotherCase pins group-derived
// authority on the legacy path. A group that lists only UserIDs matches by
// resolving the subject to its organization user. That lookup must accept a
// stored subject in either case, or the migration takes the group's roles from
// a user whose claim carries the other case.
func TestLegacyUserIDsMembershipResolvesAUserStoredInAnotherCase(t *testing.T) {
	t.Parallel()

	f, c := setupTestEnvironment(t)

	const (
		userID    = "user-legacy-casing"
		orgUserID = "orguser-legacy-casing"
	)

	require.NoError(t, c.Create(t.Context(), &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      userID,
		},
		Spec: unikornv1.UserSpec{
			Subject: "Frank@Example.com",
			State:   unikornv1.UserStateActive,
		},
	}))

	require.NoError(t, c.Create(t.Context(), &unikornv1.OrganizationUser{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      orgUserID,
			Labels: map[string]string{
				constants.UserLabel: userID,
			},
		},
		Spec: unikornv1.OrganizationUserSpec{
			State: unikornv1.UserStateActive,
		},
	}))

	// No subject entries, so only the UserIDs half can supply the match.
	require.NoError(t, c.Create(t.Context(), &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      "group-legacy-casing",
		},
		Spec: unikornv1.GroupSpec{
			RoleIDs: []string{roleAdminID},
			UserIDs: []string{orgUserID},
		},
	}))

	for _, subject := range []string{"Frank@Example.com", "frank@example.com"} {
		acl := getACLForUser(t, f.rbac, subject)
		assert.NotNil(t, acl.Organization, "%s must receive the group's organization scopes", subject)
	}
}
