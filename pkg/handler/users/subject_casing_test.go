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

package users_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// TestClient_CreateFoldsMixedCaseEmailSubject pins that the API cannot store a
// mixed-case email subject. The trusted-issuer path folds the email claim
// before it resolves a user, so a mixed-case record is invisible to it: the
// holder is admitted as never onboarded and deactivation cannot reach them.
func TestClient_CreateFoldsMixedCaseEmailSubject(t *testing.T) {
	t.Parallel()

	fixture := newUserTestFixture(t)
	ctx := newContext(t)

	request := &openapi.UserWrite{
		Spec: openapi.UserSpec{
			Subject: "Bob@Example.com",
			State:   openapi.Active,
		},
	}

	created, err := fixture.usersClient.Create(ctx, ids.MustParseOrganizationID(testOrgID), request)
	require.NoError(t, err)
	assert.Equal(t, userBobSubject, created.Spec.Subject)

	globalUsers := &unikornv1.UserList{}
	require.NoError(t, fixture.client.List(ctx, globalUsers, &client.ListOptions{Namespace: testNamespace}))
	require.Len(t, globalUsers.Items, 1)
	assert.Equal(t, userBobSubject, globalUsers.Items[0].Spec.Subject)
}

// TestClient_CreateReusesRecordDifferingOnlyByCase pins the create-path dedupe.
// Without a case-insensitive match, onboarding BOB@example.com beside an
// existing bob@example.com silently produces a second global record, and a
// subject lookup is first-match over an unordered list, so which one answers
// is not deterministic.
func TestClient_CreateReusesRecordDifferingOnlyByCase(t *testing.T) {
	t.Parallel()

	existing := newGlobalUser(userBobID, userBobSubject)
	fixture := newUserTestFixtureWithObjects(t, []client.Object{existing}, interceptor.Funcs{})
	ctx := newContext(t)

	request := &openapi.UserWrite{
		Spec: openapi.UserSpec{
			Subject: "BOB@example.com",
			State:   openapi.Active,
		},
	}

	_, err := fixture.usersClient.Create(ctx, ids.MustParseOrganizationID(testOrgID), request)
	require.NoError(t, err)

	globalUsers := &unikornv1.UserList{}
	require.NoError(t, fixture.client.List(ctx, globalUsers, &client.ListOptions{Namespace: testNamespace}))
	require.Len(t, globalUsers.Items, 1)
	assert.Equal(t, userBobID, globalUsers.Items[0].Name)
	assert.Equal(t, userBobSubject, globalUsers.Items[0].Spec.Subject)
}

// TestClient_RemovalMatchesAGroupSubjectStoredInAnotherCase pins the fail-open
// half of the fold.  removeFromGroup's own comment warns that a qualified match
// "would leave a legacy record behind, so the caller would still be an RBAC
// member of the group after a remove that reported success".  Folding the
// removal key introduced exactly that hazard keyed on case: a group entry
// written in another case survives a removal that reports success, and RBAC
// keeps conferring the group's roles.
func TestClient_RemovalMatchesAGroupSubjectStoredInAnotherCase(t *testing.T) {
	t.Parallel()

	// The stored entry carries the pre-migration case, as a directly written CR
	// or an unmigrated record would.
	storedEntry := unikornv1.GroupSubject{
		ID:     "Alice@Example.com",
		Email:  "Alice@Example.com",
		Issuer: testIssuerURL,
	}

	fixture := newUserTestFixtureWithObjects(t, []client.Object{
		newGlobalUser(userAliceID, userAliceSubject),
		newOrganizationUser(orgUserAliceID, userAliceID),
		newRadarGroup(groupAlphaID, []string{orgUserAliceID}, []unikornv1.GroupSubject{storedEntry}),
	}, interceptor.Funcs{})
	ctx := newContext(t)

	// Remove every group membership.
	_, err := fixture.usersClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), orgUserAliceID,
		&openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userAliceSubject,
				State:    openapi.Active,
				GroupIDs: openapi.GroupIDs{},
			},
		})
	require.NoError(t, err)

	group := &unikornv1.Group{}
	require.NoError(t, fixture.client.Get(ctx,
		client.ObjectKey{Namespace: testOrgNS, Name: groupAlphaID}, group))

	assert.Empty(t, group.Spec.UserIDs, "the userID half must be removed")
	assert.Empty(t, group.Spec.Subjects,
		"the subject half must be removed too, or the group keeps conferring its roles")
}

// The scenario the folds below guard: a User CR written directly with
// kubectl-unikorn bypasses the handlers, so its subject can still carry the
// pre-migration case while every group entry and every authenticated subject is
// folded.
const storedMixedCaseSubject = "Bob@Example.com"

// TestClient_CreateReusesRecordStoredInAnotherCase pins the stored side of the
// create-path dedupe. Folding only the incoming subject is not enough: an
// unfolded stored record would not match, and onboarding would add a second
// global record for the same principal.
func TestClient_CreateReusesRecordStoredInAnotherCase(t *testing.T) {
	t.Parallel()

	fixture := newUserTestFixtureWithObjects(t, []client.Object{
		newGlobalUser(userBobID, storedMixedCaseSubject),
	}, interceptor.Funcs{})
	ctx := newContext(t)

	_, err := fixture.usersClient.Create(ctx, ids.MustParseOrganizationID(testOrgID), &openapi.UserWrite{
		Spec: openapi.UserSpec{Subject: userBobSubject, State: openapi.Active},
	})
	require.NoError(t, err)

	globalUsers := &unikornv1.UserList{}
	require.NoError(t, fixture.client.List(ctx, globalUsers, &client.ListOptions{Namespace: testNamespace}))
	require.Len(t, globalUsers.Items, 1, "a record stored in another case must be reused, not duplicated")
	assert.Equal(t, userBobID, globalUsers.Items[0].Name)
}

// TestClient_MembershipWrittenFromAStoredSubjectIsFolded pins groupSubject. The
// membership subject is derived from the stored value, and RBAC compares it
// against a folded authenticated subject, so writing it unfolded confers
// nothing and leaves the grant resting on the deprecated userIDs list.
func TestClient_MembershipWrittenFromAStoredSubjectIsFolded(t *testing.T) {
	t.Parallel()

	fixture := newUserTestFixtureWithObjects(t, []client.Object{
		newGlobalUser(userBobID, storedMixedCaseSubject),
		newOrganizationUser(orgUserBobID, userBobID),
		newPlainGroup(groupAlphaID),
	}, interceptor.Funcs{})
	ctx := newContext(t)

	_, err := fixture.usersClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), orgUserBobID,
		&openapi.UserWrite{
			Spec: openapi.UserSpec{
				Subject:  userBobSubject,
				State:    openapi.Active,
				GroupIDs: openapi.GroupIDs{groupAlphaID},
			},
		})
	require.NoError(t, err)

	group := &unikornv1.Group{}
	require.NoError(t, fixture.client.Get(ctx,
		client.ObjectKey{Namespace: testOrgNS, Name: groupAlphaID}, group))

	require.Len(t, group.Spec.Subjects, 1)
	assert.Equal(t, userBobSubject, group.Spec.Subjects[0].ID)
	assert.Equal(t, userBobSubject, group.Spec.Subjects[0].Email)
}

// TestClient_ReportsMembershipForASubjectStoredInAnotherCase pins the response
// side. convert asks HasMemberByID the same question RBAC asks, so a stored
// subject in another case must still report the membership the folded group
// entry actually confers, or the API contradicts the effective authority.
func TestClient_ReportsMembershipForASubjectStoredInAnotherCase(t *testing.T) {
	t.Parallel()

	foldedEntry := unikornv1.GroupSubject{
		ID:     userBobSubject,
		Email:  userBobSubject,
		Issuer: testIssuerURL,
	}

	fixture := newUserTestFixtureWithObjects(t, []client.Object{
		newGlobalUser(userBobID, storedMixedCaseSubject),
		newOrganizationUser(orgUserBobID, userBobID),
		newRadarGroup(groupAlphaID, nil, []unikornv1.GroupSubject{foldedEntry}),
	}, interceptor.Funcs{})
	ctx := newContext(t)

	users, err := fixture.usersClient.List(ctx, ids.MustParseOrganizationID(testOrgID))
	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.Contains(t, users[0].Spec.GroupIDs, groupAlphaID,
		"a folded group entry confers the roles, so the API must report the membership")
}
