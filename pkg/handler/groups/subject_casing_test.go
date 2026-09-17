/*
Copyright 2025 the Unikorn Authors.
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

package groups_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"k8s.io/utils/ptr"
)

// TestUpdateGroupFoldsMixedCaseSubjectAtOwnIssuer pins that a group write
// resolves and stores an email subject in its folded form.  Storage holds the
// folded subject, so a verbatim mixed-case ID failed to resolve the user and
// the caller saw "user with subject ... does not exist".
func TestUpdateGroupFoldsMixedCaseSubjectAtOwnIssuer(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createUserWithOrgMembership(t, userAliceID, userAliceSubject, orguserAliceID)
	f.createGroup(t)

	subjects := []openapi.Subject{
		{
			Id:     "Alice@Example.com",
			Issuer: testIssuerURL,
			Email:  ptr.To("Alice@Example.com"),
		},
	}

	err := f.groupsClient.Update(newContext(t), ids.MustParseOrganizationID(testOrgID), groupTestID, makeGroupUpdateRequest(&subjects, nil))
	require.NoError(t, err)

	updatedGroup := f.getGroup(t)

	require.Len(t, updatedGroup.Spec.Subjects, 1)
	assert.Equal(t, userAliceSubject, updatedGroup.Spec.Subjects[0].ID)
	assert.Equal(t, userAliceSubject, updatedGroup.Spec.Subjects[0].Email)

	require.Len(t, updatedGroup.Spec.UserIDs, 1, "a folded subject must still resolve to its organization user")
	assert.Equal(t, orguserAliceID, updatedGroup.Spec.UserIDs[0])
}

// TestUpdateGroupFoldsMixedCaseSubjectAtExternalIssuer pins the storage fold on
// its own.  An external subject gets no user lookup, so an unfolded ID would
// reach storage, and RBAC matches a group subject against a folded authenticated
// subject: the group would silently confer nothing.
func TestUpdateGroupFoldsMixedCaseSubjectAtExternalIssuer(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createGroup(t)

	subjects := []openapi.Subject{
		{
			Id:     "External-User@GitHub.com",
			Issuer: "https://github.com",
			Email:  ptr.To("External-User@GitHub.com"),
		},
	}

	err := f.groupsClient.Update(newContext(t), ids.MustParseOrganizationID(testOrgID), groupTestID, makeGroupUpdateRequest(&subjects, nil))
	require.NoError(t, err)

	updatedGroup := f.getGroup(t)

	require.Len(t, updatedGroup.Spec.Subjects, 1)
	assert.Equal(t, "external-user@github.com", updatedGroup.Spec.Subjects[0].ID)
	assert.Equal(t, "external-user@github.com", updatedGroup.Spec.Subjects[0].Email)
}

// TestUpdateGroupCollapsesCaseVariantSubjectsInOneRequest pins that the fold
// happens before deduplication.  Two spellings of one address in a single
// request must not become two entries: uni-auth0 compares a whole GroupSubject
// struct, so a duplicate entry is one the normal removal path leaves behind.
func TestUpdateGroupCollapsesCaseVariantSubjectsInOneRequest(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createUserWithOrgMembership(t, userAliceID, userAliceSubject, orguserAliceID)
	f.createGroup(t)

	subjects := []openapi.Subject{
		{Id: "Alice@Example.com", Issuer: testIssuerURL, Email: ptr.To("Alice@Example.com")},
		{Id: userAliceSubject, Issuer: testIssuerURL, Email: ptr.To(userAliceSubject)},
	}

	err := f.groupsClient.Update(newContext(t), ids.MustParseOrganizationID(testOrgID), groupTestID, makeGroupUpdateRequest(&subjects, nil))
	require.NoError(t, err)

	updatedGroup := f.getGroup(t)

	require.Len(t, updatedGroup.Spec.Subjects, 1, "two spellings of one address must collapse to one entry")
	assert.Equal(t, userAliceSubject, updatedGroup.Spec.Subjects[0].ID)
}

// TestUpdateGroupFoldsSubjectDerivedFromUserID pins the other direction of the
// group write.  A User CR written directly with kubectl-unikorn bypasses the
// handlers and can still hold a mixed-case subject, and deriving a membership
// from a userID copies that subject into the group.  RBAC compares the stored
// group subject against a folded authenticated subject, so an unfolded copy
// confers nothing and leaves the grant resting on the deprecated userIDs
// fallback.
func TestUpdateGroupFoldsSubjectDerivedFromUserID(t *testing.T) {
	t.Parallel()

	const (
		mixedCaseUserID    = "user-mixed"
		mixedCaseOrgUserID = "orguser-mixed"
		mixedCaseSubject   = "Mixed@Example.com"
		foldedSubject      = "mixed@example.com"
	)

	f := setupGroupTestFixture(t)
	f.createUserWithOrgMembership(t, mixedCaseUserID, mixedCaseSubject, mixedCaseOrgUserID)
	f.createGroup(t)

	userIDs := openapi.StringList{mixedCaseOrgUserID}

	err := f.groupsClient.Update(newContext(t), ids.MustParseOrganizationID(testOrgID), groupTestID, makeGroupUpdateRequest(nil, &userIDs))
	require.NoError(t, err)

	updatedGroup := f.getGroup(t)

	require.Len(t, updatedGroup.Spec.Subjects, 1)
	assert.Equal(t, foldedSubject, updatedGroup.Spec.Subjects[0].ID)
	assert.Equal(t, foldedSubject, updatedGroup.Spec.Subjects[0].Email)
}

// TestUpdateGroupResolvesAUserStoredInAnotherCase pins the stored side of
// findUserBySubject. The incoming subject is folded, so an unfolded stored
// record would not resolve and the caller would be told the user does not
// exist.
func TestUpdateGroupResolvesAUserStoredInAnotherCase(t *testing.T) {
	t.Parallel()

	const (
		storedUserID    = "user-stored-case"
		storedOrgUserID = "orguser-stored-case"
		storedSubject   = "Alice@Example.com"
	)

	f := setupGroupTestFixture(t)
	f.createUserWithOrgMembership(t, storedUserID, storedSubject, storedOrgUserID)
	f.createGroup(t)

	subjects := []openapi.Subject{
		{Id: userAliceSubject, Issuer: testIssuerURL, Email: ptr.To(userAliceSubject)},
	}

	err := f.groupsClient.Update(newContext(t), ids.MustParseOrganizationID(testOrgID), groupTestID, makeGroupUpdateRequest(&subjects, nil))
	require.NoError(t, err, "a folded subject must resolve a record stored in another case")

	updatedGroup := f.getGroup(t)
	require.Len(t, updatedGroup.Spec.UserIDs, 1)
	assert.Equal(t, storedOrgUserID, updatedGroup.Spec.UserIDs[0])
}
