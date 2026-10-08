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

// TestUpdateGroupResolvesAUserStoredInAnotherCase pins the stored side of
// findUserBySubject.  A request can carry the canonical form of a subject that
// is stored in another case.  If the lookup misses that record, the request
// fails with an error that says the user does not exist.
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

// TestUpdateGroupFoldsMixedCaseSubjectAtOwnIssuer pins both sides of a group
// write.  The request carries the stored subject in another case.  The lookup
// must still resolve the organization user, and the entry must be stored in
// canonical form.
func TestUpdateGroupFoldsMixedCaseSubjectAtOwnIssuer(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createUserWithOrgMembership(t, userAliceID, userAliceSubject, orguserAliceID)
	f.createGroup(t)

	subjects := []openapi.Subject{
		{Id: "Alice@Example.com", Issuer: testIssuerURL, Email: ptr.To("Alice@Example.com")},
	}

	err := f.groupsClient.Update(newContext(t), ids.MustParseOrganizationID(testOrgID), groupTestID, makeGroupUpdateRequest(&subjects, nil))
	require.NoError(t, err)

	updatedGroup := f.getGroup(t)

	require.Len(t, updatedGroup.Spec.UserIDs, 1, "a mixed-case subject must resolve its organization user")
	assert.Equal(t, orguserAliceID, updatedGroup.Spec.UserIDs[0])
	require.Len(t, updatedGroup.Spec.Subjects, 1)
	assert.Equal(t, userAliceSubject, updatedGroup.Spec.Subjects[0].ID)
	assert.Equal(t, userAliceSubject, updatedGroup.Spec.Subjects[0].Email)
}

// TestUpdateGroupFoldsMixedCaseSubjectAtExternalIssuer pins the storage fold on
// its own.  An external subject gets no user lookup, so generateSubjects is the
// only place that folds it.
func TestUpdateGroupFoldsMixedCaseSubjectAtExternalIssuer(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createGroup(t)

	subjects := []openapi.Subject{
		{Id: "External-User@GitHub.com", Issuer: "https://github.com", Email: ptr.To("External-User@GitHub.com")},
	}

	err := f.groupsClient.Update(newContext(t), ids.MustParseOrganizationID(testOrgID), groupTestID, makeGroupUpdateRequest(&subjects, nil))
	require.NoError(t, err)

	updatedGroup := f.getGroup(t)

	require.Len(t, updatedGroup.Spec.Subjects, 1)
	assert.Equal(t, "external-user@github.com", updatedGroup.Spec.Subjects[0].ID)
	assert.Equal(t, "external-user@github.com", updatedGroup.Spec.Subjects[0].Email)
}

// TestUpdateGroupKeepsTheCaseOfAnOpaqueExternalID pins the limit of the fold.
// An external issuer can give an opaque ID in which case is significant, and
// the claim that RBAC matches it against keeps that case.  Only the email,
// which is an address, folds.
func TestUpdateGroupKeepsTheCaseOfAnOpaqueExternalID(t *testing.T) {
	t.Parallel()

	const opaqueID = "AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ"

	f := setupGroupTestFixture(t)
	f.createGroup(t)

	subjects := []openapi.Subject{
		{Id: opaqueID, Issuer: "https://login.example.com", Email: ptr.To("External-User@Example.com")},
	}

	err := f.groupsClient.Update(newContext(t), ids.MustParseOrganizationID(testOrgID), groupTestID, makeGroupUpdateRequest(&subjects, nil))
	require.NoError(t, err)

	updatedGroup := f.getGroup(t)

	require.Len(t, updatedGroup.Spec.Subjects, 1)
	assert.Equal(t, opaqueID, updatedGroup.Spec.Subjects[0].ID)
	assert.Equal(t, "external-user@example.com", updatedGroup.Spec.Subjects[0].Email)
}

// TestUpdateGroupCollapsesCaseVariantSubjectsInOneRequest pins that the fold
// comes before deduplication.  Two spellings of one address in a request name
// one principal, so they must become one entry.
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

// TestUpdateGroupFoldsSubjectDerivedFromUserID pins the entry that a group
// write builds from a user ID.  It copies the stored subject, which can be in
// another case when kubectl-unikorn or an older writer stored it.  The entry
// must still carry the canonical form, as the users handler and the uni-auth0
// member sync write it.
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
