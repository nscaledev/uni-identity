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

// TestUpdateGroupResolvesAMixedCaseSubjectAtOwnIssuer pins the claim side of a
// group write.  The stored subject is in canonical form and the request carries
// it in another case.  The lookup must still resolve the organization user.  The
// entry keeps the case that the request supplied, because a group write stores a
// subject as supplied.
func TestUpdateGroupResolvesAMixedCaseSubjectAtOwnIssuer(t *testing.T) {
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
	assert.Equal(t, "Alice@Example.com", updatedGroup.Spec.Subjects[0].ID, "the entry is stored as supplied")
}
