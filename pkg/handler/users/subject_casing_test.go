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

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// TestClient_CreateFoldsMixedCaseEmailSubject pins that the API stores a new
// record in canonical form, as every other writer does.  A record in another
// case beside a canonical record for the same address is a case-variant pair,
// and the lookups then resolve the address by the case of the claim.
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

// TestClient_MembershipWrittenFromAStoredSubjectIsFolded pins groupSubject.  The
// entry comes from the stored subject, which can be in another case when
// kubectl-unikorn or an older writer stored it.  The entry must still carry the
// canonical form, as the uni-auth0 member sync writes it, so that both writers
// store one entry.
func TestClient_MembershipWrittenFromAStoredSubjectIsFolded(t *testing.T) {
	t.Parallel()

	fixture := newUserTestFixtureWithObjects(t, []client.Object{
		newGlobalUser(userBobID, storedMixedCaseSubject),
		newOrganizationUser(orgUserBobID, userBobID),
		newPlainGroup(),
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
	require.NoError(t, fixture.client.Get(ctx, client.ObjectKey{Namespace: testOrgNS, Name: groupAlphaID}, group))

	require.Len(t, group.Spec.Subjects, 1)
	assert.Equal(t, userBobSubject, group.Spec.Subjects[0].ID)
	assert.Equal(t, userBobSubject, group.Spec.Subjects[0].Email)
}

// TestClient_CreateReusesRecordDifferingOnlyByCase pins the create-path dedupe.
// If the match is exact, onboarding BOB@example.com beside bob@example.com adds
// a second global record.  Two records for one principal make every later fold
// of that subject ambiguous.
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

// TestClient_RemovalMatchesAGroupSubjectStoredInAnotherCase pins the removal
// side.  A remove must find a group entry that is stored in another case.  If it
// misses the entry, the remove reports success, the entry stays, and RBAC keeps
// conferring the group's roles.  removeFromGroup's own comment names the same
// hazard for an issuer-qualified match.
func TestClient_RemovalMatchesAGroupSubjectStoredInAnotherCase(t *testing.T) {
	t.Parallel()

	// The stored entry keeps the case that its writer supplied, as an entry
	// that the data migration has not folded yet does.
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

// storedMixedCaseSubject is a stored subject that the data migration has not
// folded yet.  The request, and a group entry written from a claim, can already
// carry the canonical form.
const storedMixedCaseSubject = "Bob@Example.com"

// TestClient_CreateReusesRecordStoredInAnotherCase pins the stored side of the
// create-path dedupe.  A request can carry the canonical form of a subject that
// is stored in another case.  If the dedupe misses that record, onboarding adds
// a second global record for the same principal.
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

// TestClient_ReportsMembershipForASubjectStoredInAnotherCase pins the response
// side.  convert asks HasMemberByID the same question that RBAC asks.  A folded
// group entry confers its roles on a user stored in another case, so the API
// must report that membership too.
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

// TestClient_CreateRefusesASubjectThatFoldsOntoTwoRecords pins the ambiguity
// rule on the create path. The subject matches neither record exactly, so the
// dedupe cannot tell which one to reuse. Treating it as new adds a third record
// for the same address, and every later lookup of it stays ambiguous.
func TestClient_CreateRefusesASubjectThatFoldsOntoTwoRecords(t *testing.T) {
	t.Parallel()

	fixture := newUserTestFixtureWithObjects(t, []client.Object{
		newGlobalUser(userBobID, storedMixedCaseSubject),
		newGlobalUser("user-bob-twin", "BOB@example.com"),
	}, interceptor.Funcs{})
	ctx := newContext(t)

	_, err := fixture.usersClient.Create(ctx, ids.MustParseOrganizationID(testOrgID), &openapi.UserWrite{
		Spec: openapi.UserSpec{Subject: userBobSubject, State: openapi.Active},
	})
	require.ErrorIs(t, err, coreerrors.ErrConsistency)

	globalUsers := &unikornv1.UserList{}
	require.NoError(t, fixture.client.List(ctx, globalUsers, &client.ListOptions{Namespace: testNamespace}))
	assert.Len(t, globalUsers.Items, 2, "an ambiguous create must not add a record")
}

// TestClient_CreateRefusesASubjectThatIsNotABareAddress pins that the create
// path stores only a bare address.  net/mail also accepts a display name or
// angle brackets.  A sign-in claim carries the bare address, and no lookup
// matches it against such a record, so nobody can sign in to it.  The record
// also escapes the dedupe, so each new display name adds another global record
// beside the real one.
func TestClient_CreateRefusesASubjectThatIsNotABareAddress(t *testing.T) {
	t.Parallel()

	for _, subject := range []string{"Bob <bob@example.com>", "<bob@example.com>"} {
		t.Run(subject, func(t *testing.T) {
			t.Parallel()

			fixture := newUserTestFixtureWithObjects(t, []client.Object{
				newGlobalUser(userBobID, userBobSubject),
			}, interceptor.Funcs{})
			ctx := newContext(t)

			_, err := fixture.usersClient.Create(ctx, ids.MustParseOrganizationID(testOrgID), &openapi.UserWrite{
				Spec: openapi.UserSpec{Subject: subject, State: openapi.Active},
			})
			require.True(t, errors.IsBadRequest(err), "got %v", err)

			globalUsers := &unikornv1.UserList{}
			require.NoError(t, fixture.client.List(ctx, globalUsers, &client.ListOptions{Namespace: testNamespace}))
			assert.Len(t, globalUsers.Items, 1, "a refused create must not add a record")
		})
	}
}
