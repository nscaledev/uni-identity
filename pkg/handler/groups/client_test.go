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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/groups"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace  = "test-namespace"
	testOrgID      = "00000000-0000-4000-8000-000000000001"
	testOrgNS      = "test-org-ns"
	testIssuerURL  = "https://identity.unikorn-cloud.org"
	testIssuerHost = "identity.unikorn-cloud.org"

	userAliceSubject = "alice@example.com"
	userAliceID      = "user-alice"
	orguserAliceID   = "orguser-alice"

	userBobSubject = "bob@example.com"
	userBobID      = "user-bob"
	orguserBobID   = "orguser-bob"

	groupTestID = "group-test"
)

// newContext creates a context with required authorization and principal info.
func newContext(t *testing.T) context.Context {
	t.Helper()

	ctx := authorization.NewContext(t.Context(), &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: "test-subject",
		},
	})

	ctx = principal.NewContext(ctx, &principal.Principal{
		Actor: "test-principal",
	})

	return ctx
}

// setupTestClient creates a fake Kubernetes client with basic organization setup.
func setupTestClient(t *testing.T) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Create organization
	organization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testOrgID,
		},
		Spec: unikornv1.OrganizationSpec{},
		Status: unikornv1.OrganizationStatus{
			Namespace: testOrgNS,
		},
	}

	require.NoError(t, c.Create(t.Context(), organization))
	require.NoError(t, c.Update(t.Context(), organization)) // Update status

	return c
}

// createUserWithoutOrgMembership creates a User without an OrganizationUser.
func (f *groupTestFixture) createUserWithoutOrgMembership(t *testing.T, userID, subject string) {
	t.Helper()

	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      userID,
		},
		Spec: unikornv1.UserSpec{
			Subject: subject,
			State:   unikornv1.UserStateActive,
		},
	}
	require.NoError(t, f.client.Create(newContext(t), user))
}

// groupTestFixture holds common test setup.
type groupTestFixture struct {
	client       client.Client
	groupsClient *groups.Client
	issuer       handlercommon.IssuerValue
}

// setupGroupTestFixture creates a test fixture with all common setup.
func setupGroupTestFixture(t *testing.T) *groupTestFixture {
	t.Helper()

	c := setupTestClient(t)

	issuer := handlercommon.IssuerValue{
		URL:      testIssuerURL,
		Hostname: testIssuerHost,
	}

	return &groupTestFixture{
		client:       c,
		groupsClient: groups.New(c, testNamespace, issuer),
		issuer:       issuer,
	}
}

// createGroup creates a test group.
func (f *groupTestFixture) createGroup(t *testing.T) {
	t.Helper()

	group := &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      groupTestID,
			Labels: map[string]string{
				constants.OrganizationLabel: testOrgID,
			},
		},
		Spec: unikornv1.GroupSpec{
			RoleIDs: []string{},
		},
	}
	require.NoError(t, f.client.Create(newContext(t), group))
}

// getGroup fetches the test group.
func (f *groupTestFixture) getGroup(t *testing.T) *unikornv1.Group {
	t.Helper()

	var group unikornv1.Group
	err := f.client.Get(newContext(t), client.ObjectKey{Namespace: testOrgNS, Name: groupTestID}, &group)
	require.NoError(t, err)

	return &group
}

// createUserWithOrgMembership creates a User and OrganizationUser pair.
func (f *groupTestFixture) createUserWithOrgMembership(t *testing.T, userID, subject, orgUserID string) {
	t.Helper()

	ctx := newContext(t)

	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      userID,
		},
		Spec: unikornv1.UserSpec{
			Subject: subject,
			State:   unikornv1.UserStateActive,
		},
	}
	require.NoError(t, f.client.Create(ctx, user))

	orgUser := &unikornv1.OrganizationUser{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      orgUserID,
			Labels: map[string]string{
				constants.UserLabel:         userID,
				constants.OrganizationLabel: testOrgID,
			},
		},
		Spec: unikornv1.OrganizationUserSpec{
			State: unikornv1.UserStateActive,
		},
	}
	require.NoError(t, f.client.Create(ctx, orgUser))
}

// makeGroupUpdateRequest builds a group update request.
func makeGroupUpdateRequest(subjects *[]openapi.Subject, userIDs *openapi.StringList) *openapi.GroupWrite {
	return &openapi.GroupWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{
			Name: groupTestID,
		},
		Spec: openapi.GroupSpec{
			RoleIDs:           openapi.StringList{},
			Subjects:          subjects,
			UserIDs:           userIDs,
			ServiceAccountIDs: openapi.StringList{},
		},
	}
}

// TestUpdateGroupWithSubjects_PopulatesUserIDs tests that when a group is updated with Subjects
// that have the internal issuer, those subjects are converted to UserIDs.
func TestUpdateGroupWithSubjects_PopulatesUserIDs(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createUserWithOrgMembership(t, userAliceID, userAliceSubject, orguserAliceID)
	f.createGroup(t)

	subjects := []openapi.Subject{
		{
			Id:     userAliceSubject,
			Issuer: testIssuerURL,
			Email:  ptr.To(userAliceSubject),
		},
	}

	err := f.groupsClient.Update(newContext(t), ids.MustParseOrganizationID(testOrgID), groupTestID, makeGroupUpdateRequest(&subjects, nil))
	require.NoError(t, err)

	updatedGroup := f.getGroup(t)

	// Verify that Subjects are populated
	require.NotNil(t, updatedGroup.Spec.Subjects)
	require.Len(t, updatedGroup.Spec.Subjects, 1)
	assert.Equal(t, userAliceSubject, updatedGroup.Spec.Subjects[0].ID)
	assert.Equal(t, testIssuerURL, updatedGroup.Spec.Subjects[0].Issuer)

	// Verify that UserIDs are also populated (this is the new behavior being tested)
	require.NotNil(t, updatedGroup.Spec.UserIDs)
	require.Len(t, updatedGroup.Spec.UserIDs, 1, "UserIDs should be populated from Subjects with internal issuer")
	assert.Equal(t, orguserAliceID, updatedGroup.Spec.UserIDs[0], "UserID should match the OrganizationUser name")
}

// TestUpdateGroupWithExternalSubjects_DoesNotPopulateUserIDs tests that external subjects
// (non-internal issuer) are not converted to UserIDs.
func TestUpdateGroupWithExternalSubjects_DoesNotPopulateUserIDs(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createGroup(t)

	subjects := []openapi.Subject{
		{
			Id:     "external-user@github.com",
			Issuer: "https://github.com",
			Email:  ptr.To("external-user@github.com"),
		},
	}

	err := f.groupsClient.Update(newContext(t), ids.MustParseOrganizationID(testOrgID), groupTestID, makeGroupUpdateRequest(&subjects, nil))
	require.NoError(t, err)

	updatedGroup := f.getGroup(t)

	// Verify that Subjects are populated
	require.NotNil(t, updatedGroup.Spec.Subjects)
	require.Len(t, updatedGroup.Spec.Subjects, 1)

	// Verify that UserIDs are NOT populated for external subjects
	require.Empty(t, updatedGroup.Spec.UserIDs, "UserIDs should not be populated for external subjects")
}

// TestUpdateGroupWithMixedSubjects_PopulatesOnlyInternalUserIDs tests that when a group has
// both internal and external subjects, only internal ones are converted to UserIDs.
func TestUpdateGroupWithMixedSubjects_PopulatesOnlyInternalUserIDs(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createUserWithOrgMembership(t, userAliceID, userAliceSubject, orguserAliceID)
	f.createGroup(t)

	subjects := []openapi.Subject{
		{
			Id:     userAliceSubject,
			Issuer: testIssuerURL,
			Email:  ptr.To(userAliceSubject),
		},
		{
			Id:     "external-user@github.com",
			Issuer: "https://github.com",
			Email:  ptr.To("external-user@github.com"),
		},
	}

	err := f.groupsClient.Update(newContext(t), ids.MustParseOrganizationID(testOrgID), groupTestID, makeGroupUpdateRequest(&subjects, nil))
	require.NoError(t, err)

	updatedGroup := f.getGroup(t)

	// Verify that Subjects are populated with both users
	require.NotNil(t, updatedGroup.Spec.Subjects)
	require.Len(t, updatedGroup.Spec.Subjects, 2)

	// Verify that UserIDs only contains the internal user
	require.NotNil(t, updatedGroup.Spec.UserIDs)
	require.Len(t, updatedGroup.Spec.UserIDs, 1, "UserIDs should only contain internal subjects")
	assert.Equal(t, orguserAliceID, updatedGroup.Spec.UserIDs[0], "UserID should match the OrganizationUser name")
}

// TestUpdateGroupWithNonMemberSubject_ReturnsError tests that when a Subject with internal issuer
// is provided but the user is not a member of the organization, an error is returned.
func TestUpdateGroupWithNonMemberSubject_ReturnsError(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createUserWithoutOrgMembership(t, "user-nonmember", "nonmember@example.com")
	f.createGroup(t)

	subjects := []openapi.Subject{
		{
			Id:     "nonmember@example.com",
			Issuer: testIssuerURL,
			Email:  ptr.To("nonmember@example.com"),
		},
	}

	err := f.groupsClient.Update(newContext(t), ids.MustParseOrganizationID(testOrgID), groupTestID, makeGroupUpdateRequest(&subjects, nil))
	require.Error(t, err, "Should error when subject is not a member of the organization")
	require.True(t, errors.IsBadRequest(err))
}

// TestUpdateGroupWithNonExistentSubject_ReturnsError tests that when a Subject with internal issuer
// is provided but no User record exists for that subject, an error is returned.
func TestUpdateGroupWithNonExistentSubject_ReturnsError(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createGroup(t)

	subjects := []openapi.Subject{
		{
			Id:     "doesnotexist@example.com",
			Issuer: testIssuerURL,
			Email:  ptr.To("doesnotexist@example.com"),
		},
	}

	err := f.groupsClient.Update(newContext(t), ids.MustParseOrganizationID(testOrgID), groupTestID, makeGroupUpdateRequest(&subjects, nil))
	require.Error(t, err, "Should error when subject does not exist")
	require.True(t, errors.IsBadRequest(err))
}

// TestUpdateGroupWithUserIDs_PopulatesSubjects tests that when a group is updated with UserIDs
// (old-style API), those UserIDs are converted to Subjects.
func TestUpdateGroupWithUserIDs_PopulatesSubjects(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createUserWithOrgMembership(t, userAliceID, userAliceSubject, orguserAliceID)
	f.createGroup(t)

	userIDs := openapi.StringList{orguserAliceID}

	err := f.groupsClient.Update(newContext(t), ids.MustParseOrganizationID(testOrgID), groupTestID, makeGroupUpdateRequest(nil, &userIDs))
	require.NoError(t, err)

	updatedGroup := f.getGroup(t)

	// Verify that UserIDs are populated
	require.NotNil(t, updatedGroup.Spec.UserIDs)
	require.Len(t, updatedGroup.Spec.UserIDs, 1)
	assert.Equal(t, orguserAliceID, updatedGroup.Spec.UserIDs[0])

	// Verify that Subjects are also populated (converted from UserIDs)
	require.NotNil(t, updatedGroup.Spec.Subjects)
	require.Len(t, updatedGroup.Spec.Subjects, 1, "Subjects should be populated from UserIDs")
	assert.Equal(t, userAliceSubject, updatedGroup.Spec.Subjects[0].ID, "Subject ID should match user's subject")
	assert.Equal(t, testIssuerURL, updatedGroup.Spec.Subjects[0].Issuer, "Subject issuer should be internal issuer")
	assert.Equal(t, userAliceSubject, updatedGroup.Spec.Subjects[0].Email, "Subject email should match user's subject")
}

// TestUpdateGroupWithInvalidUserID_ReturnsError tests that when an invalid UserID is provided,
// an error is returned.
func TestUpdateGroupWithInvalidUserID_ReturnsError(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createGroup(t)

	userIDs := openapi.StringList{"nonexistent-orguser"}

	err := f.groupsClient.Update(newContext(t), ids.MustParseOrganizationID(testOrgID), groupTestID, makeGroupUpdateRequest(nil, &userIDs))
	require.Error(t, err, "Should error when UserID is invalid")
	require.True(t, errors.IsBadRequest(err))
}

// TestUpdateGroupWithMultipleUserIDs_PopulatesAllSubjects tests that when multiple UserIDs
// are provided, all are converted to Subjects.
func TestUpdateGroupWithMultipleUserIDs_PopulatesAllSubjects(t *testing.T) {
	t.Parallel()

	// Create users and org users for Alice and Bob
	users := []struct {
		userID    string
		subject   string
		orguserID string
	}{
		{userAliceID, userAliceSubject, orguserAliceID},
		{userBobID, userBobSubject, orguserBobID},
	}

	f := setupGroupTestFixture(t)

	for _, u := range users {
		f.createUserWithOrgMembership(t, u.userID, u.subject, u.orguserID)
	}

	f.createGroup(t)

	// Update the group with multiple UserIDs
	userIDs := openapi.StringList{orguserAliceID, orguserBobID}

	updateRequest := &openapi.GroupWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{
			Name: groupTestID,
		},
		Spec: openapi.GroupSpec{
			RoleIDs:           openapi.StringList{},
			UserIDs:           &userIDs,
			ServiceAccountIDs: openapi.StringList{},
		},
	}

	err := f.groupsClient.Update(newContext(t), ids.MustParseOrganizationID(testOrgID), groupTestID, updateRequest)
	require.NoError(t, err)

	// Fetch the updated group
	updatedGroup := f.getGroup(t)

	// Verify that UserIDs are populated
	require.NotNil(t, updatedGroup.Spec.UserIDs)
	require.Len(t, updatedGroup.Spec.UserIDs, 2)
	assert.Contains(t, updatedGroup.Spec.UserIDs, orguserAliceID)
	assert.Contains(t, updatedGroup.Spec.UserIDs, orguserBobID)

	// Verify that Subjects are also populated
	require.NotNil(t, updatedGroup.Spec.Subjects)
	require.Len(t, updatedGroup.Spec.Subjects, 2, "All UserIDs should be converted to Subjects")

	// Check that both subjects are present
	subjects := make(map[string]bool)
	for _, s := range updatedGroup.Spec.Subjects {
		subjects[s.ID] = true

		assert.Equal(t, testIssuerURL, s.Issuer, "All subjects should have internal issuer")
	}

	assert.True(t, subjects[userAliceSubject], "Alice's subject should be present")
	assert.True(t, subjects[userBobSubject], "Bob's subject should be present")
}

// TestUpdateGroupWithBothSubjectsAndUserIDs_ReturnsError tests that providing both Subjects
// and UserIDs returns an error.
func TestUpdateGroupWithBothSubjectsAndUserIDs_ReturnsError(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)

	f.createUserWithOrgMembership(t, userAliceID, userAliceSubject, orguserAliceID)

	f.createGroup(t)

	// Try to update the group with BOTH Subjects and UserIDs
	subjects := []openapi.Subject{
		{
			Id:     userAliceSubject,
			Issuer: testIssuerURL,
			Email:  ptr.To(userAliceSubject),
		},
	}
	userIDs := openapi.StringList{orguserAliceID}

	updateRequest := &openapi.GroupWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{
			Name: groupTestID,
		},
		Spec: openapi.GroupSpec{
			RoleIDs:           openapi.StringList{},
			Subjects:          &subjects,
			UserIDs:           &userIDs,
			ServiceAccountIDs: openapi.StringList{},
		},
	}

	err := f.groupsClient.Update(newContext(t), ids.MustParseOrganizationID(testOrgID), groupTestID, updateRequest)
	require.Error(t, err, "Should error when both subjects and userIDs are provided")
	require.True(t, errors.IsBadRequest(err))
}

func TestUpdateGroup_DeduplicatesSpecFieldsBeforePersist(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createUserWithOrgMembership(t, userAliceID, userAliceSubject, orguserAliceID)
	f.createGroup(t)

	roleA := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      "role-a",
		},
	}

	roleB := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      "role-b",
		},
	}

	require.NoError(t, f.client.Create(newContext(t), roleA))
	require.NoError(t, f.client.Create(newContext(t), roleB))

	subjects := []openapi.Subject{
		{Id: userAliceSubject, Issuer: testIssuerURL, Email: ptr.To("alice-1@example.com")},
		{Id: userAliceSubject, Issuer: testIssuerURL, Email: ptr.To("alice-2@example.com")},
		{Id: "alice@example.com", Issuer: "https://external.example.com", Email: ptr.To("alice-external-1@example.com")},
		{Id: "alice@example.com", Issuer: "https://external.example.com", Email: ptr.To("alice-external-2@example.com")},
	}

	request := &openapi.GroupWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{Name: groupTestID},
		Spec: openapi.GroupSpec{
			RoleIDs:           openapi.StringList{"role-a", "role-a", "role-b"},
			Subjects:          &subjects,
			ServiceAccountIDs: openapi.StringList{"sa-a", "sa-a", "sa-b"},
		},
	}

	err := f.groupsClient.Update(newContext(t), ids.MustParseOrganizationID(testOrgID), groupTestID, request)
	require.NoError(t, err)

	stored := f.getGroup(t)

	assert.Equal(t, []string{"role-a", "role-b"}, stored.Spec.RoleIDs)
	assert.Equal(t, []string{"sa-a", "sa-b"}, stored.Spec.ServiceAccountIDs)
	assert.Equal(t, []string{orguserAliceID}, stored.Spec.UserIDs)

	require.Len(t, stored.Spec.Subjects, 2)
	assert.Equal(t, userAliceSubject, stored.Spec.Subjects[0].ID)
	assert.Equal(t, testIssuerURL, stored.Spec.Subjects[0].Issuer)
	assert.Equal(t, "alice-1@example.com", stored.Spec.Subjects[0].Email)
	assert.Equal(t, "alice@example.com", stored.Spec.Subjects[1].ID)
	assert.Equal(t, "https://external.example.com", stored.Spec.Subjects[1].Issuer)
	assert.Equal(t, "alice-external-1@example.com", stored.Spec.Subjects[1].Email)
}

// createRadarRole creates a Role scoped to an endpoint the fixture's caller does not hold,
// so AllowRole refuses it unless the caller's ACL is extended to cover that endpoint.
func (f *groupTestFixture) createRadarRole(t *testing.T) {
	t.Helper()

	role := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      "radar-id",
			Labels:    map[string]string{"unikorn-cloud.org/name": "radar"},
		},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Organization: []unikornv1.RoleScope{
					{Name: "radar:things", Operations: []unikornv1.Operation{unikornv1.Read}},
				},
			},
		},
	}
	require.NoError(t, f.client.Create(newContext(t), role))
}

// createGroupWithRoles creates the test group with a pre-existing set of RoleIDs, standing
// in for roles granted by an earlier, more privileged write.
func (f *groupTestFixture) createGroupWithRoles(t *testing.T, roleIDs []string) {
	t.Helper()

	f.createGroupWithSpec(t, unikornv1.GroupSpec{RoleIDs: roleIDs})
}

// createGroupWithSpec creates the test group with the given spec, standing in for state
// left by an earlier, more privileged write or by direct CR access.
func (f *groupTestFixture) createGroupWithSpec(t *testing.T, spec unikornv1.GroupSpec) {
	t.Helper()

	group := &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      groupTestID,
			Labels: map[string]string{
				constants.OrganizationLabel: testOrgID,
			},
		},
		Spec: spec,
	}
	require.NoError(t, f.client.Create(newContext(t), group))
}

// aclContext builds a context carrying an ACL that grants only the given organization-scoped
// endpoints in testOrgID, layered on top of newContext's authorization/principal info.
func aclContext(t *testing.T, endpoints openapi.AclEndpoints) context.Context {
	t.Helper()

	organizations := openapi.AclOrganizationList{{Id: testOrgID, Endpoints: &endpoints}}

	return rbac.NewContext(newContext(t), &openapi.Acl{Organizations: &organizations})
}

// TestUpdateGroupRejectsRemovalOfUngrantableRole exercises the removal guard through the
// public Update() entrypoint, not just the unexported validateRoleRemovals helper directly:
// a group already carries "radar-id" (as if granted by a more privileged earlier write), and
// the caller — who cannot grant radar:things — submits an update that omits it. Update must
// refuse the request, naming the role, and leave the stored group unchanged.
func TestUpdateGroupRejectsRemovalOfUngrantableRole(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createRadarRole(t)
	f.createGroupWithRoles(t, []string{"radar-id"})

	// Caller holds identity:groups update but nothing on radar:things.
	ctx := aclContext(t, openapi.AclEndpoints{
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Update}},
	})

	// The request omits "radar-id" entirely — a silent removal attempt.
	err := f.groupsClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), groupTestID, makeGroupUpdateRequest(nil, nil))
	require.Error(t, err)
	require.True(t, errors.IsForbidden(err))
	require.Contains(t, err.Error(), "radar")

	// The group must be unchanged: the role was refused, not silently dropped.
	stored := f.getGroup(t)
	assert.Equal(t, []string{"radar-id"}, stored.Spec.RoleIDs)
}

// TestUpdateGroupKeepsUngrantableRoleWhenResent is the companion happy path: a caller who
// cannot grant radar:things may still resend a group's existing radar-id role untouched
// alongside an unrelated change (here, dropping one of two user members). The removal
// guard must not fire when the role isn't actually being dropped, and member removal is
// not a grant, so nothing else blocks the write either.  The retained member is the point:
// it comes back in the request, and re-stating an existing member must not read as an
// addition.
func TestUpdateGroupKeepsUngrantableRoleWhenResent(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createUserWithOrgMembership(t, userAliceID, userAliceSubject, orguserAliceID)
	f.createUserWithOrgMembership(t, userBobID, userBobSubject, orguserBobID)
	f.createRadarRole(t)
	f.createGroupWithSpec(t, unikornv1.GroupSpec{
		RoleIDs: []string{"radar-id"},
		UserIDs: []string{orguserAliceID, orguserBobID},
	})

	ctx := aclContext(t, openapi.AclEndpoints{
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Update}},
	})

	userIDs := openapi.StringList{orguserAliceID}
	request := makeGroupUpdateRequest(nil, &userIDs)
	request.Spec.RoleIDs = openapi.StringList{"radar-id"}

	err := f.groupsClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), groupTestID, request)
	require.NoError(t, err)

	stored := f.getGroup(t)
	assert.Equal(t, []string{"radar-id"}, stored.Spec.RoleIDs)
	assert.Equal(t, []string{orguserAliceID}, stored.Spec.UserIDs)
	require.Len(t, stored.Spec.Subjects, 1)
	assert.Equal(t, userAliceSubject, stored.Spec.Subjects[0].ID)
}

// TestUpdateGroupAllowsNoOpResendOnLegacyUserIDsGroup covers a group written before
// Subjects existed: it lists its members in UserIDs only.  Re-sending that membership
// unchanged derives the Subjects half for the first time, but the members already hold the
// group's roles through UserIDs, so nothing is conferred and the addition gate must not
// fire — otherwise a legacy group carrying an ungrantable role has no legal update at all.
func TestUpdateGroupAllowsNoOpResendOnLegacyUserIDsGroup(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createUserWithOrgMembership(t, userAliceID, userAliceSubject, orguserAliceID)
	f.createRadarRole(t)
	f.createGroupWithSpec(t, unikornv1.GroupSpec{
		RoleIDs: []string{"radar-id"},
		UserIDs: []string{orguserAliceID},
	})

	ctx := aclContext(t, openapi.AclEndpoints{
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Update}},
	})

	userIDs := openapi.StringList{orguserAliceID}
	request := makeGroupUpdateRequest(nil, &userIDs)
	request.Spec.RoleIDs = openapi.StringList{"radar-id"}

	err := f.groupsClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), groupTestID, request)
	require.NoError(t, err)

	// The write also migrates the group onto the Subjects representation.
	stored := f.getGroup(t)
	assert.Equal(t, []string{orguserAliceID}, stored.Spec.UserIDs)
	require.Len(t, stored.Spec.Subjects, 1)
	assert.Equal(t, userAliceSubject, stored.Spec.Subjects[0].ID)
	assert.Equal(t, []string{"radar-id"}, stored.Spec.RoleIDs)
}

// TestUpdateGroupRejectsGenuineAdditionToLegacyUserIDsGroup is the other half: relaxing the
// gate for members already present in either representation must not relax it for a member
// that is in neither.
func TestUpdateGroupRejectsGenuineAdditionToLegacyUserIDsGroup(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createUserWithOrgMembership(t, userAliceID, userAliceSubject, orguserAliceID)
	f.createUserWithOrgMembership(t, userBobID, userBobSubject, orguserBobID)
	f.createRadarRole(t)
	f.createGroupWithSpec(t, unikornv1.GroupSpec{
		RoleIDs: []string{"radar-id"},
		UserIDs: []string{orguserAliceID},
	})

	ctx := aclContext(t, openapi.AclEndpoints{
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Update}},
	})

	userIDs := openapi.StringList{orguserAliceID, orguserBobID}
	request := makeGroupUpdateRequest(nil, &userIDs)
	request.Spec.RoleIDs = openapi.StringList{"radar-id"}

	err := f.groupsClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), groupTestID, request)
	require.Error(t, err)
	require.True(t, errors.IsForbidden(err))
	require.Contains(t, err.Error(), "radar")

	stored := f.getGroup(t)
	assert.Equal(t, []string{orguserAliceID}, stored.Spec.UserIDs)
}

// TestUpdateGroupAllowsResendWhenStoredSubjectEmailDiffers pins the identity key: three
// different writers populate a subject's Email with three different values, so a member
// whose stored Email differs from the derived one is still the same principal and still
// not an addition.
func TestUpdateGroupAllowsResendWhenStoredSubjectEmailDiffers(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createUserWithOrgMembership(t, userAliceID, userAliceSubject, orguserAliceID)
	f.createRadarRole(t)
	f.createGroupWithSpec(t, unikornv1.GroupSpec{
		RoleIDs:  []string{"radar-id"},
		UserIDs:  []string{orguserAliceID},
		Subjects: []unikornv1.GroupSubject{{ID: userAliceSubject, Issuer: testIssuerURL, Email: "stale-display@example.com"}},
	})

	ctx := aclContext(t, openapi.AclEndpoints{
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Update}},
	})

	subjects := []openapi.Subject{
		{Id: userAliceSubject, Issuer: testIssuerURL, Email: ptr.To("fresh-display@example.com")},
	}
	request := makeGroupUpdateRequest(&subjects, nil)
	request.Spec.RoleIDs = openapi.StringList{"radar-id"}

	err := f.groupsClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), groupTestID, request)
	require.NoError(t, err)

	stored := f.getGroup(t)
	require.Len(t, stored.Spec.Subjects, 1, "the same principal must not be stored twice")
	assert.Equal(t, userAliceSubject, stored.Spec.Subjects[0].ID)
	assert.Equal(t, []string{orguserAliceID}, stored.Spec.UserIDs)
}

// TestUpdateGroupAllowsResendWhenOnlySubjectsStored is the mirror of the legacy case: the
// group stores the member as a subject only, and a UserIDs-style write names the same
// principal.  RBAC honours either representation, so completing the missing half confers
// nothing.
func TestUpdateGroupAllowsResendWhenOnlySubjectsStored(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createUserWithOrgMembership(t, userAliceID, userAliceSubject, orguserAliceID)
	f.createRadarRole(t)
	f.createGroupWithSpec(t, unikornv1.GroupSpec{
		RoleIDs:  []string{"radar-id"},
		Subjects: []unikornv1.GroupSubject{{ID: userAliceSubject, Issuer: testIssuerURL, Email: userAliceSubject}},
	})

	ctx := aclContext(t, openapi.AclEndpoints{
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Update}},
	})

	userIDs := openapi.StringList{orguserAliceID}
	request := makeGroupUpdateRequest(nil, &userIDs)
	request.Spec.RoleIDs = openapi.StringList{"radar-id"}

	err := f.groupsClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), groupTestID, request)
	require.NoError(t, err)

	stored := f.getGroup(t)
	assert.Equal(t, []string{orguserAliceID}, stored.Spec.UserIDs)
	require.Len(t, stored.Spec.Subjects, 1)
}

// TestUpdateGroupRejectsExternalSubjectAdditionAlongsideExistingMember guards the relaxation
// itself: an external subject has no organization user record, so it can only ever be
// matched in the Subjects list.  Naming it alongside a member who is already present must
// not let it in unchecked.
func TestUpdateGroupRejectsExternalSubjectAdditionAlongsideExistingMember(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createUserWithOrgMembership(t, userAliceID, userAliceSubject, orguserAliceID)
	f.createRadarRole(t)
	f.createGroupWithSpec(t, unikornv1.GroupSpec{
		RoleIDs: []string{"radar-id"},
		UserIDs: []string{orguserAliceID},
	})

	ctx := aclContext(t, openapi.AclEndpoints{
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Update}},
	})

	subjects := []openapi.Subject{
		{Id: userAliceSubject, Issuer: testIssuerURL, Email: ptr.To(userAliceSubject)},
		{Id: "mallory@evil.example.com", Issuer: "https://external.example.com"},
	}
	request := makeGroupUpdateRequest(&subjects, nil)
	request.Spec.RoleIDs = openapi.StringList{"radar-id"}

	err := f.groupsClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), groupTestID, request)
	require.Error(t, err)
	require.True(t, errors.IsForbidden(err))
	require.Contains(t, err.Error(), "radar")

	stored := f.getGroup(t)
	assert.Empty(t, stored.Spec.Subjects)
}

// TestUpdateGroupRejectsMemberAdditionToUngrantableRoleGroup covers the grant that hides
// inside a membership edit: the new member inherits every role the group carries, so
// adding one to a group holding radar-id grants radar:things to them. A caller who cannot
// grant that role must be refused, and the group left untouched.
func TestUpdateGroupRejectsMemberAdditionToUngrantableRoleGroup(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createRadarRole(t)
	f.createGroupWithRoles(t, []string{"radar-id"})

	ctx := aclContext(t, openapi.AclEndpoints{
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Update}},
	})

	request := makeGroupUpdateRequest(nil, nil)
	request.Spec.RoleIDs = openapi.StringList{"radar-id"}
	request.Spec.ServiceAccountIDs = openapi.StringList{"sa-a"}

	err := f.groupsClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), groupTestID, request)
	require.Error(t, err)
	require.True(t, errors.IsForbidden(err))
	require.Contains(t, err.Error(), "radar")

	stored := f.getGroup(t)
	assert.Empty(t, stored.Spec.ServiceAccountIDs)
	assert.Equal(t, []string{"radar-id"}, stored.Spec.RoleIDs)
}

// TestUpdateGroupRejectsUserAdditionToUngrantableRoleGroup is the human-member counterpart:
// the gate has to cover the UserIDs and Subjects representations, not just service accounts.
func TestUpdateGroupRejectsUserAdditionToUngrantableRoleGroup(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createUserWithOrgMembership(t, userAliceID, userAliceSubject, orguserAliceID)
	f.createRadarRole(t)
	f.createGroupWithRoles(t, []string{"radar-id"})

	ctx := aclContext(t, openapi.AclEndpoints{
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Update}},
	})

	userIDs := openapi.StringList{orguserAliceID}
	request := makeGroupUpdateRequest(nil, &userIDs)
	request.Spec.RoleIDs = openapi.StringList{"radar-id"}

	err := f.groupsClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), groupTestID, request)
	require.Error(t, err)
	require.True(t, errors.IsForbidden(err))
	require.Contains(t, err.Error(), "radar")

	stored := f.getGroup(t)
	assert.Empty(t, stored.Spec.UserIDs)
	assert.Empty(t, stored.Spec.Subjects)
}

// TestUpdateGroupAllowsMemberAdditionToRolelessGroup shows the gate is scoped to what the
// group actually confers: a group with no roles grants nothing, so anyone who may edit the
// group may add members to it.
func TestUpdateGroupAllowsMemberAdditionToRolelessGroup(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createGroupWithRoles(t, nil)

	ctx := aclContext(t, openapi.AclEndpoints{
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Update}},
	})

	request := makeGroupUpdateRequest(nil, nil)
	request.Spec.ServiceAccountIDs = openapi.StringList{"sa-a"}

	err := f.groupsClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), groupTestID, request)
	require.NoError(t, err)

	stored := f.getGroup(t)
	assert.Equal(t, []string{"sa-a"}, stored.Spec.ServiceAccountIDs)
}

// TestUpdateGroupAllowsMemberAdditionByRoleHolder is the other half of the gate: the grant
// traces to a holder, so a caller who does hold radar:things may add members to the group
// that confers it.
func TestUpdateGroupAllowsMemberAdditionByRoleHolder(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createRadarRole(t)
	f.createGroupWithRoles(t, []string{"radar-id"})

	ctx := aclContext(t, openapi.AclEndpoints{
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Update}},
		{Name: "radar:things", Operations: openapi.AclOperations{openapi.Read}},
	})

	request := makeGroupUpdateRequest(nil, nil)
	request.Spec.RoleIDs = openapi.StringList{"radar-id"}
	request.Spec.ServiceAccountIDs = openapi.StringList{"sa-a"}

	err := f.groupsClient.Update(ctx, ids.MustParseOrganizationID(testOrgID), groupTestID, request)
	require.NoError(t, err)

	stored := f.getGroup(t)
	assert.Equal(t, []string{"radar-id"}, stored.Spec.RoleIDs)
	assert.Equal(t, []string{"sa-a"}, stored.Spec.ServiceAccountIDs)
}
