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
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/groups"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace  = "test-namespace"
	testOrgID      = "test-org"
	testOrgNS      = "test-org-ns"
	testIssuerURL  = "https://identity.unikorn-cloud.org"
	testIssuerHost = "identity.unikorn-cloud.org"

	userAliceSubject = "alice@example.com"
	userAliceID      = "user-alice"
	orguserAliceID   = "orguser-alice"

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

	err := f.groupsClient.Update(newContext(t), testOrgID, groupTestID, makeGroupUpdateRequest(&subjects, nil))
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

	err := f.groupsClient.Update(newContext(t), testOrgID, groupTestID, makeGroupUpdateRequest(&subjects, nil))
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

	err := f.groupsClient.Update(newContext(t), testOrgID, groupTestID, makeGroupUpdateRequest(&subjects, nil))
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

	err := f.groupsClient.Update(newContext(t), testOrgID, groupTestID, makeGroupUpdateRequest(&subjects, nil))
	require.Error(t, err, "Should error when subject is not a member of the organization")
	assert.Contains(t, err.Error(), "not a member of", "Error should indicate the user is not a member")
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

	err := f.groupsClient.Update(newContext(t), testOrgID, groupTestID, makeGroupUpdateRequest(&subjects, nil))
	require.Error(t, err, "Should error when subject does not exist")
	assert.Contains(t, err.Error(), "user", "Error should indicate issue with user lookup")
}

// TestUpdateGroupWithUserIDs_PopulatesSubjects tests that when a group is updated with UserIDs
// (old-style API), those UserIDs are converted to Subjects.
func TestUpdateGroupWithUserIDs_PopulatesSubjects(t *testing.T) {
	t.Parallel()

	f := setupGroupTestFixture(t)
	f.createUserWithOrgMembership(t, userAliceID, userAliceSubject, orguserAliceID)
	f.createGroup(t)

	userIDs := openapi.StringList{orguserAliceID}

	err := f.groupsClient.Update(newContext(t), testOrgID, groupTestID, makeGroupUpdateRequest(nil, &userIDs))
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

	err := f.groupsClient.Update(newContext(t), testOrgID, groupTestID, makeGroupUpdateRequest(nil, &userIDs))
	require.Error(t, err, "Should error when UserID is invalid")
	assert.Contains(t, err.Error(), "organization member", "Error should indicate issue with organization member lookup")
}

// TestUpdateGroupWithMultipleUserIDs_PopulatesAllSubjects tests that when multiple UserIDs
// are provided, all are converted to Subjects.
func TestUpdateGroupWithMultipleUserIDs_PopulatesAllSubjects(t *testing.T) {
	t.Parallel()

	const (
		userBobSubject = "bob@example.com"
		userBobID      = "user-bob"
		orguserBobID   = "orguser-bob"
	)

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

	err := f.groupsClient.Update(newContext(t), testOrgID, groupTestID, updateRequest)
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

	err := f.groupsClient.Update(newContext(t), testOrgID, groupTestID, updateRequest)
	require.Error(t, err, "Should error when both subjects and userIDs are provided")
	assert.Contains(t, err.Error(), "cannot provide both", "Error should indicate both fields were provided")
}
