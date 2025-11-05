/*
Copyright 2025 the Unikorn Authors.

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

// TestUpdateGroupWithSubjects_PopulatesUserIDs tests that when a group is updated with Subjects
// that have the internal issuer, those subjects are converted to UserIDs.
func TestUpdateGroupWithSubjects_PopulatesUserIDs(t *testing.T) {
	t.Parallel()

	c := setupTestClient(t)
	ctx := newContext(t)

	// Create a User in the global namespace
	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      userAliceID,
		},
		Spec: unikornv1.UserSpec{
			Subject: userAliceSubject,
			State:   unikornv1.UserStateActive,
		},
	}
	require.NoError(t, c.Create(ctx, user))

	// Create an OrganizationUser that links to the User
	orgUser := &unikornv1.OrganizationUser{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      orguserAliceID,
			Labels: map[string]string{
				constants.UserLabel:         userAliceID,
				constants.OrganizationLabel: testOrgID,
			},
		},
		Spec: unikornv1.OrganizationUserSpec{
			State: unikornv1.UserStateActive,
		},
	}
	require.NoError(t, c.Create(ctx, orgUser))

	// Create a group
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
	require.NoError(t, c.Create(ctx, group))

	// Create groups client
	issuer := handlercommon.IssuerValue{
		URL:      testIssuerURL,
		Hostname: testIssuerHost,
	}
	groupsClient := groups.New(c, testNamespace, issuer)

	// Update the group with Subjects (new-style API)
	subjects := []openapi.Subject{
		{
			Id:     userAliceSubject,
			Issuer: testIssuerURL, // Internal issuer
			Email:  ptr.To(userAliceSubject),
		},
	}

	updateRequest := &openapi.GroupWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{
			Name: groupTestID,
		},
		Spec: openapi.GroupSpec{
			RoleIDs:           openapi.StringList{},
			Subjects:          &subjects,
			ServiceAccountIDs: openapi.StringList{},
		},
	}

	err := groupsClient.Update(ctx, testOrgID, groupTestID, updateRequest)
	require.NoError(t, err)

	// Fetch the updated group
	var updatedGroup unikornv1.Group
	err = c.Get(ctx, client.ObjectKey{Namespace: testOrgNS, Name: groupTestID}, &updatedGroup)
	require.NoError(t, err)

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

	c := setupTestClient(t)
	ctx := newContext(t)

	// Create a group
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
	require.NoError(t, c.Create(ctx, group))

	// Create groups client
	issuer := handlercommon.IssuerValue{
		URL:      testIssuerURL,
		Hostname: testIssuerHost,
	}
	groupsClient := groups.New(c, testNamespace, issuer)

	// Update the group with external Subjects
	subjects := []openapi.Subject{
		{
			Id:     "external-user@github.com",
			Issuer: "https://github.com", // External issuer
			Email:  ptr.To("external-user@github.com"),
		},
	}

	updateRequest := &openapi.GroupWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{
			Name: groupTestID,
		},
		Spec: openapi.GroupSpec{
			RoleIDs:           openapi.StringList{},
			Subjects:          &subjects,
			ServiceAccountIDs: openapi.StringList{},
		},
	}

	err := groupsClient.Update(ctx, testOrgID, groupTestID, updateRequest)
	require.NoError(t, err)

	// Fetch the updated group
	var updatedGroup unikornv1.Group
	err = c.Get(ctx, client.ObjectKey{Namespace: testOrgNS, Name: groupTestID}, &updatedGroup)
	require.NoError(t, err)

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

	c := setupTestClient(t)
	ctx := newContext(t)

	// Create a User in the global namespace
	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      userAliceID,
		},
		Spec: unikornv1.UserSpec{
			Subject: userAliceSubject,
			State:   unikornv1.UserStateActive,
		},
	}
	require.NoError(t, c.Create(ctx, user))

	// Create an OrganizationUser that links to the User
	orgUser := &unikornv1.OrganizationUser{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      orguserAliceID,
			Labels: map[string]string{
				constants.UserLabel:         userAliceID,
				constants.OrganizationLabel: testOrgID,
			},
		},
		Spec: unikornv1.OrganizationUserSpec{
			State: unikornv1.UserStateActive,
		},
	}
	require.NoError(t, c.Create(ctx, orgUser))

	// Create a group
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
	require.NoError(t, c.Create(ctx, group))

	// Create groups client
	issuer := handlercommon.IssuerValue{
		URL:      testIssuerURL,
		Hostname: testIssuerHost,
	}
	groupsClient := groups.New(c, testNamespace, issuer)

	// Update the group with mixed Subjects (internal + external)
	subjects := []openapi.Subject{
		{
			Id:     userAliceSubject,
			Issuer: testIssuerURL, // Internal issuer
			Email:  ptr.To(userAliceSubject),
		},
		{
			Id:     "external-user@github.com",
			Issuer: "https://github.com", // External issuer
			Email:  ptr.To("external-user@github.com"),
		},
	}

	updateRequest := &openapi.GroupWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{
			Name: groupTestID,
		},
		Spec: openapi.GroupSpec{
			RoleIDs:           openapi.StringList{},
			Subjects:          &subjects,
			ServiceAccountIDs: openapi.StringList{},
		},
	}

	err := groupsClient.Update(ctx, testOrgID, groupTestID, updateRequest)
	require.NoError(t, err)

	// Fetch the updated group
	var updatedGroup unikornv1.Group
	err = c.Get(ctx, client.ObjectKey{Namespace: testOrgNS, Name: groupTestID}, &updatedGroup)
	require.NoError(t, err)

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

	c := setupTestClient(t)
	ctx := newContext(t)

	// Create a User in the global namespace (but no OrganizationUser linking them to the org)
	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      "user-nonmember",
		},
		Spec: unikornv1.UserSpec{
			Subject: "nonmember@example.com",
			State:   unikornv1.UserStateActive,
		},
	}
	require.NoError(t, c.Create(ctx, user))

	// Create a group
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
	require.NoError(t, c.Create(ctx, group))

	// Create groups client
	issuer := handlercommon.IssuerValue{
		URL:      testIssuerURL,
		Hostname: testIssuerHost,
	}
	groupsClient := groups.New(c, testNamespace, issuer)

	// Try to update the group with a Subject for a user that's not in the organization
	subjects := []openapi.Subject{
		{
			Id:     "nonmember@example.com",
			Issuer: testIssuerURL, // Internal issuer
			Email:  ptr.To("nonmember@example.com"),
		},
	}

	updateRequest := &openapi.GroupWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{
			Name: groupTestID,
		},
		Spec: openapi.GroupSpec{
			RoleIDs:           openapi.StringList{},
			Subjects:          &subjects,
			ServiceAccountIDs: openapi.StringList{},
		},
	}

	err := groupsClient.Update(ctx, testOrgID, groupTestID, updateRequest)
	require.Error(t, err, "Should error when subject is not a member of the organization")
	assert.Contains(t, err.Error(), "not a member of", "Error should indicate the user is not a member")
}

// TestUpdateGroupWithNonExistentSubject_ReturnsError tests that when a Subject with internal issuer
// is provided but no User record exists for that subject, an error is returned.
func TestUpdateGroupWithNonExistentSubject_ReturnsError(t *testing.T) {
	t.Parallel()

	c := setupTestClient(t)
	ctx := newContext(t)

	// Create a group
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
	require.NoError(t, c.Create(ctx, group))

	// Create groups client
	issuer := handlercommon.IssuerValue{
		URL:      testIssuerURL,
		Hostname: testIssuerHost,
	}
	groupsClient := groups.New(c, testNamespace, issuer)

	// Try to update the group with a Subject for a user that doesn't exist at all
	subjects := []openapi.Subject{
		{
			Id:     "doesnotexist@example.com",
			Issuer: testIssuerURL, // Internal issuer
			Email:  ptr.To("doesnotexist@example.com"),
		},
	}

	updateRequest := &openapi.GroupWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{
			Name: groupTestID,
		},
		Spec: openapi.GroupSpec{
			RoleIDs:           openapi.StringList{},
			Subjects:          &subjects,
			ServiceAccountIDs: openapi.StringList{},
		},
	}

	err := groupsClient.Update(ctx, testOrgID, groupTestID, updateRequest)
	require.Error(t, err, "Should error when subject does not exist")
	assert.Contains(t, err.Error(), "user", "Error should indicate issue with user lookup")
}

// TestUpdateGroupWithUserIDs_PopulatesSubjects tests that when a group is updated with UserIDs
// (old-style API), those UserIDs are converted to Subjects.
func TestUpdateGroupWithUserIDs_PopulatesSubjects(t *testing.T) {
	t.Parallel()

	c := setupTestClient(t)
	ctx := newContext(t)

	// Create a User in the global namespace
	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      userAliceID,
		},
		Spec: unikornv1.UserSpec{
			Subject: userAliceSubject,
			State:   unikornv1.UserStateActive,
		},
	}
	require.NoError(t, c.Create(ctx, user))

	// Create an OrganizationUser that links to the User
	orgUser := &unikornv1.OrganizationUser{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      orguserAliceID,
			Labels: map[string]string{
				constants.UserLabel:         userAliceID,
				constants.OrganizationLabel: testOrgID,
			},
		},
		Spec: unikornv1.OrganizationUserSpec{
			State: unikornv1.UserStateActive,
		},
	}
	require.NoError(t, c.Create(ctx, orgUser))

	// Create a group
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
	require.NoError(t, c.Create(ctx, group))

	// Create groups client
	issuer := handlercommon.IssuerValue{
		URL:      testIssuerURL,
		Hostname: testIssuerHost,
	}
	groupsClient := groups.New(c, testNamespace, issuer)

	// Update the group with UserIDs (old-style API)
	userIDs := openapi.StringList{orguserAliceID}

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

	err := groupsClient.Update(ctx, testOrgID, groupTestID, updateRequest)
	require.NoError(t, err)

	// Fetch the updated group
	var updatedGroup unikornv1.Group
	err = c.Get(ctx, client.ObjectKey{Namespace: testOrgNS, Name: groupTestID}, &updatedGroup)
	require.NoError(t, err)

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

	c := setupTestClient(t)
	ctx := newContext(t)

	// Create a group
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
	require.NoError(t, c.Create(ctx, group))

	// Create groups client
	issuer := handlercommon.IssuerValue{
		URL:      testIssuerURL,
		Hostname: testIssuerHost,
	}
	groupsClient := groups.New(c, testNamespace, issuer)

	// Try to update the group with an invalid UserID
	userIDs := openapi.StringList{"nonexistent-orguser"}

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

	err := groupsClient.Update(ctx, testOrgID, groupTestID, updateRequest)
	require.Error(t, err, "Should error when UserID is invalid")
	assert.Contains(t, err.Error(), "organization member", "Error should indicate issue with organization member lookup")
}

// TestUpdateGroupWithMultipleUserIDs_PopulatesAllSubjects tests that when multiple UserIDs
// are provided, all are converted to Subjects.
func TestUpdateGroupWithMultipleUserIDs_PopulatesAllSubjects(t *testing.T) {
	t.Parallel()

	c := setupTestClient(t)
	ctx := newContext(t)

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

	for _, u := range users {
		user := &unikornv1.User{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: testNamespace,
				Name:      u.userID,
			},
			Spec: unikornv1.UserSpec{
				Subject: u.subject,
				State:   unikornv1.UserStateActive,
			},
		}
		require.NoError(t, c.Create(ctx, user))

		orgUser := &unikornv1.OrganizationUser{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: testOrgNS,
				Name:      u.orguserID,
				Labels: map[string]string{
					constants.UserLabel:         u.userID,
					constants.OrganizationLabel: testOrgID,
				},
			},
			Spec: unikornv1.OrganizationUserSpec{
				State: unikornv1.UserStateActive,
			},
		}
		require.NoError(t, c.Create(ctx, orgUser))
	}

	// Create a group
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
	require.NoError(t, c.Create(ctx, group))

	// Create groups client
	issuer := handlercommon.IssuerValue{
		URL:      testIssuerURL,
		Hostname: testIssuerHost,
	}
	groupsClient := groups.New(c, testNamespace, issuer)

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

	err := groupsClient.Update(ctx, testOrgID, groupTestID, updateRequest)
	require.NoError(t, err)

	// Fetch the updated group
	var updatedGroup unikornv1.Group
	err = c.Get(ctx, client.ObjectKey{Namespace: testOrgNS, Name: groupTestID}, &updatedGroup)
	require.NoError(t, err)

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

	c := setupTestClient(t)
	ctx := newContext(t)

	// Create a User in the global namespace
	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      userAliceID,
		},
		Spec: unikornv1.UserSpec{
			Subject: userAliceSubject,
			State:   unikornv1.UserStateActive,
		},
	}
	require.NoError(t, c.Create(ctx, user))

	// Create an OrganizationUser that links to the User
	orgUser := &unikornv1.OrganizationUser{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      orguserAliceID,
			Labels: map[string]string{
				constants.UserLabel:         userAliceID,
				constants.OrganizationLabel: testOrgID,
			},
		},
		Spec: unikornv1.OrganizationUserSpec{
			State: unikornv1.UserStateActive,
		},
	}
	require.NoError(t, c.Create(ctx, orgUser))

	// Create a group
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
	require.NoError(t, c.Create(ctx, group))

	// Create groups client
	issuer := handlercommon.IssuerValue{
		URL:      testIssuerURL,
		Hostname: testIssuerHost,
	}
	groupsClient := groups.New(c, testNamespace, issuer)

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

	err := groupsClient.Update(ctx, testOrgID, groupTestID, updateRequest)
	require.Error(t, err, "Should error when both subjects and userIDs are provided")
	assert.Contains(t, err.Error(), "cannot provide both", "Error should indicate both fields were provided")
}
