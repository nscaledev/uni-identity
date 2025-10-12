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

package rbac_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace = "test-namespace"
	testOrgID     = "test-org"
	testOrgNS     = "test-org-ns"

	// Users
	userAliceSubject = "alice@example.com"
	userAliceID      = "user-alice"

	userBobSubject = "bob@example.com"
	userBobID      = "user-bob"

	userCharlieSubject = "charlie@example.com"
	userCharlieID      = "user-charlie"

	// Groups
	groupAdminsID   = "group-admins"
	groupDevelopers = "group-developers"
	groupReaders    = "group-readers"

	// Roles
	roleAdminID     = "role-admin"
	roleDeveloperID = "role-developer"
	roleReaderID    = "role-reader"

	// Projects
	projectAlphaID = "project-alpha"
	projectBetaID  = "project-beta"
)

// setupTestEnvironment creates a comprehensive RBAC test environment with users, groups, roles, and projects.
func setupTestEnvironment(t *testing.T) (client.Client, *rbac.RBAC) {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	var objects []client.Object
	appendObjects := func(objs ...client.Object) {
		objects = append(objects, objs...)
	}

	// addUserToOrgInGroups creates the relationship between a (global) user and an organisation.
	addUserToOrgInGroups := func(user *unikornv1.User, _ *unikornv1.Organization, groups []*unikornv1.Group) {
		// and add the orguser ID to the group
		for _, g := range groups {
			g.Spec.Subjects = append(g.Spec.Subjects, user.Spec.Subject)
		}
	}

	// Create global Users
	userAlice := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      userAliceID,
		},
		Spec: unikornv1.UserSpec{
			Subject: userAliceSubject,
			State:   unikornv1.UserStateActive,
		},
	}

	userBob := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      userBobID,
		},
		Spec: unikornv1.UserSpec{
			Subject: userBobSubject,
			State:   unikornv1.UserStateActive,
		},
	}

	userCharlie := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      userCharlieID,
		},
		Spec: unikornv1.UserSpec{
			Subject: userCharlieSubject,
			State:   unikornv1.UserStateActive,
		},
	}

	appendObjects(userAlice, userBob, userCharlie)

	// Create Organization
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

	appendObjects(organization)

	// Create Roles with different permission scopes
	roleAdmin := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      roleAdminID,
		},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Global: []unikornv1.RoleScope{
					{
						Name:       "users:manage",
						Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Read, unikornv1.Update, unikornv1.Delete},
					},
				},
				Organization: []unikornv1.RoleScope{
					{
						Name:       "org:manage",
						Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Read, unikornv1.Update, unikornv1.Delete},
					},
				},
			},
		},
	}

	roleDeveloper := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      roleDeveloperID,
		},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Organization: []unikornv1.RoleScope{
					{
						Name:       "org:read",
						Operations: []unikornv1.Operation{unikornv1.Read},
					},
				},
				Project: []unikornv1.RoleScope{
					{
						Name:       "project:deploy",
						Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Update},
					},
				},
			},
		},
	}

	roleReader := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      roleReaderID,
		},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Organization: []unikornv1.RoleScope{
					{
						Name:       "org:read",
						Operations: []unikornv1.Operation{unikornv1.Read},
					},
				},
				Project: []unikornv1.RoleScope{
					{
						Name:       "project:read",
						Operations: []unikornv1.Operation{unikornv1.Read},
					},
				},
			},
		},
	}

	appendObjects(roleAdmin, roleDeveloper, roleReader)

	groupAdminsObj := &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      groupAdminsID,
		},
		Spec: unikornv1.GroupSpec{
			RoleIDs: []string{roleAdminID},
		},
	}

	groupReadersObj := &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      groupReaders,
		},
		Spec: unikornv1.GroupSpec{
			RoleIDs: []string{roleReaderID},
		},
	}

	// Bob and Charlie are developers
	groupDevelopersObj := &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      groupDevelopers,
		},
		Spec: unikornv1.GroupSpec{
			RoleIDs: []string{roleDeveloperID},
		},
	}

	appendObjects(groupAdminsObj, groupReadersObj, groupDevelopersObj)

	addUserToOrgInGroups(userAlice, organization, []*unikornv1.Group{groupAdminsObj})
	addUserToOrgInGroups(userBob, organization, []*unikornv1.Group{groupDevelopersObj})
	addUserToOrgInGroups(userCharlie, organization, []*unikornv1.Group{groupReadersObj, groupDevelopersObj})

	// Create Projects
	projectAlpha := &unikornv1.Project{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      projectAlphaID,
			Labels: map[string]string{
				constants.OrganizationLabel: testOrgID,
			},
		},
		Spec: unikornv1.ProjectSpec{
			GroupIDs: []string{groupDevelopers}, // Only developers have access
		},
	}

	projectBeta := &unikornv1.Project{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      projectBetaID,
			Labels: map[string]string{
				constants.OrganizationLabel: testOrgID,
			},
		},
		Spec: unikornv1.ProjectSpec{
			GroupIDs: []string{groupDevelopers, groupReaders}, // Developers and readers
		},
	}

	appendObjects(projectAlpha, projectBeta)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		Build()

	rbacClient := rbac.New(fakeClient, testNamespace, &rbac.Options{})

	return fakeClient, rbacClient
}

// getACLForUser is a helper to get the ACL for a given user subject.
func getACLForUser(t *testing.T, ctx context.Context, rbacClient *rbac.RBAC, subject string) *openapi.Acl {
	t.Helper()

	// Create authorization info with user subject
	info := &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub:    subject,
			OrgIds: ptr.To([]string{testOrgID}),
		},
	}

	ctx = authorization.NewContext(ctx, info)

	acl, err := rbacClient.GetACL(ctx, testOrgID)
	require.NoError(t, err)
	require.NotNil(t, acl)

	return acl
}

// TestGroupMigrationACLContent verifies the actual ACL content is correct.
func TestGroupACLContent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	_, rbacClient := setupTestEnvironment(t)

	// Test Alice (Admin) - should have global and organization permissions
	aclAlice := getACLForUser(t, ctx, rbacClient, userAliceSubject)
	assert.NotNil(t, aclAlice.Global, "Alice should have global permissions")
	assert.NotNil(t, aclAlice.Organization, "Alice should have organization permissions")
	assert.Nil(t, aclAlice.Projects, "Alice should not have project-specific permissions")

	// Verify Alice has users:manage globally
	hasUsersManage := false
	for _, endpoint := range *aclAlice.Global {
		if endpoint.Name == "users:manage" {
			hasUsersManage = true
			assert.Contains(t, endpoint.Operations, openapi.Create)
			assert.Contains(t, endpoint.Operations, openapi.Read)
			assert.Contains(t, endpoint.Operations, openapi.Update)
			assert.Contains(t, endpoint.Operations, openapi.Delete)
		}
	}
	assert.True(t, hasUsersManage, "Alice should have users:manage permission")

	// Test Bob (Developer) - should have organization read and project permissions
	aclBob := getACLForUser(t, ctx, rbacClient, userBobSubject)
	assert.Nil(t, aclBob.Global, "Bob should not have global permissions")
	assert.NotNil(t, aclBob.Organization, "Bob should have organization permissions")
	assert.NotNil(t, aclBob.Projects, "Bob should have project permissions")
	assert.Len(t, *aclBob.Projects, 2, "Bob should have access to 2 projects (alpha and beta)")

	// Verify Bob has org:read
	hasOrgRead := false
	for _, endpoint := range aclBob.Organization.Endpoints {
		if endpoint.Name == "org:read" {
			hasOrgRead = true
			require.Contains(t, endpoint.Operations, openapi.Read)
		}
	}
	assert.True(t, hasOrgRead, "Bob should have org:read permission")

	// Test Charlie (Developer + Reader) - should have merged permissions
	aclCharlie := getACLForUser(t, ctx, rbacClient, userCharlieSubject)
	assert.Nil(t, aclCharlie.Global, "Charlie should not have global permissions")
	assert.NotNil(t, aclCharlie.Organization, "Charlie should have organization permissions")
	assert.NotNil(t, aclCharlie.Projects, "Charlie should have project permissions")
	assert.Len(t, *aclCharlie.Projects, 2, "Charlie should have access to 2 projects")

	// Charlie should have both deploy and read permissions on projects (merged from two groups)
	for _, project := range *aclCharlie.Projects {
		if project.Id == projectAlphaID {
			// Alpha: only developers group, so deploy but no read-specific
			hasProjectDeploy := false
			for _, endpoint := range project.Endpoints {
				if endpoint.Name == "project:deploy" {
					hasProjectDeploy = true
				}
			}
			require.True(t, hasProjectDeploy, "Charlie should have deploy on project-alpha")
		}
		if project.Id == projectBetaID {
			// Beta: both groups, so should have both deploy and read
			hasProjectDeploy := false
			hasProjectRead := false
			for _, endpoint := range project.Endpoints {
				if endpoint.Name == "project:deploy" {
					hasProjectDeploy = true
				}
				if endpoint.Name == "project:read" {
					hasProjectRead = true
				}
			}
			assert.True(t, hasProjectDeploy, "Charlie should have deploy on project-beta")
			assert.True(t, hasProjectRead, "Charlie should have read on project-beta")
		}
	}
}
