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
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/users"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace = "test-namespace"
	testOrgID     = "test-org"
	testOrgNS     = "test-org-ns"

	altOrgID = "alt-org-id"
	altOrgNS = "alt-namespace"

	userAliceSubject = "alice@example.com"
	userAliceID      = "user-alice"

	userBobSubject = "bob@example.com"
	userBobID      = "user-bob"

	userCharlieSubject = "charlie@example.com"
	userCharlieID      = "user-charlie"

	serviceAccountAlphaID = "sa-alpha"
	serviceAccountBetaID  = "sa-beta"

	groupAdminsID   = "group-admins"
	groupDevelopers = "group-developers"
	groupReaders    = "group-readers"
	groupServices   = "group-services"

	roleAdminID     = "role-admin"
	roleDeveloperID = "role-developer"
	roleReaderID    = "role-reader"

	projectAlphaID = "project-alpha"
	projectBetaID  = "project-beta"
)

// The API handlers like to have things in the context, so they can label any resources they make.
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

// setupTestEnvironment creates a comprehensive RBAC test environment with users, groups, roles, and projects.
func setupTestEnvironment(t *testing.T) *rbac.RBAC {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	createObjects := func(objs ...client.Object) {
		t.Helper()

		for i := range objs {
			require.NoError(t, c.Create(t.Context(), objs[i]))
		}
	}

	createUser := func(id, subject string, groups []*unikornv1.Group) {
		t.Helper()

		groupids := make([]string, len(groups))
		for i := range groups {
			groupids[i] = groups[i].Name
		}

		userclient := users.New("identity.unikorn-cloud.org", c, testNamespace, nil /* issuer */, &users.Options{
			// luckily these are all to do with email verification, which we don't want to use.
		})
		// this is needed because deep in the bowels of request handling, it's consulted in
		// order to set some Kubernetes object metadata.
		ctx := newContext(t)
		_, err := userclient.Create(ctx, testOrgID, &openapi.UserWrite{
			Metadata: &coreopenapi.ResourceWriteMetadata{
				Name: id,
			},
			Spec: openapi.UserSpec{
				Subject:  subject,
				State:    openapi.Active,
				GroupIDs: groupids,
			},
		})
		require.NoError(t, err)
	}

	// Create Organization.
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

	altOrganization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      altOrgID,
		},
		Spec: unikornv1.OrganizationSpec{},
		Status: unikornv1.OrganizationStatus{
			Namespace: altOrgNS,
		},
	}

	createObjects(organization, altOrganization)
	require.NoError(t, c.Update(t.Context(), organization)) // to update the status with a namespace.

	// Create Roles with different permission scopes.
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

	createObjects(roleAdmin, roleDeveloper, roleReader)

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

	// Group for service accounts
	groupServicesObj := &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      groupServices,
		},
		Spec: unikornv1.GroupSpec{
			RoleIDs:           []string{roleDeveloperID},
			ServiceAccountIDs: []string{serviceAccountAlphaID},
		},
	}

	createObjects(groupAdminsObj, groupReadersObj, groupDevelopersObj, groupServicesObj)

	projectAlpha := &unikornv1.Project{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      projectAlphaID,
			Labels: map[string]string{
				constants.OrganizationLabel: testOrgID,
			},
		},
		Spec: unikornv1.ProjectSpec{
			GroupIDs: []string{groupDevelopers, groupServices}, // Developers and services have access
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
			GroupIDs: []string{groupDevelopers, groupReaders, groupServices}, // Developers, readers, and services
		},
	}

	createObjects(projectAlpha, projectBeta)

	createUser(userAliceID, userAliceSubject, []*unikornv1.Group{groupAdminsObj})
	createUser(userBobID, userBobSubject, []*unikornv1.Group{groupDevelopersObj})
	createUser(userCharlieID, userCharlieSubject, []*unikornv1.Group{groupReadersObj, groupDevelopersObj})

	rbacClient := rbac.New(c, testNamespace, &rbac.Options{})

	return rbacClient
}

// getACLForUser is a helper to get the ACL for a given user subject.
func getACLForUser(t *testing.T, rbacClient *rbac.RBAC, subject string) *openapi.Acl {
	t.Helper()

	// Create authorization info with user subject
	info := &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: subject,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.User,
				OrgIds:  []string{testOrgID},
			},
		},
	}

	ctx := authorization.NewContext(t.Context(), info)

	acl, err := rbacClient.GetACL(ctx, testOrgID)
	require.NoError(t, err)
	require.NotNil(t, acl)

	return acl
}

// TestGroupMigrationACLContent verifies the actual ACL content is correct.
//
//nolint:cyclop
func TestGroupACLContent(t *testing.T) {
	t.Parallel()

	rbacClient := setupTestEnvironment(t)

	// Test Alice (Admin) - should have global and organization permissions.
	aclAlice := getACLForUser(t, rbacClient, userAliceSubject)
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

	// Test Bob (Developer) - should have organization read and project permissions.
	aclBob := getACLForUser(t, rbacClient, userBobSubject)
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

	// Test Charlie (Developer + Reader) - should have merged permissions.
	aclCharlie := getACLForUser(t, rbacClient, userCharlieSubject)
	assert.Nil(t, aclCharlie.Global, "Charlie should not have global permissions")
	assert.NotNil(t, aclCharlie.Organization, "Charlie should have organization permissions")
	assert.NotNil(t, aclCharlie.Projects, "Charlie should have project permissions")
	assert.Len(t, *aclCharlie.Projects, 2, "Charlie should have access to 2 projects")

	// Charlie should have both deploy and read permissions on projects (merged from two groups).
	for _, project := range *aclCharlie.Projects {
		if project.Id == projectAlphaID {
			// Alpha: only developers group, so deploy but no read-specific.
			hasProjectDeploy := false

			for _, endpoint := range project.Endpoints {
				if endpoint.Name == "project:deploy" {
					hasProjectDeploy = true
				}
			}

			require.True(t, hasProjectDeploy, "Charlie should have deploy on project-alpha")
		}

		if project.Id == projectBetaID {
			// Beta: both groups, so should have both deploy and read.
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

// getACLForServiceAccount is a helper to get the ACL for a given service account.
func getACLForServiceAccount(t *testing.T, rbacClient *rbac.RBAC, subject string, orgIDs []string) *openapi.Acl {
	t.Helper()

	// Create authorization info for service account
	info := &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: subject,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.Service,
				OrgIds:  orgIDs,
			},
		},
	}

	ctx := authorization.NewContext(t.Context(), info)

	acl, err := rbacClient.GetACL(ctx, testOrgID)
	require.NoError(t, err)
	require.NotNil(t, acl)

	return acl
}

// TestServiceAccountACL verifies that service accounts get correct permissions via groups.
func TestServiceAccountACL(t *testing.T) {
	t.Parallel()

	rbacClient := setupTestEnvironment(t)

	// Test service account that's a member of the services group
	aclAlpha := getACLForServiceAccount(t, rbacClient, serviceAccountAlphaID, []string{testOrgID})
	assert.Nil(t, aclAlpha.Global, "Service account should not have global permissions")
	assert.NotNil(t, aclAlpha.Organization, "Service account should have organization permissions")
	assert.NotNil(t, aclAlpha.Projects, "Service account should have project permissions")

	// Verify service account has org:read (from developer role)
	hasOrgRead := false

	for _, endpoint := range aclAlpha.Organization.Endpoints {
		if endpoint.Name == "org:read" {
			hasOrgRead = true

			require.Contains(t, endpoint.Operations, openapi.Read)
		}
	}

	assert.True(t, hasOrgRead, "Service account should have org:read permission")

	// Service account should have access to projects (from developer role)
	assert.Len(t, *aclAlpha.Projects, 2, "Service account should have access to 2 projects")

	// Test service account not in any group
	aclBeta := getACLForServiceAccount(t, rbacClient, serviceAccountBetaID, []string{testOrgID})
	assert.Nil(t, aclBeta.Global, "Service account not in groups should not have global permissions")
	assert.Nil(t, aclBeta.Organization, "Service account not in groups should not have organization permissions")
	assert.Nil(t, aclBeta.Projects, "Service account not in groups should not have project permissions")
}

// TestServiceAccountWrongOrganization verifies that service accounts from different orgs fail.
func TestServiceAccountMissingOrganization(t *testing.T) {
	t.Parallel()

	rbacClient := setupTestEnvironment(t)

	// Service account claims to be from a different organization
	info := &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: serviceAccountAlphaID,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.Service,
				OrgIds:  []string{"different-org"},
			},
		},
	}

	ctx := authorization.NewContext(t.Context(), info)

	// This should fail because the organization doesn't exist
	_, err := rbacClient.GetACL(ctx, testOrgID)
	require.Error(t, err, "Should fail when service account's organization doesn't exist")
}

// TestServiceAccountMissingOrgIDs tests error handling when service account has no org IDs.
func TestServiceAccountMissingOrgIDs(t *testing.T) {
	t.Parallel()

	rbacClient := setupTestEnvironment(t)

	// Service account with no org IDs
	info := &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: serviceAccountAlphaID,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.Service,
				OrgIds:  []string{}, // Empty org IDs
			},
		},
	}

	ctx := authorization.NewContext(t.Context(), info)

	_, err := rbacClient.GetACL(ctx, testOrgID)
	require.Error(t, err)
	assert.ErrorIs(t, err, rbac.ErrWrongOrganizationCount)
}

// TestServiceAccountMultipleOrgIDs tests error handling when service account has multiple org IDs.
func TestServiceAccountMultipleOrgIDs(t *testing.T) {
	t.Parallel()

	rbacClient := setupTestEnvironment(t)

	// Service account with multiple org IDs (should only have one)
	info := &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: serviceAccountAlphaID,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.Service,
				OrgIds:  []string{testOrgID, "another-org"},
			},
		},
	}

	ctx := authorization.NewContext(t.Context(), info)

	_, err := rbacClient.GetACL(ctx, testOrgID)
	require.Error(t, err)
	assert.ErrorIs(t, err, rbac.ErrWrongOrganizationCount)
}

func TestServiceAccount_WrongOrganization(t *testing.T) {
	t.Parallel()

	rbacClient := setupTestEnvironment(t)

	// Service account with multiple org IDs (should only have one)
	info := &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: serviceAccountAlphaID,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.Service,
				OrgIds:  []string{testOrgID},
			},
		},
	}

	ctx := authorization.NewContext(t.Context(), info)

	_, err := rbacClient.GetACL(ctx, altOrgID) // <-- asking about **alternative org**
	require.Error(t, err)
	assert.ErrorIs(t, err, rbac.ErrNotInOrganization)
}
