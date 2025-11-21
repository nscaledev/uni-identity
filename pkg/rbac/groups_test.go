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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/users"
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

type fixture struct {
	// Because of the way service account creation works, we can't specify the ID
	// for a service account when creating it; we have to create it then look at
	// the ID it was given.
	serviceAccountAlphaID, serviceAccountBetaID, serviceAccountAltAlphaID string

	rbac *rbac.RBAC
}

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

	serviceAccountAlphaName = "sa-alpha"
	serviceAccountBetaName  = "sa-beta"

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

func createUser(t *testing.T, c client.Client, id, subject string, groups []*unikornv1.Group) {
	t.Helper()

	groupids := make([]string, len(groups))
	for i := range groups {
		groupids[i] = groups[i].Name
	}

	iss := handlercommon.IssuerValue{
		URL:      "https://identity.unikorn-cloud.org",
		Hostname: "identity.unikorn-cloud.org",
	}
	userclient := users.New(c, testNamespace, nil /* JWT issuer */, iss, &users.Options{
		// luckily these are all to do with email verification, which we don't want to use.
	})

	// this is needed because deep in the bowels of request handling, it's consulted in
	// order to set some Kubernetes object metadata.
	ctx := newContext(t)
	_, err := userclient.Create(ctx, testOrgID, &openapi.UserWrite{
		Metadata: &coreapi.ResourceWriteMetadata{
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

func newOrganization(objectNamespace, name, orgNamespace string) *unikornv1.Organization {
	return &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: objectNamespace,
			Name:      name,
		},
		Spec: unikornv1.OrganizationSpec{},
		Status: unikornv1.OrganizationStatus{
			Namespace: orgNamespace,
		},
	}
}

func createServiceAccount(t *testing.T, c client.Client, name, orgID, orgNamespace string) string {
	t.Helper()

	// It would be better to use the API, but creating service accounts needs a token issuer,
	// and that is a pain to set up. So: fake it by creating a record in Kubernetes the way
	// the handler would, rather than going through the API.
	meta := &coreapi.ResourceWriteMetadata{
		Name: name,
	}

	objectMeta := conversion.NewObjectMetadata(meta, orgNamespace).WithOrganization(orgID).Get()
	sa := unikornv1.ServiceAccount{
		ObjectMeta: objectMeta,
		Spec: unikornv1.ServiceAccountSpec{
			Expiry: ptr.To(metav1.NewTime(time.Now().Add(2 * time.Hour))),
		},
	}

	require.NoError(t, c.Create(t.Context(), &sa))

	return sa.Name // hereafter used as the service account ID
}

// setupTestEnvironment creates a comprehensive RBAC test environment with users, groups, roles, and projects.
func setupTestEnvironment(t *testing.T) fixture {
	t.Helper()

	var f fixture

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

	organization := newOrganization(testNamespace, testOrgID, testOrgNS)

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

	f.serviceAccountAlphaID = createServiceAccount(t, c, serviceAccountAlphaName, testOrgID, testOrgNS)
	f.serviceAccountBetaID = createServiceAccount(t, c, serviceAccountBetaName, testOrgID, testOrgNS)
	f.serviceAccountAltAlphaID = createServiceAccount(t, c, serviceAccountAlphaName, altOrgID, altOrgNS)

	// Group for service accounts
	groupServicesObj := &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      groupServices,
		},
		Spec: unikornv1.GroupSpec{
			RoleIDs:           []string{roleDeveloperID},
			ServiceAccountIDs: []string{f.serviceAccountAlphaID},
		},
	}

	// Group in alternate org for the service account there, to check the calculation for Org A does not
	// include permissions from Org B.
	groupAltServicesObj := &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: altOrgNS,
			Name:      groupServices,
		},
		Spec: unikornv1.GroupSpec{
			RoleIDs:           []string{roleDeveloperID},
			ServiceAccountIDs: []string{f.serviceAccountAltAlphaID},
		},
	}

	createObjects(groupAdminsObj, groupReadersObj, groupDevelopersObj, groupServicesObj, groupAltServicesObj)

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

	createUser(t, c, userAliceID, userAliceSubject, []*unikornv1.Group{groupAdminsObj})
	createUser(t, c, userBobID, userBobSubject, []*unikornv1.Group{groupDevelopersObj})
	createUser(t, c, userCharlieID, userCharlieSubject, []*unikornv1.Group{groupReadersObj, groupDevelopersObj})

	rbacClient := rbac.New(c, testNamespace, &rbac.Options{})
	f.rbac = rbacClient

	return f
}

// getACLForUser is a helper to get the ACL for a given user subject.
func getACLForUser(t *testing.T, rbacClient *rbac.RBAC, subject string) *openapi.Acl {
	t.Helper()

	// Create authorization info with user subject
	info := &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: subject,
		},
	}

	ctx := authorization.NewContext(t.Context(), info)

	acl, err := rbacClient.GetACL(ctx, testOrgID)
	require.NoError(t, err)
	require.NotNil(t, acl)

	return acl
}

// TestGroupACLContentOrganizationScoped verifies the actual ACL content is correct.
//
//nolint:cyclop
func TestGroupACLContentOrganizationScoped(t *testing.T) {
	t.Parallel()

	f := setupTestEnvironment(t)

	// Test Alice (Admin) - should have organization permissions.
	aclAlice := getACLForUser(t, f.rbac, userAliceSubject)
	assert.Nil(t, aclAlice.Global, "Alice should not have global permissions")
	assert.NotNil(t, aclAlice.Organization, "Alice should have organization permissions")
	assert.Nil(t, aclAlice.Projects, "Alice should not have project-specific permissions")

	// Test Bob (Developer) - should have organization read and project permissions.
	aclBob := getACLForUser(t, f.rbac, userBobSubject)
	assert.Nil(t, aclBob.Global, "Bob should not have global permissions")
	assert.NotNil(t, aclBob.Organization, "Bob should have organization permissions")
	assert.NotNil(t, aclBob.Organization.Endpoints, "Bob should have organization endpoints")
	assert.NotNil(t, aclBob.Projects, "Bob should have project permissions")
	assert.Len(t, *aclBob.Projects, 2, "Bob should have access to 2 projects (alpha and beta)")

	// Verify Bob has org:read
	hasOrgRead := false

	for _, endpoint := range *aclBob.Organization.Endpoints {
		if endpoint.Name == "org:read" {
			hasOrgRead = true

			require.Contains(t, endpoint.Operations, openapi.Read)
		}
	}

	assert.True(t, hasOrgRead, "Bob should have org:read permission")

	// Test Charlie (Developer + Reader) - should have merged permissions.
	aclCharlie := getACLForUser(t, f.rbac, userCharlieSubject)
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

// TestGroupACLContent verifies the actual ACL content is correct.
//
//nolint:cyclop
func TestGroupACLContent(t *testing.T) {
	t.Parallel()

	f := setupTestEnvironment(t)

	// Test Alice (Admin) - should have organization permissions.
	aclAlice := getACLForUser(t, f.rbac, userAliceSubject)
	require.Nil(t, aclAlice.Global, "Alice should not have global permissions")
	require.NotNil(t, aclAlice.Organizations, "Alice should have organization permissions")

	// Test Bob (Developer) - should have organization read and project permissions.
	aclBob := getACLForUser(t, f.rbac, userBobSubject)
	require.Nil(t, aclBob.Global, "Bob should not have global permissions")
	require.NotNil(t, aclBob.Organizations, "Bob should have organization permissions")
	require.Len(t, *aclBob.Organizations, 1, "Bob should be a member of one organization")

	bobOrganization := &(*aclBob.Organizations)[0]
	require.Equal(t, testOrgID, bobOrganization.Id, "Bob should have organization ID set")
	require.NotNil(t, bobOrganization.Endpoints, "Bob should have organization permissions")
	require.NotNil(t, bobOrganization.Projects, "Bob should have project permissions")
	require.Len(t, *bobOrganization.Projects, 2, "Bob should have access to 2 projects (alpha and beta)")

	// Verify Bob has org:read
	hasOrgRead := false

	for _, endpoint := range *bobOrganization.Endpoints {
		if endpoint.Name == "org:read" {
			hasOrgRead = true

			require.Contains(t, endpoint.Operations, openapi.Read)
		}
	}

	require.True(t, hasOrgRead, "Bob should have org:read permission")

	// Test Charlie (Developer + Reader) - should have merged permissions.
	aclCharlie := getACLForUser(t, f.rbac, userCharlieSubject)
	require.Nil(t, aclCharlie.Global, "Charlie should not have global permissions")
	require.NotNil(t, aclCharlie.Organizations, "Charlie should have organization permissions")
	require.Len(t, *aclCharlie.Organizations, 1, "Charlie should be a member of one organization")

	charlieOrganization := &(*aclCharlie.Organizations)[0]
	assert.NotNil(t, charlieOrganization.Projects, "Charlie should have project permissions")
	assert.Len(t, *charlieOrganization.Projects, 2, "Charlie should have access to 2 projects")

	// Charlie should have both deploy and read permissions on projects (merged from two groups).
	for _, project := range *charlieOrganization.Projects {
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
func getACLForServiceAccount(t *testing.T, rbacClient *rbac.RBAC, subject string) *openapi.Acl {
	t.Helper()

	// Create authorization info for service account
	info := &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: subject,
		},
		ServiceAccount: true,
	}

	ctx := authorization.NewContext(t.Context(), info)

	acl, err := rbacClient.GetACL(ctx, testOrgID)
	require.NoError(t, err)
	require.NotNil(t, acl)

	return acl
}

// TestServiceAccountACLOrganizationScoped verifies that service accounts get correct permissions via groups.
func TestServiceAccountACLOrganizationScoped(t *testing.T) {
	t.Parallel()

	f := setupTestEnvironment(t)

	// Test service account that's a member of the services group
	aclAlpha := getACLForServiceAccount(t, f.rbac, f.serviceAccountAlphaID)
	assert.Nil(t, aclAlpha.Global, "Service account should not have global permissions")
	assert.NotNil(t, aclAlpha.Organization, "Service account should have organization permissions")
	assert.NotNil(t, aclAlpha.Organization.Endpoints, "Service account should have organization endpoints")
	assert.NotNil(t, aclAlpha.Projects, "Service account should have project permissions")

	// Verify service account has org:read (from developer role)
	hasOrgRead := false

	for _, endpoint := range *aclAlpha.Organization.Endpoints {
		if endpoint.Name == "org:read" {
			hasOrgRead = true

			require.Contains(t, endpoint.Operations, openapi.Read)
		}
	}

	assert.True(t, hasOrgRead, "Service account should have org:read permission")

	// Service account should have access to projects (from developer role)
	assert.Len(t, *aclAlpha.Projects, 2, "Service account should have access to 2 projects")

	// Test service account not in any group
	aclBeta := getACLForServiceAccount(t, f.rbac, f.serviceAccountBetaID)
	assert.Nil(t, aclBeta.Global, "Service account not in groups should not have global permissions")
	assert.Nil(t, aclBeta.Organization, "Service account not in groups should not have organization permissions")
	assert.Nil(t, aclBeta.Projects, "Service account not in groups should not have project permissions")
}

func TestServiceAccountOrganizationScoped_WrongOrganization(t *testing.T) {
	t.Parallel()

	f := setupTestEnvironment(t)

	aclAlpha := getACLForServiceAccount(t, f.rbac, f.serviceAccountAltAlphaID)
	assert.Empty(t, aclAlpha.Organization, "Service account bound to org B should have no permissions in org A")
	assert.Empty(t, aclAlpha.Projects, "Service account bound to org B should have no permissions in org A")
}

func TestServiceAccountACL(t *testing.T) {
	t.Parallel()

	f := setupTestEnvironment(t)

	// Test service account that's a member of the services group
	aclAlpha := getACLForServiceAccount(t, f.rbac, f.serviceAccountAlphaID)
	require.Nil(t, aclAlpha.Global, "Service account should not have global permissions")
	require.NotNil(t, aclAlpha.Organizations, "Service account should have organization permissions")

	alphaOrganizations := *aclAlpha.Organizations
	require.Len(t, alphaOrganizations, 1, "Service account should have one organization")

	alphaOrganization := &alphaOrganizations[0]
	assert.NotNil(t, alphaOrganization.Endpoints, "Service account should have organization endpoints")
	assert.NotNil(t, alphaOrganization.Projects, "Service account should have project permissions")

	// Verify service account has org:read (from developer role)
	hasOrgRead := false

	for _, endpoint := range *alphaOrganization.Endpoints {
		if endpoint.Name == "org:read" {
			hasOrgRead = true

			require.Contains(t, endpoint.Operations, openapi.Read)
		}
	}

	assert.True(t, hasOrgRead, "Service account should have org:read permission")

	// Service account should have access to projects (from developer role)
	assert.Len(t, *aclAlpha.Projects, 2, "Service account should have access to 2 projects")

	// Test service account not in any group
	aclBeta := getACLForServiceAccount(t, f.rbac, f.serviceAccountBetaID)
	assert.Nil(t, aclBeta.Global, "Service account not in groups should not have global permissions")
	assert.Nil(t, aclBeta.Organizations, "Service account not in groups should not have organization permissions")
}

func TestServiceAccount_WrongOrganization(t *testing.T) {
	t.Parallel()

	f := setupTestEnvironment(t)

	aclAlpha := getACLForServiceAccount(t, f.rbac, f.serviceAccountAltAlphaID)
	require.NotNil(t, aclAlpha.Organizations, "Service account should have organization permissions")

	alphaOrganizations := *aclAlpha.Organizations
	require.Len(t, alphaOrganizations, 1, "Service account should have one organization")

	alphaOrganization := &alphaOrganizations[0]
	require.Equal(t, altOrgID, alphaOrganization.Id, "Service account should have permissions for the organization it's bound to")
}
