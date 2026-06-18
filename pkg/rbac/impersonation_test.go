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

package rbac_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	impersonationServiceCN   = "impersonation-service"
	roleImpersonationService = "role-impersonation-service"
)

// setupImpersonationEnvironment builds on the standard test environment by adding a
// registered system account role whose global scopes are provided by the caller.
// This allows each test to specify exactly what the impersonating service is allowed
// to do, keeping test intent clear.
func setupImpersonationEnvironment(t *testing.T, serviceGlobalScopes []unikornv1.RoleScope) fixture {
	t.Helper()

	f, c := setupTestEnvironment(t)

	serviceRole := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      roleImpersonationService,
		},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Global: serviceGlobalScopes,
			},
		},
	}
	require.NoError(t, c.Create(t.Context(), serviceRole))

	f.rbac = rbac.New(c, testNamespace, &rbac.Options{
		SystemAccountRoleIDs: map[string]string{impersonationServiceCN: roleImpersonationService},
	})

	return f
}

// impersonate is a convenience wrapper that calls getACLForSystemAccount with the
// standard impersonation service CN and impersonate=true.
func impersonate(t *testing.T, f fixture, userSubject string) *openapi.Acl {
	t.Helper()

	acl, err := getACLForSystemAccount(t, f.rbac, impersonationServiceCN, &principal.Principal{
		Type:  openapi.User,
		Actor: userSubject,
	}, true)
	require.NoError(t, err)

	return acl
}

// TestImpersonation_DoesNotLeakOtherOrganizations is the confused-deputy
// regression: a principal is strictly scoped to one organization, so a service
// impersonating a user *in one organization* must never reach that user's
// permissions in any *other* organization, even when the service's own ACL is a
// global superset. Eve is a developer in both testOrgID and altOrgID; the
// impersonated request is scoped to testOrgID, so altOrgID must not appear.
func TestImpersonation_DoesNotLeakOtherOrganizations(t *testing.T) {
	t.Parallel()

	_, c := setupTestEnvironment(t)
	ctx := t.Context()

	// A registered impersonation service with a broad global ACL, so the
	// intersection cannot mask a leak.
	serviceRole := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: roleImpersonationService},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Global: []unikornv1.RoleScope{
					{Name: "org:read", Operations: []unikornv1.Operation{unikornv1.Read}},
					{Name: "project:read", Operations: []unikornv1.Operation{unikornv1.Read}},
					{Name: "project:deploy", Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Update}},
				},
			},
		},
	}
	require.NoError(t, c.Create(ctx, serviceRole))

	const (
		eveID      = "user-eve"
		eveSubject = "eve@example.com"
	)

	// Eve is a developer in testOrgID (via the standard fixture group)...
	createUser(t, c, eveID, eveSubject, []*unikornv1.Group{{ObjectMeta: metav1.ObjectMeta{Name: groupDevelopers}}})

	// The global user resource name is what OrganizationUser membership is keyed
	// on; resolve it rather than assuming the display name.
	eveUser, err := userdb.NewUserDatabase(c, testNamespace).GetActiveUser(ctx, eveSubject)
	require.NoError(t, err)

	// ...and also an active member, with developer permissions, in altOrgID.
	require.NoError(t, c.Create(ctx, &unikornv1.OrganizationUser{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: altOrgNS,
			Name:      "orguser-eve-alt",
			Labels: map[string]string{
				constants.UserLabel:         eveUser.Name,
				constants.OrganizationLabel: altOrgID,
			},
		},
		Spec: unikornv1.OrganizationUserSpec{State: unikornv1.UserStateActive},
	}))
	require.NoError(t, c.Create(ctx, &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{Namespace: altOrgNS, Name: "alt-developers"},
		Spec: unikornv1.GroupSpec{
			RoleIDs:  []string{roleDeveloperID},
			Subjects: []unikornv1.GroupSubject{{ID: eveSubject}},
		},
	}))

	rbacClient := rbac.New(c, testNamespace, &rbac.Options{
		SystemAccountRoleIDs: map[string]string{impersonationServiceCN: roleImpersonationService},
	})

	// Sanity: Eve's own unscoped ACL really does include altOrgID, so the
	// confinement assertion below is meaningful and not vacuous.
	directInfo := &authorization.Info{
		Userinfo: &openapi.Userinfo{Sub: eveSubject, HttpsunikornCloudOrgauthz: &openapi.AuthClaims{Acctype: openapi.User}},
	}
	directACL, err := rbacClient.GetACL(authorization.NewContext(ctx, directInfo), "")
	require.NoError(t, err)
	require.NotNil(t, directACL.Organizations)
	require.True(t, orgListContains(directACL.Organizations, altOrgID),
		"sanity: Eve must directly hold permissions in altOrgID")

	// Impersonated, scoped to testOrgID: altOrgID must not appear anywhere.
	impersonated, err := getACLForSystemAccount(t, rbacClient, impersonationServiceCN,
		&principal.Principal{Type: openapi.User, Actor: eveSubject, OrganizationID: testOrgID}, true)
	require.NoError(t, err)

	if impersonated.Organizations != nil {
		require.False(t, orgListContains(impersonated.Organizations, altOrgID),
			"impersonation leaked the actor's other organization")
	}

	if impersonated.Organization != nil {
		require.NotEqual(t, altOrgID, impersonated.Organization.Id,
			"impersonation leaked the actor's other organization as the scoped org")
	}
}

func orgListContains(orgs *openapi.AclOrganizationList, id string) bool {
	if orgs == nil {
		return false
	}

	for _, o := range *orgs {
		if o.Id == id {
			return true
		}
	}

	return false
}

// TestImpersonation_ServiceHasGlobalSuperset_UserACLPassesThroughUnchanged verifies
// that when the service's global ACL is a superset of the user's permissions, the
// impersonated ACL equals the user's direct ACL.
func TestImpersonation_ServiceHasGlobalSuperset_UserACLPassesThroughUnchanged(t *testing.T) {
	t.Parallel()

	f := setupImpersonationEnvironment(t, []unikornv1.RoleScope{
		{Name: "org:read", Operations: []unikornv1.Operation{unikornv1.Read}},
		{Name: "project:deploy", Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Update}},
		{Name: "project:read", Operations: []unikornv1.Operation{unikornv1.Read}},
	})

	// Bob has org:read and project:deploy. Both are in the service allow-list so his
	// full ACL should pass through unchanged.
	aclDirect := getACLForUser(t, f.rbac, userBobSubject)
	aclImpersonated := impersonate(t, f, userBobSubject)

	assert.Equal(t, aclDirect, aclImpersonated)
}

// TestImpersonation_ServiceHasGlobalProjectRead_UserProjectDeployStripped verifies
// that project:deploy is stripped when the service only allows project:read globally.
func TestImpersonation_ServiceHasGlobalProjectRead_UserProjectDeployStripped(t *testing.T) {
	t.Parallel()

	// Service only permits project:read globally.
	f := setupImpersonationEnvironment(t, []unikornv1.RoleScope{
		{Name: "project:read", Operations: []unikornv1.Operation{unikornv1.Read}},
	})

	// Charlie has project:read and project:deploy on beta; project:deploy on alpha.
	// Scoped project permissions land in acl.Projects (top-level), not acl.Organization.Projects.
	// After intersection: only project:read survives; alpha (deploy-only) is dropped.
	acl := impersonate(t, f, userCharlieSubject)

	// org:read is not in the service allow-list, so Organization should be nil.
	assert.Nil(t, acl.Organization)

	require.NotNil(t, acl.Projects)

	projects := *acl.Projects

	for _, proj := range projects {
		for _, ep := range proj.Endpoints {
			assert.NotEqual(t, "project:deploy", ep.Name, "project:deploy should be stripped in project %s", proj.Id)
		}
	}

	// project-alpha only had project:deploy for Charlie, so it should be gone.
	for _, proj := range projects {
		assert.NotEqual(t, projectAlphaID, proj.Id, "project-alpha should be dropped as all its endpoints were stripped")
	}
}

// TestImpersonation_ServiceHasGlobalOrgRead_UserOrgReadPermitted verifies that an
// org-scoped org:read in the user's ACL passes through when the service allows it globally.
func TestImpersonation_ServiceHasGlobalOrgRead_UserOrgReadPermitted(t *testing.T) {
	t.Parallel()

	f := setupImpersonationEnvironment(t, []unikornv1.RoleScope{
		{Name: "org:read", Operations: []unikornv1.Operation{unikornv1.Read}},
	})

	// Bob has org:read at organization scope. The service allows it globally,
	// so it should appear in the impersonated ACL.
	acl := impersonate(t, f, userBobSubject)

	require.NotNil(t, acl.Organization, "org-scoped org:read should survive intersection")
	require.NotNil(t, acl.Organization.Endpoints)

	hasOrgRead := false

	for _, ep := range *acl.Organization.Endpoints {
		if ep.Name == "org:read" {
			hasOrgRead = true

			assert.Contains(t, ep.Operations, openapi.Read)
		}
	}

	assert.True(t, hasOrgRead, "org:read should be present after intersection")
}

// TestImpersonation_ServiceLacksResource_UserPermissionsForThatResourceStripped verifies
// that when the service has no permission for a resource, the user's permissions for
// that resource are fully stripped regardless of scope.
func TestImpersonation_ServiceLacksResource_UserPermissionsForThatResourceStripped(t *testing.T) {
	t.Parallel()

	// Service only has a completely unrelated resource — nothing the test users have.
	f := setupImpersonationEnvironment(t, []unikornv1.RoleScope{
		{Name: "unrelated:resource", Operations: []unikornv1.Operation{unikornv1.Read}},
	})

	acl := impersonate(t, f, userBobSubject)

	assert.Nil(t, acl.Global)
	assert.Nil(t, acl.Organization)
	assert.Nil(t, acl.Organizations)
	assert.Nil(t, acl.Projects)
}

// TestImpersonation_ServiceHasSubsetOfOperations_ExcessUserOperationsStripped verifies
// that when the service allows only a subset of operations on a resource, operations
// the service does not hold are stripped from the user's ACL.
func TestImpersonation_ServiceHasSubsetOfOperations_ExcessUserOperationsStripped(t *testing.T) {
	t.Parallel()

	// Service allows project:deploy read-only. Bob has project:deploy create+update.
	// None of Bob's operations appear in the service allow-list, so the project
	// entries should be dropped entirely.
	f := setupImpersonationEnvironment(t, []unikornv1.RoleScope{
		{Name: "project:deploy", Operations: []unikornv1.Operation{unikornv1.Read}},
	})

	acl := impersonate(t, f, userBobSubject)

	// org:read is not in the service allow-list either, so Organization should be nil.
	assert.Nil(t, acl.Organization)
	assert.Nil(t, acl.Organizations)

	// project:deploy [create, update] ∩ project:deploy [read] = ∅ → projects dropped.
	assert.Nil(t, acl.Projects)
}

// TestImpersonation_ServiceHasNoPermissions_EmptyACLReturned verifies that a service
// with an empty role yields a fully empty impersonated ACL regardless of the user's
// own permissions.
func TestImpersonation_ServiceHasNoPermissions_EmptyACLReturned(t *testing.T) {
	t.Parallel()

	f := setupImpersonationEnvironment(t, []unikornv1.RoleScope{})

	acl := impersonate(t, f, userCharlieSubject)

	assert.Nil(t, acl.Global)
	assert.Nil(t, acl.Organization)
	assert.Nil(t, acl.Organizations)
	assert.Nil(t, acl.Projects)
}
