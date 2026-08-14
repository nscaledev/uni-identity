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

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"

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

	return setupImpersonationEnvironmentWithBindings(t, serviceGlobalScopes, rbac.Options{})
}

// setupImpersonationEnvironmentWithBindings is setupImpersonationEnvironment
// with control over the full rbac.Options (so tests can set GlobalRoleBindings)
// and extra Role fixtures beyond the fixed impersonation-service role.
func setupImpersonationEnvironmentWithBindings(t *testing.T, serviceGlobalScopes []unikornv1.RoleScope, opts rbac.Options, extraRoles ...*unikornv1.Role) fixture {
	t.Helper()

	f, c := setupTestEnvironment(t)

	for _, r := range extraRoles {
		require.NoError(t, c.Create(t.Context(), r))
	}

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

	opts.SystemAccountRoleIDs = map[string]string{impersonationServiceCN: roleImpersonationService}
	f.rbac = rbac.New(c, testNamespace, &opts)

	return f
}

// impersonate is a convenience wrapper that calls getACLForSystemAccount with the
// standard impersonation service CN and impersonate=true.
func impersonate(t *testing.T, f fixture, userSubject string) *openapi.Acl {
	t.Helper()

	acl, err := getACLForSystemAccount(t, f.rbac, impersonationServiceCN, &principal.Principal{
		Type:            openapi.User,
		Actor:           userSubject,
		OrganizationIDs: []string{testOrgID},
	}, true)
	require.NoError(t, err)

	return acl
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

// TestImpersonation_UniExactBindingIntersectsWithServiceACL pins the full
// impersonation path for the ID-398 spec requirement that a uni-exact global
// role binding stays intersected with the calling service's ACL. The
// impersonated actor's subject matches a binding on the UNI sentinel
// (processImpersonatedPrincipalACL always resolves impersonated user
// principals at that issuer), so processUserAccountACL grants the binding's
// global scopes and skips membership resolution entirely (replace
// semantics) — but the confused-deputy intersection in getSystemAccountACL
// still strips whatever the impersonating service itself is not permitted
// to touch.
func TestImpersonation_UniExactBindingIntersectsWithServiceACL(t *testing.T) {
	t.Parallel()

	const boundRoleID = "role-uni-binding"

	boundRole := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      boundRoleID,
		},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Global: []unikornv1.RoleScope{
					{Name: "identity:organizations", Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Read, unikornv1.Update, unikornv1.Delete}},
					{Name: "identity:other", Operations: []unikornv1.Operation{unikornv1.Read}},
				},
			},
		},
	}

	f := setupImpersonationEnvironmentWithBindings(t,
		// Service ACL allows read on identity:organizations — a strict
		// subset of the binding's grant, giving the intersection something
		// to strip on both endpoints (partial-verb strip, full-endpoint drop).
		// It also allows org:read: if replace semantics did NOT hold and Bob's
		// own org membership were resolved, his org-scoped org:read grant
		// would survive the intersection and land in acl.Organization,
		// falsifying the assert.Nil below.
		[]unikornv1.RoleScope{
			{Name: "identity:organizations", Operations: []unikornv1.Operation{unikornv1.Read}},
			{Name: "org:read", Operations: []unikornv1.Operation{unikornv1.Read}},
		},
		rbac.Options{
			GlobalRoleBindings: rbac.GlobalRoleBindingsValue{
				{Issuer: constants.UNISentinel, Subject: userBobSubject, RoleIDs: []string{boundRoleID}},
			},
		},
		boundRole,
	)

	acl := impersonate(t, f, userBobSubject)

	require.NotNil(t, acl.Global)
	assert.Equal(t, openapi.AclEndpoints{{Name: "identity:organizations", Operations: []openapi.AclOperation{openapi.Read}}}, *acl.Global)

	// Replace semantics under impersonation: membership resolution was
	// skipped for the bound actor, so nothing outside Global should appear.
	assert.Nil(t, acl.Organization)
	assert.Nil(t, acl.Organizations)
	assert.Nil(t, acl.Projects)
}

// TestImpersonatedPrincipalNeverMatchesGroupBindings pins spec §2: an
// impersonated principal whose (hypothetical) groups would match a
// configured group binding still gets NO group-derived global scopes.
// processImpersonatedPrincipalACL always resolves impersonated user
// principals against the UNI sentinel issuer with nil groups, and group
// bindings are rejected outright on the sentinel at flag-parse time
// (validateGroupBindingIssuer rejects idconstants.UNISentinel), so a group
// binding is structurally unreachable on this path, not merely unmatched.
// This gap is functional as well as protective: group-derived authority
// deliberately does not survive a delegated hop, exactly like today's
// external-issuer subject bindings.
func TestImpersonatedPrincipalNeverMatchesGroupBindings(t *testing.T) {
	t.Parallel()

	const boundRoleID = "role-group-bound"

	boundRole := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      boundRoleID,
		},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Global: []unikornv1.RoleScope{
					{Name: "identity:organizations", Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Read, unikornv1.Update, unikornv1.Delete}},
				},
			},
		},
	}

	// The service ACL grants the same scopes the binding would grant, so a
	// leak isn't hidden by the confused-deputy intersection: if the group
	// binding matched at all, its scopes would survive to acl.Global below.
	f := setupImpersonationEnvironmentWithBindings(t,
		[]unikornv1.RoleScope{
			{Name: "identity:organizations", Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Read, unikornv1.Update, unikornv1.Delete}},
		},
		rbac.Options{
			GlobalGroupRoleBindings: rbac.GlobalGroupRoleBindingsValue{
				{Issuer: "https://staff.example.com/", Group: "Platform Engineering", RoleIDs: []string{boundRoleID}},
			},
		},
		boundRole,
	)

	acl := impersonate(t, f, userBobSubject)

	assert.Nil(t, acl.Global, "impersonated principal acquired global scopes from a group binding")
}
