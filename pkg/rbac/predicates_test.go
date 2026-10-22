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

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// A predicate MUST agree with the gate it mirrors.  They are the same question
// asked for different purposes, and a divergence would mean a principal could
// see a resource in a list that they are then refused access to, or the
// reverse.  Asserting agreement rather than each in isolation is what keeps
// them from drifting apart.
func TestPredicatesAgreeWithTheirGate(t *testing.T) {
	t.Parallel()

	acl := aclFixture()
	orgID := ids.MustParseOrganizationID(organizationID)
	projID := ids.MustParseProjectID(projectID)

	t.Run("organization scope", func(t *testing.T) {
		t.Parallel()

		for _, test := range []struct {
			name      string
			endpoint  string
			operation openapi.AclOperation
		}{
			{"granted", resourceType1, openapi.Read},
			{"wrong operation", resourceType1, openapi.Create},
			{"unknown endpoint", "wibble", openapi.Read},
		} {
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				ctx := rbac.NewContext(t.Context(), acl)

				allowed := rbac.AllowOrganizationScopeID(ctx, test.endpoint, test.operation, orgID) == nil
				require.Equal(t, allowed, rbac.PermitsOrganizationScopeID(ctx, test.endpoint, test.operation, orgID))
			})
		}
	})

	t.Run("project scope", func(t *testing.T) {
		t.Parallel()

		for _, test := range []struct {
			name      string
			endpoint  string
			operation openapi.AclOperation
		}{
			{"granted", resourceType2, openapi.Read},
			{"wrong operation", resourceType2, openapi.Create},
			{"unknown endpoint", "wibble", openapi.Read},
		} {
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				ctx := rbac.NewContext(t.Context(), acl)

				allowed := rbac.AllowProjectScopeID(ctx, test.endpoint, test.operation, orgID, projID) == nil
				require.Equal(t, allowed, rbac.PermitsProjectScopeID(ctx, test.endpoint, test.operation, orgID, projID))
			})
		}
	})

	t.Run("global scope", func(t *testing.T) {
		t.Parallel()

		ctx := rbac.NewContext(t.Context(), acl)

		allowed := rbac.AllowGlobalScope(ctx, resourceType1, openapi.Read) == nil
		require.Equal(t, allowed, rbac.PermitsGlobalScope(ctx, resourceType1, openapi.Read))
	})
}

// The scope-reader and role predicates were the three the agreement test above
// missed, which is how the one predicate that records got in.  Every member of
// the family MUST be covered here: a test named for an invariant only enforces
// it where it actually looks.
func TestEveryPredicateAgreesWithItsGate(t *testing.T) {
	t.Parallel()

	acl := aclFixture()
	orgID := ids.MustParseOrganizationID(organizationID)
	projID := ids.MustParseProjectID(projectID)

	t.Run("organization scope reader", func(t *testing.T) {
		t.Parallel()

		for _, test := range []struct {
			name     string
			endpoint string
			scope    scopeStub
		}{
			{"granted", resourceType1, scopeStub{orgID: orgID}},
			{"unknown endpoint", "wibble", scopeStub{orgID: orgID}},
			{"scope cannot be read", resourceType1, scopeStub{err: errScope}},
		} {
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				ctx := rbac.NewContext(t.Context(), acl)

				allowed := rbac.AllowOrganizationScopeReader(ctx, test.endpoint, openapi.Read, test.scope) == nil
				require.Equal(t, allowed, rbac.PermitsOrganizationScopeReader(ctx, test.endpoint, openapi.Read, test.scope))
			})
		}
	})

	t.Run("project scope reader", func(t *testing.T) {
		t.Parallel()

		for _, test := range []struct {
			name     string
			endpoint string
			scope    scopeStub
		}{
			{"granted", resourceType2, scopeStub{orgID: orgID, projID: projID}},
			{"unknown endpoint", "wibble", scopeStub{orgID: orgID, projID: projID}},
			{"scope cannot be read", resourceType2, scopeStub{err: errScope}},
		} {
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				ctx := rbac.NewContext(t.Context(), acl)

				allowed := rbac.AllowProjectScopeReader(ctx, test.endpoint, openapi.Read, test.scope) == nil
				require.Equal(t, allowed, rbac.PermitsProjectScopeReader(ctx, test.endpoint, openapi.Read, test.scope))
			})
		}
	})

	t.Run("role", func(t *testing.T) {
		t.Parallel()

		for _, test := range []struct {
			name string
			role *unikornv1.Role
		}{
			{"grantable, the principal holds what it confers", roleGranting(resourceType1, openapi.Read)},
			{"not grantable, confers more than the principal holds", roleGranting(resourceType1, openapi.Delete)},
			{"not grantable, confers an endpoint the principal lacks", roleGranting("wibble", openapi.Read)},
		} {
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				ctx := rbac.NewContext(t.Context(), acl)

				allowed := rbac.AllowRole(ctx, test.role, orgID) == nil
				require.Equal(t, allowed, rbac.PermitsRole(ctx, test.role, orgID))
			})
		}
	})
}

// roleGranting builds a role conferring one operation on one endpoint at
// organization scope, which is the smallest thing AllowRole has to walk.
func roleGranting(endpoint string, operation openapi.AclOperation) *unikornv1.Role {
	return &unikornv1.Role{
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Organization: []unikornv1.RoleScope{
					{
						Name:       endpoint,
						Operations: []unikornv1.Operation{unikornv1.Operation(operation)},
					},
				},
			},
		},
	}
}

// The fixture grants read on resourceType1 at organization scope and nothing at
// global scope, so these pin the actual answers rather than only self
// consistency.
func TestPredicatesReturnTheExpectedAnswer(t *testing.T) {
	t.Parallel()

	acl := aclFixture()
	ctx := rbac.NewContext(t.Context(), acl)
	orgID := ids.MustParseOrganizationID(organizationID)
	projID := ids.MustParseProjectID(projectID)

	require.True(t, rbac.PermitsOrganizationScopeID(ctx, resourceType1, openapi.Read, orgID))
	require.False(t, rbac.PermitsOrganizationScopeID(ctx, resourceType1, openapi.Create, orgID))

	require.True(t, rbac.PermitsProjectScopeID(ctx, resourceType2, openapi.Read, orgID, projID))
	require.False(t, rbac.PermitsProjectScopeID(ctx, resourceType2, openapi.Delete, orgID, projID))

	// The fixture grants nothing globally.
	require.False(t, rbac.PermitsGlobalScope(ctx, resourceType1, openapi.Read))
}

// A principal with no ACL at all must be refused rather than panicking, since
// filtering runs on every list.
func TestPredicatesWithoutAnACL(t *testing.T) {
	t.Parallel()

	ctx := rbac.NewContext(t.Context(), &openapi.Acl{})
	orgID := ids.MustParseOrganizationID(organizationID)
	projID := ids.MustParseProjectID(projectID)

	require.False(t, rbac.PermitsGlobalScope(ctx, resourceType1, openapi.Read))
	require.False(t, rbac.PermitsOrganizationScopeID(ctx, resourceType1, openapi.Read, orgID))
	require.False(t, rbac.PermitsProjectScopeID(ctx, resourceType2, openapi.Read, orgID, projID))
}
