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
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	"sigs.k8s.io/yaml"
)

// chartValuesPath locates the Helm values file that is the single source of truth for
// the built-in role catalogue rendered by charts/identity/templates/roles.yaml. The
// guard test parses it directly so that any change to the role definitions is validated
// against the intended grant relationships.
const chartValuesPath = "../../charts/identity/values.yaml"

// endpointOperations mirrors the map-of-lists shape used under each scope block in
// values.yaml: endpoint name -> granted CRUD operations.
type endpointOperations map[string][]string

type chartRole struct {
	Description string `json:"description"`
	Protected   bool   `json:"protected"`
	Scopes      struct {
		Global       endpointOperations `json:"global"`
		Organization endpointOperations `json:"organization"`
		Project      endpointOperations `json:"project"`
	} `json:"scopes"`
}

type chartValues struct {
	Roles map[string]chartRole `json:"roles"`
}

func loadChartRoles(t *testing.T) map[string]chartRole {
	t.Helper()

	raw, err := os.ReadFile(filepath.Clean(chartValuesPath))
	require.NoError(t, err)

	var values chartValues

	require.NoError(t, yaml.Unmarshal(raw, &values))
	require.NotEmpty(t, values.Roles)

	return values.Roles
}

func toRoleScopes(in endpointOperations) []unikornv1.RoleScope {
	if len(in) == 0 {
		return nil
	}

	scopes := make([]unikornv1.RoleScope, 0, len(in))

	for name, operations := range in {
		ops := make([]unikornv1.Operation, len(operations))
		for i, operation := range operations {
			ops[i] = unikornv1.Operation(operation)
		}

		scopes = append(scopes, unikornv1.RoleScope{Name: name, Operations: ops})
	}

	return scopes
}

// asRole projects a chart role into the stored Role resource AllowRole consumes as the
// grant target.
func asRole(in chartRole) *unikornv1.Role {
	return &unikornv1.Role{
		Spec: unikornv1.RoleSpec{
			Protected: in.Protected,
			Scopes: unikornv1.RoleScopes{
				Global:       toRoleScopes(in.Scopes.Global),
				Organization: toRoleScopes(in.Scopes.Organization),
				Project:      toRoleScopes(in.Scopes.Project),
			},
		},
	}
}

func toACLEndpoints(in endpointOperations) openapi.AclEndpoints {
	endpoints := make(openapi.AclEndpoints, 0, len(in))

	for name, operations := range in {
		ops := make(openapi.AclOperations, len(operations))
		for i, operation := range operations {
			ops[i] = openapi.AclOperation(operation)
		}

		endpoints = append(endpoints, openapi.AclEndpoint{Name: name, Operations: ops})
	}

	return endpoints
}

// aclForHolder builds the effective ACL a principal holding exactly this role would have
// when resolved for organizationID. The organization block lands at organization scope
// and the project block in a single accessible project, exactly as pkg/rbac accumulates
// real group membership. This placement is what makes downscoping observable: a holder's
// project-scoped authority lives under a project, it is not promoted to organization
// scope.
func aclForHolder(in chartRole) *openapi.Acl {
	acl := &openapi.Acl{}

	if len(in.Scopes.Global) > 0 {
		global := toACLEndpoints(in.Scopes.Global)
		acl.Global = &global
	}

	organization := openapi.AclOrganization{Id: organizationID}

	if len(in.Scopes.Organization) > 0 {
		endpoints := toACLEndpoints(in.Scopes.Organization)
		organization.Endpoints = &endpoints
	}

	if len(in.Scopes.Project) > 0 {
		projects := openapi.AclProjectList{
			{Id: projectID, Endpoints: toACLEndpoints(in.Scopes.Project)},
		}
		organization.Projects = &projects
	}

	organizations := openapi.AclOrganizationList{organization}
	acl.Organizations = &organizations

	return acl
}

// TestBuiltinRoleGrantability asserts that AllowRole permits exactly the grants declared
// in the grant tree for every ordered pair of user-facing built-in roles, using the role
// definitions parsed from charts/identity/values.yaml.
func TestBuiltinRoleGrantability(t *testing.T) {
	t.Parallel()

	// grantTree encodes the intended delegation relationships between the user-facing
	// (non-protected) built-in roles. Each granter maps to every role it must be able to
	// grant, i.e. every role whose permission set it fully contains at the same or a
	// narrower scope (a role can always grant itself):
	//
	//	administrator ─┬─ auditor ─── reader
	//	               └─ user ────── reader
	//
	// This is the source of truth for the "X is a superset of Y" relationship. It guards
	// against role-catalogue drift such as the removed application:* endpoints, which were
	// present on user/reader but missing from administrator and thereby silently made
	// user/reader non-grantable by an administrator. Any endpoint added to a leaf role must
	// remain covered by every role above it here, or this test fails.
	grantTree := map[string][]string{
		"administrator": {"administrator", "auditor", "user", "reader"},
		"auditor":       {"auditor", "reader"},
		"user":          {"user", "reader"},
		"reader":        {"reader"},
	}

	roles := loadChartRoles(t)

	// Every user-facing role in the chart must appear in the grant tree so that a newly
	// added role cannot silently escape the guard.
	userFacing := make([]string, 0, len(roles))

	for name, role := range roles {
		if role.Protected {
			continue
		}

		userFacing = append(userFacing, name)

		require.Containsf(t, grantTree, name, "user-facing role %q is missing from grantTree; declare its grant relationships", name)
	}

	slices.Sort(userFacing)

	// Conversely, every role named in the grant tree must be a real, user-facing role,
	// so stale entries cannot mask a deleted or newly-protected role.
	for granter, grantees := range grantTree {
		require.Containsf(t, userFacing, granter, "grantTree references unknown or protected granter %q", granter)

		for _, grantee := range grantees {
			require.Containsf(t, userFacing, grantee, "grantTree references unknown or protected grantee %q", grantee)
		}
	}

	org := ids.MustParseOrganizationID(organizationID)

	for _, granter := range userFacing {
		ctx := rbac.NewContext(t.Context(), aclForHolder(roles[granter]))

		for _, grantee := range userFacing {
			expectGrantable := slices.Contains(grantTree[granter], grantee)

			t.Run(granter+" grants "+grantee, func(t *testing.T) {
				t.Parallel()

				err := rbac.AllowRole(ctx, asRole(roles[grantee]), org)

				if expectGrantable {
					require.NoErrorf(t, err, "%q holds a superset of %q and must be able to grant it, but AllowRole refused", granter, grantee)
				} else {
					require.Errorf(t, err, "%q does not hold a superset of %q and must not be able to grant it, but AllowRole allowed it", granter, grantee)
				}
			})
		}
	}
}
