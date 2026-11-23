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
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	projectAdministratorRole = "project-administrator"

	projectsEndpoint  = "identity:projects"
	imagesEndpoint    = "region:images"
	networksEndpoint  = "region:networks:v2"
	instancesEndpoint = "compute:instances"

	readerProjectID    = "3b376e8f-5e34-4199-a527-130b3c2dcd20"
	unrelatedProjectID = "9a6c4c1e-2f7a-4d49-8d5b-2b1c1b5a1d77"
)

func sortedOperations(in endpointOperations) endpointOperations {
	out := make(endpointOperations, len(in))

	for endpoint, operations := range in {
		out[endpoint] = slices.Sorted(slices.Values(operations))
	}

	return out
}

func TestProjectAdministratorRoleContract(t *testing.T) {
	t.Parallel()

	roles := loadChartRoles(t)

	role, ok := roles[projectAdministratorRole]
	require.Truef(t, ok, "built-in role %q is missing", projectAdministratorRole)

	t.Run("is not protected", func(t *testing.T) {
		t.Parallel()

		require.False(t, role.Protected, "a protected role is hidden from the API, so no organization can grant it")
	})

	t.Run("organization block equals the reader organization block", func(t *testing.T) {
		t.Parallel()

		require.Equal(t, sortedOperations(roles["reader"].Scopes.Organization), sortedOperations(role.Scopes.Organization))
	})

	t.Run("project block equals the user project block plus project update", func(t *testing.T) {
		t.Parallel()

		expected := maps.Clone(roles["user"].Scopes.Project)
		expected[projectsEndpoint] = []string{"read", "update"}

		require.Equal(t, sortedOperations(expected), sortedOperations(role.Scopes.Project))
	})

	t.Run("holds no global scope", func(t *testing.T) {
		t.Parallel()

		require.Empty(t, role.Scopes.Global)
	})

	forbidden := []struct {
		endpoint   string
		operations []string
	}{
		{endpoint: projectsEndpoint, operations: []string{"create", "delete"}},
		{endpoint: "identity:users"},
		{endpoint: "identity:groups"},
		{endpoint: "identity:roles"},
		{endpoint: "identity:serviceaccounts"},
		{endpoint: "identity:oauth2providers"},
		{endpoint: "identity:organizations"},
		{endpoint: imagesEndpoint, operations: []string{"create", "delete"}},
	}

	scopes := map[string]endpointOperations{
		"global":       role.Scopes.Global,
		"organization": role.Scopes.Organization,
		"project":      role.Scopes.Project,
	}

	for scope, block := range scopes {
		for _, test := range forbidden {
			name := "forbids " + test.endpoint + " at " + scope + " scope"
			if len(test.operations) > 0 {
				name = "forbids " + strings.Join(test.operations, ", ") + " on " + test.endpoint + " at " + scope + " scope"
			}

			t.Run(name, func(t *testing.T) {
				t.Parallel()

				granted := block[test.endpoint]

				if len(test.operations) == 0 {
					require.Emptyf(t, granted, "%s grants no operation on %s at %s scope", projectAdministratorRole, test.endpoint, scope)

					return
				}

				for _, operation := range test.operations {
					require.NotContainsf(t, granted, operation, "%s must not grant %s on %s at %s scope", projectAdministratorRole, operation, test.endpoint, scope)
				}
			})
		}
	}
}

func TestProjectAdministratorEnforcement(t *testing.T) {
	t.Parallel()

	roles := loadChartRoles(t)

	role, ok := roles[projectAdministratorRole]
	require.Truef(t, ok, "built-in role %q is missing", projectAdministratorRole)

	ctx := rbac.NewContext(t.Context(), aclForHolder(role))

	organization := ids.MustParseOrganizationID(organizationID)
	project := ids.MustParseProjectID(projectID)
	otherOrganization := ids.MustParseOrganizationID("208c1d08-7e37-45ac-a9ce-a738c3854613")
	otherProject := ids.MustParseProjectID("3b376e8f-5e34-4199-a527-130b3c2dcd20")

	inProject := func(endpoint string, operation openapi.AclOperation) error {
		return rbac.AllowProjectScopeID(ctx, endpoint, operation, organization, project)
	}

	inOtherProject := func(endpoint string, operation openapi.AclOperation) error {
		return rbac.AllowProjectScopeID(ctx, endpoint, operation, organization, otherProject)
	}

	inOtherOrganization := func(endpoint string, operation openapi.AclOperation) error {
		return rbac.AllowProjectScopeID(ctx, endpoint, operation, otherOrganization, otherProject)
	}

	inOrganization := func(endpoint string, operation openapi.AclOperation) error {
		return rbac.AllowOrganizationScopeID(ctx, endpoint, operation, organization)
	}

	inOtherOrganizationScope := func(endpoint string, operation openapi.AclOperation) error {
		return rbac.AllowOrganizationScopeID(ctx, endpoint, operation, otherOrganization)
	}

	tests := []struct {
		name      string
		check     func(string, openapi.AclOperation) error
		endpoint  string
		operation openapi.AclOperation
		allowed   bool
	}{
		{"networks create in the project", inProject, "region:networks:v2", openapi.Create, true},
		{"networks read in the project", inProject, "region:networks:v2", openapi.Read, true},
		{"networks update in the project", inProject, "region:networks:v2", openapi.Update, true},
		{"networks delete in the project", inProject, "region:networks:v2", openapi.Delete, true},
		{"instances create in the project", inProject, "compute:instances", openapi.Create, true},
		{"instances delete in the project", inProject, "compute:instances", openapi.Delete, true},
		{"clusters read in the project", inProject, "kubernetes:clusters", openapi.Read, true},
		{"clusters update in the project", inProject, "kubernetes:clusters", openapi.Update, true},
		{"clusters delete in the project", inProject, "kubernetes:clusters", openapi.Delete, true},

		{"project read in the project", inProject, projectsEndpoint, openapi.Read, true},
		{"project update in the project", inProject, projectsEndpoint, openapi.Update, true},
		{"project create in the project", inProject, projectsEndpoint, openapi.Create, false},
		{"project delete in the project", inProject, projectsEndpoint, openapi.Delete, false},

		{"networks read in another project", inOtherProject, "region:networks:v2", openapi.Read, false},
		{"instances create in another project", inOtherProject, "compute:instances", openapi.Create, false},
		{"project read in another project", inOtherProject, projectsEndpoint, openapi.Read, false},
		{"project update in another project", inOtherProject, projectsEndpoint, openapi.Update, false},

		{"networks read in another organization", inOtherOrganization, "region:networks:v2", openapi.Read, false},
		{"project update in another organization", inOtherOrganization, projectsEndpoint, openapi.Update, false},
		{"image read in another organization", inOtherOrganizationScope, imagesEndpoint, openapi.Read, false},

		{"project update at organization scope", inOrganization, projectsEndpoint, openapi.Update, false},
		{"project create at organization scope", inOrganization, projectsEndpoint, openapi.Create, false},
		{"project delete at organization scope", inOrganization, projectsEndpoint, openapi.Delete, false},
		{"project read at organization scope", inOrganization, projectsEndpoint, openapi.Read, false},
		{"networks read at organization scope", inOrganization, "region:networks:v2", openapi.Read, false},

		{"groups update at organization scope", inOrganization, "identity:groups", openapi.Update, false},
		{"groups update in the project", inProject, "identity:groups", openapi.Update, false},
		{"service accounts update at organization scope", inOrganization, "identity:serviceaccounts", openapi.Update, false},
		{"service accounts update in the project", inProject, "identity:serviceaccounts", openapi.Update, false},

		{"flavors read at organization scope", inOrganization, "region:flavors", openapi.Read, true},
		{"quotas read at organization scope", inOrganization, "identity:quotas", openapi.Read, true},
		{"image read at organization scope", inOrganization, imagesEndpoint, openapi.Read, true},
		{"image create at organization scope", inOrganization, imagesEndpoint, openapi.Create, false},
		{"image delete at organization scope", inOrganization, imagesEndpoint, openapi.Delete, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.check(test.endpoint, test.operation)

			if test.allowed {
				require.NoError(t, err)
			} else {
				require.True(t, coreerrors.IsForbidden(err), "want 403, got %v", err)
			}
		})
	}

	t.Run("grants its own role in the organization", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, rbac.AllowRole(ctx, asRole(role), organization))
	})

	t.Run("grants no role in another organization", func(t *testing.T) {
		t.Parallel()

		err := rbac.AllowRole(ctx, asRole(role), otherOrganization)
		require.True(t, coreerrors.IsForbidden(err), "want 403, got %v", err)
	})
}

// requireGrantStopsAtProject takes an ACL that holds the project-administrator role in
// the project with projectID and the reader role in the project with readerProjectID.
func requireGrantStopsAtProject(t *testing.T, acl *openapi.Acl, organization string) {
	t.Helper()

	ctx := rbac.NewContext(t.Context(), acl)

	check := func(project, endpoint string, operation openapi.AclOperation) error {
		return rbac.AllowProjectScopeID(ctx, endpoint, operation, ids.MustParseOrganizationID(organization), ids.MustParseProjectID(project))
	}

	tests := []struct {
		name      string
		project   string
		endpoint  string
		operation openapi.AclOperation
		allowed   bool
	}{
		{"administered project, networks update", projectID, networksEndpoint, openapi.Update, true},
		{"administered project, instances create", projectID, instancesEndpoint, openapi.Create, true},
		{"administered project, project update", projectID, projectsEndpoint, openapi.Update, true},

		{"read-only project, networks read", readerProjectID, networksEndpoint, openapi.Read, true},
		{"read-only project, project read", readerProjectID, projectsEndpoint, openapi.Read, true},
		{"read-only project, networks update", readerProjectID, networksEndpoint, openapi.Update, false},
		{"read-only project, instances create", readerProjectID, instancesEndpoint, openapi.Create, false},
		{"read-only project, project update", readerProjectID, projectsEndpoint, openapi.Update, false},

		{"unrelated project, networks read", unrelatedProjectID, networksEndpoint, openapi.Read, false},
		{"unrelated project, networks update", unrelatedProjectID, networksEndpoint, openapi.Update, false},
		{"unrelated project, instances create", unrelatedProjectID, instancesEndpoint, openapi.Create, false},
		{"unrelated project, project update", unrelatedProjectID, projectsEndpoint, openapi.Update, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := check(test.project, test.endpoint, test.operation)

			if test.allowed {
				require.NoError(t, err)
			} else {
				require.True(t, coreerrors.IsForbidden(err), "want 403, got %v", err)
			}
		})
	}
}

func TestProjectAdministratorGrantStopsAtItsProject(t *testing.T) {
	t.Parallel()

	roles := loadChartRoles(t)
	administrator, reader := roles[projectAdministratorRole], roles["reader"]

	organizationEndpoints := toACLEndpoints(administrator.Scopes.Organization)
	projects := openapi.AclProjectList{
		{Id: projectID, Endpoints: toACLEndpoints(administrator.Scopes.Project)},
		{Id: readerProjectID, Endpoints: toACLEndpoints(reader.Scopes.Project)},
	}

	t.Run("from a hand-built ACL", func(t *testing.T) {
		t.Parallel()

		acl := &openapi.Acl{Organizations: &openapi.AclOrganizationList{{
			Id:        organizationID,
			Endpoints: &organizationEndpoints,
			Projects:  &projects,
		}}}

		requireGrantStopsAtProject(t, acl, organizationID)
	})

	t.Run("from the ACL the groups produce", func(t *testing.T) {
		t.Parallel()

		const subject = "project-administrator@example.com"

		scheme := runtime.NewScheme()
		require.NoError(t, corev1.AddToScheme(scheme))
		require.NoError(t, unikornv1.AddToScheme(scheme))

		cli := fake.NewClientBuilder().WithScheme(scheme).Build()

		require.NoError(t, cli.Create(t.Context(), newOrganization(testNamespace, testOrgID, testOrgNS)))

		for _, name := range []string{projectAdministratorRole, "reader"} {
			role := asRole(roles[name])
			role.Namespace, role.Name = testNamespace, name
			require.NoError(t, cli.Create(t.Context(), role))

			require.NoError(t, cli.Create(t.Context(), &unikornv1.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: testOrgNS, Name: "group-" + name},
				Spec: unikornv1.GroupSpec{
					RoleIDs:  []string{name},
					Subjects: []unikornv1.GroupSubject{{ID: subject}},
				},
			}))
		}

		for project, group := range map[string]string{projectID: "group-" + projectAdministratorRole, readerProjectID: "group-reader"} {
			require.NoError(t, cli.Create(t.Context(), &unikornv1.Project{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testOrgNS,
					Name:      project,
					Labels:    map[string]string{constants.OrganizationLabel: testOrgID},
				},
				Spec: unikornv1.ProjectSpec{GroupIDs: []string{group}},
			}))
		}

		acl := getACLForUser(t, rbac.New(cli, testNamespace, &rbac.Options{}), subject)

		requireGrantStopsAtProject(t, acl, testOrgID)
	})
}

func TestProjectAdministratorHoldsNoWorkloadAccessAtOrganizationScope(t *testing.T) {
	t.Parallel()

	role, ok := loadChartRoles(t)[projectAdministratorRole]
	require.Truef(t, ok, "built-in role %q is missing", projectAdministratorRole)
	require.NotEmpty(t, role.Scopes.Project)

	ctx := rbac.NewContext(t.Context(), aclForHolder(role))
	organization := ids.MustParseOrganizationID(organizationID)
	project := ids.MustParseProjectID(projectID)

	for endpoint, operations := range role.Scopes.Project {
		t.Run(endpoint, func(t *testing.T) {
			t.Parallel()

			for _, operation := range operations {
				require.NoErrorf(t, rbac.AllowProjectScopeID(ctx, endpoint, openapi.AclOperation(operation), organization, project),
					"%s must reach %s in its own project", operation, endpoint)
			}

			for _, operation := range []openapi.AclOperation{openapi.Create, openapi.Read, openapi.Update, openapi.Delete} {
				err := rbac.AllowOrganizationScopeID(ctx, endpoint, operation, organization)
				require.Truef(t, coreerrors.IsForbidden(err), "%s on %s at organization scope: want 403, got %v", operation, endpoint, err)
			}
		})
	}
}
