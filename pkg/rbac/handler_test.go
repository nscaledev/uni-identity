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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	"k8s.io/apimachinery/pkg/labels"
)

const (
	organizationID = "foo"
	projectID      = "bar"
	resourceType1  = "candy"
	resourceType2  = "cookie"
)

func aclFixture() *openapi.Acl {
	return &openapi.Acl{
		Organizations: &openapi.AclOrganizationList{
			{
				Id: organizationID,
				Endpoints: &openapi.AclEndpoints{
					{
						Name: resourceType1,
						Operations: openapi.AclOperations{
							openapi.Read,
						},
					},
				},
				Projects: &openapi.AclProjectList{
					{
						Id: projectID,
						Endpoints: openapi.AclEndpoints{
							{
								Name: resourceType2,
								Operations: openapi.AclOperations{
									openapi.Read,
								},
							},
						},
					},
				},
			},
		},
	}
}

// TestUnscopedACL ensures HTTP handlers operate correctly on unscoped ACLs.
func TestUnscopedACL(t *testing.T) {
	t.Parallel()

	acl := aclFixture()

	tests := []struct {
		Name           string
		OrganizationID string
		ProjectID      string
		Resource       string
		Operation      openapi.AclOperation
		ShouldFail     bool
	}{
		{
			Name:           "Accept Organization Scoped Resource With Organization Privilege",
			OrganizationID: organizationID,
			Resource:       resourceType1,
			Operation:      openapi.Read,
		},
		{
			Name:           "Reject Organization Scoped Resource With Wrong Organization",
			OrganizationID: "wibble",
			Resource:       resourceType1,
			Operation:      openapi.Create,
			ShouldFail:     true,
		},
		{
			Name:           "Reject Organization Scoped Resource With No Privilege",
			OrganizationID: organizationID,
			Resource:       "wibble",
			Operation:      openapi.Read,
			ShouldFail:     true,
		},
		{
			Name:           "Reject Organization Scoped Resource With Wrong Privilege",
			OrganizationID: organizationID,
			Resource:       resourceType1,
			Operation:      openapi.Create,
			ShouldFail:     true,
		},
		{
			Name:           "Accept Project Scoped Resource With Organization Privilege",
			OrganizationID: organizationID,
			ProjectID:      projectID,
			Resource:       resourceType1,
			Operation:      openapi.Read,
		},
		{
			Name:           "Reject Project Scoped Resource With Wrong Organization",
			OrganizationID: "wibble",
			ProjectID:      projectID,
			Resource:       resourceType1,
			Operation:      openapi.Read,
			ShouldFail:     true,
		},
		{
			Name:           "Reject Project Scoped Resource With No Organization Privilege",
			OrganizationID: organizationID,
			ProjectID:      projectID,
			Resource:       "wibble",
			Operation:      openapi.Read,
			ShouldFail:     true,
		},
		{
			Name:           "Reject Project Scoped Resource With Wrong Organization Privilege",
			OrganizationID: organizationID,
			ProjectID:      projectID,
			Resource:       resourceType1,
			Operation:      openapi.Create,
			ShouldFail:     true,
		},
		{
			Name:           "Accept Project Scoped Resource With Project Privilege",
			OrganizationID: organizationID,
			ProjectID:      projectID,
			Resource:       resourceType2,
			Operation:      openapi.Read,
		},
		{
			Name:           "Reject Project Scoped Resource With Wrong Organization",
			OrganizationID: "wibble",
			ProjectID:      projectID,
			Resource:       resourceType2,
			Operation:      openapi.Read,
			ShouldFail:     true,
		},
		{
			Name:           "Reject Project Scoped Resource With No Project Privilege",
			OrganizationID: organizationID,
			ProjectID:      projectID,
			Resource:       "wibble",
			Operation:      openapi.Read,
			ShouldFail:     true,
		},
		{
			Name:           "Reject Project Scoped Resource With Wrong Project Privilege",
			OrganizationID: organizationID,
			ProjectID:      projectID,
			Resource:       resourceType2,
			Operation:      openapi.Create,
			ShouldFail:     true,
		},
	}

	for i := range tests {
		test := &tests[i]

		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			//nolint:nestif
			if test.ProjectID != "" {
				err := rbac.AllowProjectScope(rbac.NewContext(t.Context(), acl), test.Resource, test.Operation, test.OrganizationID, test.ProjectID)
				if test.ShouldFail {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
			} else {
				err := rbac.AllowOrganizationScope(rbac.NewContext(t.Context(), acl), test.Resource, test.Operation, test.OrganizationID)
				if test.ShouldFail {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
			}
		})
	}
}

const (
	organizationID1 = "foo"
	projectID1_1    = "bar"
	projectID1_2    = "baz"
	organizationID2 = "foo2"
	projectID2_1    = "bar2"
	projectID2_2    = "baz2"
)

func aclFilterFixturePlatformAdmin() *openapi.Acl {
	return &openapi.Acl{}
}

func aclFilterFixtureAdmin() *openapi.Acl {
	return &openapi.Acl{
		Organizations: &openapi.AclOrganizationList{
			{
				Id: organizationID1,
			},
			{
				Id: organizationID2,
			},
		},
	}
}

func aclFilterFixtureUser() *openapi.Acl {
	return &openapi.Acl{
		Organizations: &openapi.AclOrganizationList{
			{
				Id: organizationID1,
				Projects: &openapi.AclProjectList{
					{
						Id: projectID1_1,
					},
					{
						Id: projectID1_2,
					},
				},
			},
			{
				Id: organizationID2,
				Projects: &openapi.AclProjectList{
					{
						Id: projectID2_1,
					},
					{
						Id: projectID2_2,
					},
				},
			},
		},
	}
}

func TestUnscopedACLFiltersAdmin(t *testing.T) {
	t.Parallel()

	acl := aclFilterFixtureAdmin()

	organizationIDs := rbac.OrganizationIDs(rbac.NewContext(t.Context(), acl))
	require.Len(t, organizationIDs, 2)
	require.Equal(t, organizationID1, organizationIDs[0])
	require.Equal(t, organizationID2, organizationIDs[1])
}

// TestUnscopedACLFiltersUser tests filtering e.g. limiting via label selection to reduce
// the working set size before doing a full RBAC check.
func TestUnscopedACLFiltersUser(t *testing.T) {
	t.Parallel()

	acl := aclFilterFixtureUser()

	organizationIDs := rbac.OrganizationIDs(rbac.NewContext(t.Context(), acl))
	require.Len(t, organizationIDs, 2)
	require.Equal(t, organizationID1, organizationIDs[0])
	require.Equal(t, organizationID2, organizationIDs[1])
}

func userOrganizationSelector(t *testing.T, query []string) labels.Selector {
	t.Helper()

	selector, err := rbac.AddOrganizationIDQuery(rbac.NewContext(t.Context(), aclFilterFixtureUser()), labels.Everything(), query)
	require.NoError(t, err)

	return selector
}

func adminOrganizationSelector(t *testing.T, query []string) labels.Selector {
	t.Helper()

	selector, err := rbac.AddOrganizationIDQuery(rbac.NewContext(t.Context(), aclFilterFixtureAdmin()), labels.Everything(), query)
	require.NoError(t, err)

	return selector
}

func platformAdminOrganizationSelector(t *testing.T, query []string) labels.Selector {
	t.Helper()

	selector, err := rbac.AddOrganizationIDQuery(rbac.NewContext(t.Context(), aclFilterFixturePlatformAdmin()), labels.Everything(), query)
	require.NoError(t, err)

	return selector
}

func userOrganizationAndProjectSelector(t *testing.T, organizationQuery, projectQuery []string) labels.Selector {
	t.Helper()

	selector, err := rbac.AddOrganizationAndProjectIDQuery(rbac.NewContext(t.Context(), aclFilterFixtureUser()), labels.Everything(), organizationQuery, projectQuery)
	require.NoError(t, err)

	return selector
}

func adminOrganizationAndProjectSelector(t *testing.T, organizationQuery, projectQuery []string) labels.Selector {
	t.Helper()

	selector, err := rbac.AddOrganizationAndProjectIDQuery(rbac.NewContext(t.Context(), aclFilterFixtureAdmin()), labels.Everything(), organizationQuery, projectQuery)
	require.NoError(t, err)

	return selector
}

func platformAdminOrganizationAndProjectSelector(t *testing.T, organizationQuery, projectQuery []string) labels.Selector {
	t.Helper()

	selector, err := rbac.AddOrganizationAndProjectIDQuery(rbac.NewContext(t.Context(), aclFilterFixturePlatformAdmin()), labels.Everything(), organizationQuery, projectQuery)
	require.NoError(t, err)

	return selector
}

// TestOrganizationSelection tests no organization query defaults to all
// organizations in the ACL.
func TestOrganizationSelection(t *testing.T) {
	t.Parallel()

	userSelector := userOrganizationSelector(t, nil)
	adminSelector := adminOrganizationSelector(t, nil)
	platformAdminSelector := platformAdminOrganizationSelector(t, nil)

	tests := []struct {
		name                 string
		labels               labels.Labels
		matchesUser          bool
		matchesAdmin         bool
		matchesPlatformAdmin bool
	}{
		{
			name: "Matches resource in organization 1 and project 1",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_1,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Matches resource in organization 1 and project 2",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_2,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Matches resource in organization 2 and project 1",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID2,
				constants.ProjectLabel:      projectID2_1,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Does not match resource in unknown organization",
			labels: labels.Set{
				constants.OrganizationLabel: "wibble",
				constants.ProjectLabel:      "wibble",
			},
			matchesPlatformAdmin: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, test.matchesUser, userSelector.Matches(test.labels))
			require.Equal(t, test.matchesAdmin, adminSelector.Matches(test.labels))
			require.Equal(t, test.matchesPlatformAdmin, platformAdminSelector.Matches(test.labels))
		})
	}
}

// TestOrganizationSelectionMismatch tests what happens when a user submits a query where
// they cannot match anything.
func TestOrganizationSelectionNoMatches(t *testing.T) {
	t.Parallel()

	query := []string{
		"wibble",
	}

	_, err := rbac.AddOrganizationIDQuery(rbac.NewContext(t.Context(), aclFilterFixtureUser()), labels.Everything(), query)
	require.Error(t, err)
	require.True(t, rbac.HasNoMatches(err))
}

// TestOrganizationSelectionWithSingleQuery tests a single organization query
// returns only resources from that organization.
func TestOrganizationSelectionWithSingleQuery(t *testing.T) {
	t.Parallel()

	query := []string{
		organizationID1,
	}

	userSelector := userOrganizationSelector(t, query)
	adminSelector := adminOrganizationSelector(t, query)
	platformAdminSelector := platformAdminOrganizationSelector(t, query)

	tests := []struct {
		name                 string
		labels               labels.Labels
		matchesUser          bool
		matchesAdmin         bool
		matchesPlatformAdmin bool
	}{
		{
			name: "Matches resource in organization 1 and project 1",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_1,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Matches resource in organization 1 and project 2",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_2,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Does not match resource in organization 2",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID2,
				constants.ProjectLabel:      projectID2_1,
			},
		},
		{
			name: "Does not match resource in unknown organization",
			labels: labels.Set{
				constants.OrganizationLabel: "wibble",
				constants.ProjectLabel:      "wibble",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, test.matchesUser, userSelector.Matches(test.labels))
			require.Equal(t, test.matchesAdmin, adminSelector.Matches(test.labels))
			require.Equal(t, test.matchesPlatformAdmin, platformAdminSelector.Matches(test.labels))
		})
	}
}

// TestOrganizationSelectionWithMultipleQuery tests multiple organization queries
// return all resources from those organizations, constrained to those in the ACL.
func TestOrganizationSelectionWithMultipleQuery(t *testing.T) {
	t.Parallel()

	query := []string{
		organizationID1,
		organizationID2,
		"wibble",
	}

	userSelector := userOrganizationSelector(t, query)
	adminSelector := adminOrganizationSelector(t, query)
	platformAdminSelector := platformAdminOrganizationSelector(t, query)

	tests := []struct {
		name                 string
		labels               labels.Labels
		matchesUser          bool
		matchesAdmin         bool
		matchesPlatformAdmin bool
	}{
		{
			name: "Matches resource in organization 1 and project 1",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_1,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Matches resource in organization 1 and project 2",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_2,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Matches resource in organization 2 and project 2",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID2,
				constants.ProjectLabel:      projectID2_1,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Does not match resource in unknown organization",
			labels: labels.Set{
				constants.OrganizationLabel: "wibble",
				constants.ProjectLabel:      "wibble",
			},
			matchesPlatformAdmin: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, test.matchesUser, userSelector.Matches(test.labels))
			require.Equal(t, test.matchesAdmin, adminSelector.Matches(test.labels))
			require.Equal(t, test.matchesPlatformAdmin, platformAdminSelector.Matches(test.labels))
		})
	}
}

// TestOrganizationAndProjectSelection tests that no organization or project queries
// defaults to all resources in organizations defined in the ACL.
func TestOrganizationAndProjectSelection(t *testing.T) {
	t.Parallel()

	userSelector := userOrganizationAndProjectSelector(t, nil, nil)
	adminSelector := adminOrganizationAndProjectSelector(t, nil, nil)
	platformAdminSelector := platformAdminOrganizationAndProjectSelector(t, nil, nil)

	tests := []struct {
		name                 string
		labels               labels.Labels
		matchesUser          bool
		matchesAdmin         bool
		matchesPlatformAdmin bool
	}{
		{
			name: "Matches resource in organization 1 and project 1",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_1,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Matches resource in organization 1 and project 2",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_2,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Matches resource in organization 2 and project 1",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID2,
				constants.ProjectLabel:      projectID2_1,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Does not match resource in unknown organization",
			labels: labels.Set{
				constants.OrganizationLabel: "wibble",
				constants.ProjectLabel:      "wibble",
			},
			matchesPlatformAdmin: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, test.matchesUser, userSelector.Matches(test.labels))
			require.Equal(t, test.matchesAdmin, adminSelector.Matches(test.labels))
			require.Equal(t, test.matchesPlatformAdmin, platformAdminSelector.Matches(test.labels))
		})
	}
}

// TestOrganizationAndProjectSelectionWithOrganizationQuerySingle tests a single organization
// query returns only resources in that organization.
func TestOrganizationAndProjectSelectionWithOrganizationQuerySingle(t *testing.T) {
	t.Parallel()

	query := []string{
		organizationID1,
	}

	userSelector := userOrganizationAndProjectSelector(t, query, nil)
	adminSelector := adminOrganizationAndProjectSelector(t, query, nil)
	platformAdminSelector := platformAdminOrganizationAndProjectSelector(t, query, nil)

	tests := []struct {
		name                 string
		labels               labels.Labels
		matchesUser          bool
		matchesAdmin         bool
		matchesPlatformAdmin bool
	}{
		{
			name: "Matches resource in organization 1 and project 1",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_1,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Matches resource in organization 1 and project 2",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_2,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Does not match resource in organization 2",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID2,
				constants.ProjectLabel:      projectID2_1,
			},
		},
		{
			name: "Does not match resource in unknown organization",
			labels: labels.Set{
				constants.OrganizationLabel: "wibble",
				constants.ProjectLabel:      "wibble",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, test.matchesUser, userSelector.Matches(test.labels))
			require.Equal(t, test.matchesAdmin, adminSelector.Matches(test.labels))
			require.Equal(t, test.matchesPlatformAdmin, platformAdminSelector.Matches(test.labels))
		})
	}
}

// TestOrganizationAndProjectSelectionWithOrganizationQueryMultiple tests multiple organization
// queries return only resources in those organizations, constrained to those in the ACL.
func TestOrganizationAndProjectSelectionWithOrganizationQueryMultiple(t *testing.T) {
	t.Parallel()

	query := []string{
		organizationID1,
		organizationID2,
		"wibble",
	}

	userSelector := userOrganizationAndProjectSelector(t, query, nil)
	adminSelector := adminOrganizationAndProjectSelector(t, query, nil)
	platformAdminSelector := platformAdminOrganizationAndProjectSelector(t, query, nil)

	tests := []struct {
		name                 string
		labels               labels.Labels
		matchesUser          bool
		matchesAdmin         bool
		matchesPlatformAdmin bool
	}{
		{
			name: "Matches resource in organization 1 and project 1",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_1,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Matches resource in organization 1 and project 2",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_2,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Matches resource in organization 2 and project 1",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID2,
				constants.ProjectLabel:      projectID2_1,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Does not match resource in unknown organization",
			labels: labels.Set{
				constants.OrganizationLabel: "wibble",
				constants.ProjectLabel:      "wibble",
			},
			matchesPlatformAdmin: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, test.matchesUser, userSelector.Matches(test.labels))
			require.Equal(t, test.matchesAdmin, adminSelector.Matches(test.labels))
			require.Equal(t, test.matchesPlatformAdmin, platformAdminSelector.Matches(test.labels))
		})
	}
}

// TestOrganizationAndProjectSelectionWithProjectQuerySingle tests a single project
// query returns only resources in that project.
func TestOrganizationAndProjectSelectionWithProjectQuerySingle(t *testing.T) {
	t.Parallel()

	query := []string{
		projectID1_1,
	}

	userSelector := userOrganizationAndProjectSelector(t, nil, query)
	adminSelector := adminOrganizationAndProjectSelector(t, nil, query)
	platformAdminSelector := platformAdminOrganizationAndProjectSelector(t, nil, query)

	tests := []struct {
		name                 string
		labels               labels.Labels
		matchesUser          bool
		matchesAdmin         bool
		matchesPlatformAdmin bool
	}{
		{
			name: "Matches resource in organization 1 and project 1",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_1,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Does not match resource in organization 1 and project 2",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_2,
			},
		},
		{
			name: "Does not match resource in organization 2",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID2,
				constants.ProjectLabel:      projectID2_1,
			},
		},
		{
			name: "Does not match resource in unknown organization",
			labels: labels.Set{
				constants.OrganizationLabel: "wibble",
				constants.ProjectLabel:      "wibble",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, test.matchesUser, userSelector.Matches(test.labels))
			require.Equal(t, test.matchesAdmin, adminSelector.Matches(test.labels))
			require.Equal(t, test.matchesPlatformAdmin, platformAdminSelector.Matches(test.labels))
		})
	}
}

// TestOrganizationAndProjectSelectionWithProjectQueryMultiple tests multiple project
// queries returns only objects in those projects, constained to projects in the ACL.
func TestOrganizationAndProjectSelectionWithProjectQueryMultiple(t *testing.T) {
	t.Parallel()

	query := []string{
		projectID1_1,
		projectID2_1,
		"wibble",
	}

	userSelector := userOrganizationAndProjectSelector(t, nil, query)
	adminSelector := adminOrganizationAndProjectSelector(t, nil, query)
	platformAdminSelector := platformAdminOrganizationAndProjectSelector(t, nil, query)

	tests := []struct {
		name                 string
		labels               labels.Labels
		matchesUser          bool
		matchesAdmin         bool
		matchesPlatformAdmin bool
	}{
		{
			name: "Matches resource in organization 1 and project 1",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_1,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Does not match resource in organization 1 and project 2",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_2,
			},
		},
		{
			name: "Matches resource in organization 2 and project 1",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID2,
				constants.ProjectLabel:      projectID2_1,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Does not match resource in organization 2 and project 2",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID2,
				constants.ProjectLabel:      projectID2_2,
			},
		},
		{
			name: "Does not match resource in unknown organization",
			labels: labels.Set{
				constants.OrganizationLabel: "wibble",
				constants.ProjectLabel:      "wibble",
			},
			matchesPlatformAdmin: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, test.matchesUser, userSelector.Matches(test.labels))
			require.Equal(t, test.matchesAdmin, adminSelector.Matches(test.labels))
			require.Equal(t, test.matchesPlatformAdmin, platformAdminSelector.Matches(test.labels))
		})
	}
}

// TestOrganizationAndProjectSelectionWithOrganizationAndProjectQuerySingle tests that a
// combination of a single organization and project query retusn only resources in that
// project in that organization.
func TestOrganizationAndProjectSelectionWithOrganizationAndProjectQuerySingle(t *testing.T) {
	t.Parallel()

	organizationQuery := []string{
		organizationID1,
	}

	projectQuery := []string{
		projectID1_1,
	}

	userSelector := userOrganizationAndProjectSelector(t, organizationQuery, projectQuery)
	adminSelector := adminOrganizationAndProjectSelector(t, organizationQuery, projectQuery)
	platformAdminSelector := platformAdminOrganizationAndProjectSelector(t, organizationQuery, projectQuery)

	tests := []struct {
		name                 string
		labels               labels.Labels
		matchesUser          bool
		matchesAdmin         bool
		matchesPlatformAdmin bool
	}{
		{
			name: "Matches resource in organization 1 and project 1",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_1,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Does not match resource in organization 1 and project 2",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_2,
			},
		},
		{
			name: "Does not match resource in organization 2",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID2,
				constants.ProjectLabel:      projectID2_1,
			},
		},
		{
			name: "Does not match resource in unknown organization",
			labels: labels.Set{
				constants.OrganizationLabel: "wibble",
				constants.ProjectLabel:      "wibble",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, test.matchesUser, userSelector.Matches(test.labels))
			require.Equal(t, test.matchesAdmin, adminSelector.Matches(test.labels))
			require.Equal(t, test.matchesPlatformAdmin, platformAdminSelector.Matches(test.labels))
		})
	}
}

// TestOrganizationAndProjectSelectionWithOrganizationAndProjectQueryMultiple tests multiple
// organization and project queries returns any resource in one of the organizations and one
// of the projects, constrained by what's in the ACL.
func TestOrganizationAndProjectSelectionWithOrganizationAndProjectQueryMultiple(t *testing.T) {
	t.Parallel()

	organizationQuery := []string{
		organizationID1,
		organizationID2,
		"wibble",
	}

	projectQuery := []string{
		projectID1_1,
		projectID2_1,
		"wibble",
	}

	userSelector := userOrganizationAndProjectSelector(t, organizationQuery, projectQuery)
	adminSelector := adminOrganizationAndProjectSelector(t, organizationQuery, projectQuery)
	platformAdminSelector := platformAdminOrganizationAndProjectSelector(t, organizationQuery, projectQuery)

	tests := []struct {
		name                 string
		labels               labels.Labels
		matchesUser          bool
		matchesAdmin         bool
		matchesPlatformAdmin bool
	}{
		{
			name: "Matches resource in organization 1 and project 1",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_1,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Does not match resource in organization 1 and project 2",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID1,
				constants.ProjectLabel:      projectID1_2,
			},
		},
		{
			name: "Matches resource in organization 2 and project 1",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID2,
				constants.ProjectLabel:      projectID2_1,
			},
			matchesUser:          true,
			matchesAdmin:         true,
			matchesPlatformAdmin: true,
		},
		{
			name: "Does not match resource in organization 2 and project 2",
			labels: labels.Set{
				constants.OrganizationLabel: organizationID2,
				constants.ProjectLabel:      projectID2_2,
			},
		},
		{
			name: "Does not match resource in unknown organization",
			labels: labels.Set{
				constants.OrganizationLabel: "wibble",
				constants.ProjectLabel:      "wibble",
			},
			matchesPlatformAdmin: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, test.matchesUser, userSelector.Matches(test.labels))
			require.Equal(t, test.matchesAdmin, adminSelector.Matches(test.labels))
			require.Equal(t, test.matchesPlatformAdmin, platformAdminSelector.Matches(test.labels))
		})
	}
}
