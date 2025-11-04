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

	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
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
