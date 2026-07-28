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
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	openapiMock "github.com/unikorn-cloud/identity/pkg/openapi/mock"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// platformACL builds a single-organization ACL for the platform-project (D16/D21) tests. The
// substrate resource (resourceType1) is granted at ORGANIZATION scope — the org-admin case that
// drives the leak.
//   - hidden lists the organization's platform-project IDs the subject may not see; leaving it
//     empty models a subject that holds identity:projects:platform (nothing is hidden from them).
//   - projectGrant adds an explicit PROJECT-scope grant on projectID, modelling a genuine member
//     (a customer never has this for a platform project).
func platformACL(hidden []string, projectGrant bool) *openapi.Acl {
	org := openapi.AclOrganization{
		Id: organizationID,
		Endpoints: &openapi.AclEndpoints{
			{Name: resourceType1, Operations: openapi.AclOperations{openapi.Read, openapi.Create}},
		},
	}

	if len(hidden) > 0 {
		h := append([]string{}, hidden...)
		org.PlatformProjects = &h
	}

	if projectGrant {
		org.Projects = &openapi.AclProjectList{
			{
				Id: projectID,
				Endpoints: openapi.AclEndpoints{
					{Name: resourceType1, Operations: openapi.AclOperations{openapi.Read, openapi.Create}},
				},
			},
		}
	}

	return &openapi.Acl{Organizations: &openapi.AclOrganizationList{org}}
}

// TestAllowProjectScopePlatformProject locks in the core D21 behaviour: an organization-scope
// grant covers every project EXCEPT the ones hidden from the subject (platform projects), which
// require an explicit per-project grant or the capability (an empty hidden set).
func TestAllowProjectScopePlatformProject(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name         string
		ACL          *openapi.Acl
		ErrorChecker func(error) bool // nil = expect allow
	}{
		{
			// No regression: an org grant still reaches a normal (non-hidden) project.
			Name: "Allow: org grant, project not hidden",
			ACL:  platformACL(nil, false),
		},
		{
			// Capability holder (Envir SA): the hidden set is empty, so the org grant reaches it.
			Name: "Allow: capability holder sees the platform project (empty hidden set)",
			ACL:  platformACL(nil, false),
		},
		{
			// The fix: an org grant must NOT reach a hidden platform project, and the denial
			// must be not-found so it is indistinguishable from the project not existing (no
			// 403-vs-404 existence oracle).
			Name:         "Deny: org grant does not reach a hidden platform project (as not found)",
			ACL:          platformACL([]string{projectID}, false),
			ErrorChecker: coreerrors.IsHTTPNotFound,
		},
		{
			// The hidden set is honoured when carried only on the singular scoped Organization
			// (the shape a scoped-token ACL is built with), and still denies as not-found.
			Name: "Deny: hidden set on the singular scoped organization (as not found)",
			ACL: &openapi.Acl{
				Organization: &openapi.AclOrganization{
					Id:               organizationID,
					PlatformProjects: &[]string{projectID},
				},
			},
			ErrorChecker: coreerrors.IsHTTPNotFound,
		},
		{
			// Not-found is ONLY for hidden platform projects: an ordinary no-grant denial must
			// stay forbidden or we lose real 403 semantics everywhere else.
			Name: "Deny: plain no-grant denial stays forbidden",
			ACL: &openapi.Acl{
				Organizations: &openapi.AclOrganizationList{
					{
						Id: organizationID,
						Endpoints: &openapi.AclEndpoints{
							{Name: resourceType2, Operations: openapi.AclOperations{openapi.Read}},
						},
					},
				},
			},
			ErrorChecker: coreerrors.IsForbidden,
		},
		{
			// A genuine per-project member still gets through even when the project is hidden.
			Name: "Allow: explicit per-project grant overrides hiding",
			ACL:  platformACL([]string{projectID}, true),
		},
		{
			// A different project being hidden must not affect this one.
			Name: "Allow: a different project is hidden",
			ACL:  platformACL([]string{"11111111-1111-4111-8111-111111111111"}, false),
		},
		{
			// A global (platform administrator) grant is never constrained by hidden projects.
			Name: "Allow: global grant is unconstrained by hiding",
			ACL: &openapi.Acl{
				Global: &openapi.AclEndpoints{
					{Name: resourceType1, Operations: openapi.AclOperations{openapi.Read}},
				},
				Organizations: &openapi.AclOrganizationList{
					{Id: organizationID, PlatformProjects: &[]string{projectID}},
				},
			},
		},
	}

	for i := range tests {
		test := &tests[i]

		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			ctx := rbac.NewContext(t.Context(), test.ACL)

			err := rbac.AllowProjectScope(ctx, resourceType1, openapi.Read, organizationID, projectID)
			if test.ErrorChecker != nil {
				require.Error(t, err)
				require.True(t, test.ErrorChecker(err))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestAllowProjectScopeCreatePlatformProject locks in that the create path (which does NOT go
// through AllowProjectScope) also refuses to create into a hidden platform project on an
// organization-scope grant — and does so before the identity existence API call.
func TestAllowProjectScopeCreatePlatformProject(t *testing.T) {
	t.Parallel()

	projectOKResponse := &openapi.GetApiV1OrganizationsOrganizationIDProjectsProjectIDResponse{
		HTTPResponse: &http.Response{StatusCode: http.StatusOK},
	}

	tests := []struct {
		Name         string
		ACL          *openapi.Acl
		SetupMock    func(client *openapiMock.MockClientWithResponsesInterface)
		ErrorChecker func(error) bool // nil = expect allow
	}{
		{
			// The fix: an org grant cannot create INTO a hidden platform project, and the
			// existence API is never consulted (no mock expectation set). The denial is
			// not-found, matching the nonexistent-project response below it (no oracle).
			Name:         "Deny: org grant cannot create into a hidden platform project (as not found)",
			ACL:          platformACL([]string{projectID}, false),
			ErrorChecker: coreerrors.IsHTTPNotFound,
		},
		{
			// No regression: an org grant can still create into a normal project (existence checked).
			Name: "Allow: org grant creates into a normal project",
			ACL:  platformACL(nil, false),
			SetupMock: func(c *openapiMock.MockClientWithResponsesInterface) {
				c.EXPECT().
					GetApiV1OrganizationsOrganizationIDProjectsProjectIDWithResponse(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(projectOKResponse, nil)
			},
		},
		{
			// A genuine per-project member may create even when the project is hidden — the
			// explicit project grant short-circuits before the existence check.
			Name: "Allow: explicit per-project grant creates into a hidden project",
			ACL:  platformACL([]string{projectID}, true),
		},
	}

	for i := range tests {
		test := &tests[i]

		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockClient := openapiMock.NewMockClientWithResponsesInterface(ctrl)

			if test.SetupMock != nil {
				test.SetupMock(mockClient)
			}

			ctx := rbac.NewContext(t.Context(), test.ACL)

			err := rbac.AllowProjectScopeCreate(ctx, mockClient, resourceType1, openapi.Create, organizationID, projectID)
			if test.ErrorChecker != nil {
				require.Error(t, err)
				require.True(t, test.ErrorChecker(err))
			} else {
				require.NoError(t, err)
			}
		})
	}
}
