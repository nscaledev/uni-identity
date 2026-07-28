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

package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/handler"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// customerACLHidingPlatformProject builds the ACL of an ordinary organization member: a broad
// identity:projects grant at organization scope, with aclHiddenProject listed as a platform
// project they must not see. This is exactly what the ACL builder produces for a non-capability
// caller, and it is what makes rbac.AllowProjectScope deny the hidden project.
func customerACLHidingPlatformProject() *openapi.Acl {
	endpoints := openapi.AclEndpoints{
		{
			Name:       "identity:projects",
			Operations: openapi.AclOperations{openapi.Read, openapi.Update, openapi.Delete},
		},
	}
	hidden := []string{aclHiddenProject}

	return &openapi.Acl{
		Organizations: &openapi.AclOrganizationList{
			{
				Id:               aclTestOrg,
				Endpoints:        &endpoints,
				PlatformProjects: &hidden,
			},
		},
	}
}

func hiddenProjectRequest(t *testing.T, method string, acl *openapi.Acl) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, "/api/v1/organizations/"+aclTestOrg+"/projects/"+aclHiddenProject, nil)
	req = req.WithContext(rbac.NewContext(t.Context(), acl))

	rec := httptest.NewRecorder()

	org := ids.MustParseOrganizationID(aclTestOrg)
	proj := ids.MustParseProjectID(aclHiddenProject)

	// A nil client is safe: every one of these cases is resolved at the authorization gate before
	// the handler touches storage.
	h := &handler.Handler{}

	switch method {
	case http.MethodGet:
		h.GetApiV1OrganizationsOrganizationIDProjectsProjectID(rec, req, org, proj)
	case http.MethodPut:
		h.PutApiV1OrganizationsOrganizationIDProjectsProjectID(rec, req, org, proj)
	case http.MethodDelete:
		h.DeleteApiV1OrganizationsOrganizationIDProjectsProjectID(rec, req, org, proj)
	default:
		t.Fatalf("unsupported method %q", method)
	}

	return rec
}

// TestProjectHidesPlatformProjectAsNotFound pins that a customer acting on a real platform project
// gets 404, not 403. rbac.AllowProjectScope denies a hidden platform project with a forbidden
// error; returning that verbatim would be an existence oracle — 403 means "a real platform project
// lives here", 404 means "nothing here" — exactly the distinction D16/D21 hide. The handler must
// therefore translate the denial into 404 (Codex P1 "Return 404 before hidden-project RBAC
// denies"). Covers read, update and delete, which share the pattern.
func TestProjectHidesPlatformProjectAsNotFound(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			rec := hiddenProjectRequest(t, method, customerACLHidingPlatformProject())

			require.Equal(t, http.StatusNotFound, rec.Code, "hidden platform project must look nonexistent, not forbidden")
		})
	}
}

// TestProjectForbiddenStaysForbiddenWhenNotHidden ensures the 404 translation is scoped to
// genuinely-hidden projects. A caller with no access at all to a project that is NOT in their
// hidden set must still receive the original 403, so we do not blanket-convert every denial into a
// 404 (which would itself become an oracle in the other direction).
func TestProjectForbiddenStaysForbiddenWhenNotHidden(t *testing.T) {
	t.Parallel()

	// An empty ACL: no organization grant, nothing hidden.
	rec := hiddenProjectRequest(t, http.MethodGet, &openapi.Acl{})

	require.Equal(t, http.StatusForbidden, rec.Code, "a genuine no-access denial must stay 403")
}
