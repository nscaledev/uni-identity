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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/handler"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// This test is the A9 decoupling regression guard for the /acl handlers:
// GetApiV1Acl and GetApiV1OrganizationsOrganizationIDAcl are pure
// pass-throughs of the ACL the middleware seeded into the request context.
// They never consult Allow*/the decision engine, so the coarse-ACL surface
// stays structurally decoupled from the enforcement engine the Cerbos
// migration swaps underneath it.  The Handler is constructed with EVERY
// dependency nil (no Kubernetes client, no RBAC, no PDP) — the nils are part
// of the assertion: were either handler to consult anything beyond
// rbac.FromContext, it would panic here; were it to recompute or filter the
// ACL, the verbatim body comparison would fail.

// aclPassThroughFixture is a non-trivial ACL populating every section of the
// wire shape (global, scoped organization, unscoped organization list,
// project list) so the verbatim pass-through is proven for the full shape,
// not just a lucky subset.
func aclPassThroughFixture() *openapi.Acl {
	return &openapi.Acl{
		Global: &openapi.AclEndpoints{
			{Name: "identity:organizations", Operations: openapi.AclOperations{openapi.Read, openapi.Update}},
		},
		Organization: &openapi.AclOrganization{
			Id: "acl-org-id",
			Endpoints: &openapi.AclEndpoints{
				{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Create, openapi.Read}},
			},
			Projects: &openapi.AclProjectList{
				{
					Id: "acl-project-id",
					Endpoints: openapi.AclEndpoints{
						{Name: "compute:clusters", Operations: openapi.AclOperations{openapi.Read, openapi.Delete}},
					},
				},
			},
		},
		Organizations: &openapi.AclOrganizationList{
			{
				Id: "acl-org-id",
				Endpoints: &openapi.AclEndpoints{
					{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Create, openapi.Read}},
				},
			},
		},
		Projects: &openapi.AclProjectList{
			{
				Id: "acl-project-id",
				Endpoints: openapi.AclEndpoints{
					{Name: "compute:clusters", Operations: openapi.AclOperations{openapi.Read, openapi.Delete}},
				},
			},
		},
	}
}

// doACL dispatches an /acl handler with the given ACL seeded into the
// request context (as the authorization middleware does) and returns the
// decoded response body.
func doACL(t *testing.T, acl *openapi.Acl, path string, dispatch func(http.ResponseWriter, *http.Request)) *openapi.Acl {
	t.Helper()

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(rbac.NewContext(t.Context(), acl), http.MethodGet, path, nil)

	dispatch(w, r)

	require.Equal(t, http.StatusOK, w.Code)

	got := &openapi.Acl{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), got))

	return got
}

func TestACLHandlersPassThroughContextACL(t *testing.T) {
	t.Parallel()

	// Every dependency nil on purpose: the /acl handlers touch only
	// rbac.FromContext and the response writer.
	h, err := handler.New(nil, nil, "", nil, nil, nil, nil, &handler.Options{})
	require.NoError(t, err)

	acl := aclPassThroughFixture()

	t.Run("GetApiV1Acl", func(t *testing.T) {
		t.Parallel()

		got := doACL(t, acl, "/api/v1/acl", h.GetApiV1Acl)
		require.Equal(t, acl, got, "the global /acl handler must return the context ACL verbatim")
	})

	t.Run("GetApiV1OrganizationsOrganizationIDAcl", func(t *testing.T) {
		t.Parallel()

		organizationID := ids.MustParseOrganizationID("f47ac10b-58cc-4372-a567-0e02b2c3d479")

		got := doACL(t, acl, "/api/v1/organizations/f47ac10b-58cc-4372-a567-0e02b2c3d479/acl", func(w http.ResponseWriter, r *http.Request) {
			h.GetApiV1OrganizationsOrganizationIDAcl(w, r, organizationID)
		})
		require.Equal(t, acl, got, "the organization /acl handler must return the context ACL verbatim (the middleware already scoped it)")
	})
}
