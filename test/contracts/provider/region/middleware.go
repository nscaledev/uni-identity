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

package region_test

import (
	"net/http"
	"strings"

	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// MockACLMiddleware injects a mock ACL into the request context for contract testing.
// This allows the handler to bypass RBAC checks without requiring real authentication.
// For contract testing with parameterized states, organization IDs come from the consumer contract,
// so we create a permissive ACL that extracts the organization ID from the request path.
func MockACLMiddleware(_ []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create endpoints that grant full access to all identity resources
			endpoints := openapi.AclEndpoints{
				{Name: "identity:organizations", Operations: openapi.AclOperations{openapi.Create, openapi.Read, openapi.Update, openapi.Delete}},
				{Name: "identity:projects", Operations: openapi.AclOperations{openapi.Create, openapi.Read, openapi.Update, openapi.Delete}},
				{Name: "identity:allocations", Operations: openapi.AclOperations{openapi.Create, openapi.Read, openapi.Update, openapi.Delete}},
				{Name: "identity:users", Operations: openapi.AclOperations{openapi.Create, openapi.Read, openapi.Update, openapi.Delete}},
				{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Create, openapi.Read, openapi.Update, openapi.Delete}},
				{Name: "identity:roles", Operations: openapi.AclOperations{openapi.Create, openapi.Read, openapi.Update, openapi.Delete}},
			}

			// Extract organization ID from request path
			// Pattern: /api/v1/organizations/{orgID}/...
			orgID := extractOrganizationID(r.URL.Path)
			if orgID == "" {
				// Fallback to a default org if extraction fails
				orgID = "test-org"
			}

			// Create a single organization with the extracted/default ID
			organizations := openapi.AclOrganizationList{
				{
					Id:        orgID,
					Endpoints: &endpoints,
				},
			}

			mockACL := &openapi.Acl{
				Organizations: &organizations,
			}

			// Inject the mock ACL into the request context
			ctx := rbac.NewContext(r.Context(), mockACL)

			// Inject mock authorization info (required for SetIdentityMetadata)
			authInfo := &authorization.Info{
				Userinfo: &openapi.Userinfo{
					Sub: "test-user", // Mock user subject
				},
			}
			ctx = authorization.NewContext(ctx, authInfo)

			// Inject mock principal info (required for SetIdentityMetadata)
			principalInfo := &principal.Principal{
				Actor:          "test-user",
				OrganizationID: orgID,
			}
			ctx = principal.NewContext(ctx, principalInfo)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractOrganizationID extracts the organization ID from the request path.
// Expected pattern: /api/v1/organizations/{orgID}/...
func extractOrganizationID(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "organizations" && i+1 < len(parts) {
			return parts[i+1]
		}
	}

	return ""
}
