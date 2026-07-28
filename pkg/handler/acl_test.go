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

const (
	aclTestOrg       = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	aclHiddenProject = "550e8400-e29b-41d4-a716-446655440000"
)

// aclWithPlatformProjects builds an ACL that carries the hidden platform-project set on both the
// singular and plural organization representations — the state the builder produces for a
// non-capability caller.
func aclWithPlatformProjects() *openapi.Acl {
	hidden := []string{aclHiddenProject}

	return &openapi.Acl{
		Organization: &openapi.AclOrganization{
			Id:               aclTestOrg,
			PlatformProjects: &hidden,
		},
		Organizations: &openapi.AclOrganizationList{
			{
				Id:               aclTestOrg,
				PlatformProjects: &hidden,
			},
		},
	}
}

func callACLAsService(t *testing.T) *openapi.Acl {
	t.Helper()

	acl := aclWithPlatformProjects()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/organizations/"+aclTestOrg+"/acl", nil)
	req = req.WithContext(rbac.NewContext(t.Context(), acl))

	// A service-to-service caller reaches identity over mTLS, which the ingress surfaces as the
	// Ssl-Client-Cert header; a direct user/CLI/UI caller has none.
	req.Header.Set("Ssl-Client-Cert", "dummy-cert")

	rec := httptest.NewRecorder()

	(&handler.Handler{}).GetApiV1OrganizationsOrganizationIDAcl(rec, req, ids.MustParseOrganizationID(aclTestOrg))

	require.Equal(t, http.StatusOK, rec.Code)

	var got openapi.Acl

	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))

	// The source ACL is cached and shared across requests, so the handler must never mutate it.
	require.NotNil(t, acl.Organization.PlatformProjects, "handler mutated the shared context ACL")
	require.NotNil(t, (*acl.Organizations)[0].PlatformProjects, "handler mutated the shared context ACL")

	return &got
}

// TestGetACLKeepsPlatformProjectsForServices pins that a service-to-service caller (mTLS) still
// receives the hidden set — the sibling services need it to enforce the hiding (D21).
//
// This stays a unit test on purpose: it turns on the Ssl-Client-Cert header that only an mTLS
// service-to-service call carries, which the bearer-token integration suite cannot produce. The
// customer-facing half of this behaviour (the set is scrubbed for direct users) is covered by the
// test/api "Platform projects" integration suite.
func TestGetACLKeepsPlatformProjectsForServices(t *testing.T) {
	t.Parallel()

	got := callACLAsService(t)

	require.NotNil(t, got.Organizations)
	require.NotNil(t, (*got.Organizations)[0].PlatformProjects, "service caller must still receive the hidden set")
	require.Equal(t, []string{aclHiddenProject}, *(*got.Organizations)[0].PlatformProjects)
}
