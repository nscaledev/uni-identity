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

// This test is the Go side of the RBAC conformance harness. It does not hard-code
// its cases: it reads testdata/model_vectors.json, which is generated from the
// Lean formal model in ../../formal (see formal/README.md), and asserts that the
// real rbac package reproduces the decision the model computed for each scenario.
//
// The vectors are the oracle. Each scenario carries the model's `expected`
// decision; hand-written base cases additionally carry a `humanExpect` outcome a
// human asserts. We check the real code against the model, and (for base cases)
// that the model still matches human intent.
//
// Running these tests needs no Lean toolchain — only the checked-in JSON. To
// change the cases, edit the model and run `make regenerate-vectors`; CI fails if
// the committed JSON drifts from what the model produces.

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

const vectorsPath = "testdata/model_vectors.json"

// The JSON schema emitted by the generator (formal/UniRbac/Vectors.lean).

type vectorEndpoint struct {
	Name       string   `json:"name"`
	Operations []string `json:"operations"`
}

type vectorProject struct {
	ID        string           `json:"id"`
	Endpoints []vectorEndpoint `json:"endpoints"`
}

type vectorACL struct {
	Global       []vectorEndpoint `json:"global"`
	Organization []vectorEndpoint `json:"organization"`
	Projects     []vectorProject  `json:"projects"`
}

type vectorRole struct {
	Global       []vectorEndpoint `json:"global"`
	Organization []vectorEndpoint `json:"organization"`
	Project      []vectorEndpoint `json:"project"`
}

type vectorQuery struct {
	Kind string      `json:"kind"`
	Role *vectorRole `json:"role"`
}

type vectorScenario struct {
	Name           string      `json:"name"`
	Source         string      `json:"source"`
	OrganizationID string      `json:"organizationId"`
	ACL            vectorACL   `json:"acl"`
	Query          vectorQuery `json:"query"`
	Expected       string      `json:"expected"`
	HumanExpect    *string     `json:"humanExpect"`
}

type vectorDocument struct {
	Scenarios []vectorScenario `json:"scenarios"`
}

// aclOperations converts the JSON operation words to openapi ACL operations.
func aclOperations(ops []string) openapi.AclOperations {
	out := make(openapi.AclOperations, 0, len(ops))

	for _, op := range ops {
		switch op {
		case "create":
			out = append(out, openapi.Create)
		case "read":
			out = append(out, openapi.Read)
		case "update":
			out = append(out, openapi.Update)
		case "delete":
			out = append(out, openapi.Delete)
		}
	}

	return out
}

// aclEndpoints converts a JSON permission set to an openapi ACL endpoint list.
func aclEndpoints(endpoints []vectorEndpoint) openapi.AclEndpoints {
	out := make(openapi.AclEndpoints, 0, len(endpoints))

	for _, e := range endpoints {
		out = append(out, openapi.AclEndpoint{Name: e.Name, Operations: aclOperations(e.Operations)})
	}

	return out
}

// roleOperations converts JSON operation words to CRD role operations.
func roleOperations(ops []string) []unikornv1.Operation {
	out := make([]unikornv1.Operation, 0, len(ops))

	for _, op := range ops {
		switch op {
		case "create":
			out = append(out, unikornv1.Create)
		case "read":
			out = append(out, unikornv1.Read)
		case "update":
			out = append(out, unikornv1.Update)
		case "delete":
			out = append(out, unikornv1.Delete)
		}
	}

	return out
}

// roleScopes converts a JSON permission set to a CRD role scope list.
func roleScopes(endpoints []vectorEndpoint) []unikornv1.RoleScope {
	if len(endpoints) == 0 {
		return nil
	}

	out := make([]unikornv1.RoleScope, 0, len(endpoints))

	for _, e := range endpoints {
		out = append(out, unikornv1.RoleScope{Name: e.Name, Operations: roleOperations(e.Operations)})
	}

	return out
}

// buildACL reconstructs an *openapi.Acl from a scenario, mirroring the modelACL
// helper this test replaced: a single organization holding the org-scope
// endpoints and projects, plus any global endpoints.
func buildACL(organizationID string, acl vectorACL) *openapi.Acl {
	out := &openapi.Acl{}

	if len(acl.Global) > 0 {
		endpoints := aclEndpoints(acl.Global)
		out.Global = &endpoints
	}

	if len(acl.Organization) == 0 && len(acl.Projects) == 0 {
		return out
	}

	organization := openapi.AclOrganization{Id: organizationID}

	if len(acl.Organization) > 0 {
		endpoints := aclEndpoints(acl.Organization)
		organization.Endpoints = &endpoints
	}

	if len(acl.Projects) > 0 {
		projects := make(openapi.AclProjectList, 0, len(acl.Projects))

		for _, project := range acl.Projects {
			projects = append(projects, openapi.AclProject{
				Id:        project.ID,
				Endpoints: aclEndpoints(project.Endpoints),
			})
		}

		organization.Projects = &projects
	}

	organizations := openapi.AclOrganizationList{organization}
	out.Organizations = &organizations

	return out
}

// buildRole reconstructs a *unikornv1.Role from a scenario, mirroring modelRole.
func buildRole(role *vectorRole) *unikornv1.Role {
	return &unikornv1.Role{
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Global:       roleScopes(role.Global),
				Organization: roleScopes(role.Organization),
				Project:      roleScopes(role.Project),
			},
		},
	}
}

// decide runs the scenario's query against the real rbac package and returns the
// decision as the same "allow"/"deny" word the model emits.
func decide(t *testing.T, scenario vectorScenario) string {
	t.Helper()

	switch scenario.Query.Kind {
	case "allowRole":
		require.NotNil(t, scenario.Query.Role, "allowRole scenario missing role")

		acl := buildACL(scenario.OrganizationID, scenario.ACL)
		role := buildRole(scenario.Query.Role)
		organizationID := ids.MustParseOrganizationID(scenario.OrganizationID)

		if rbac.AllowRole(rbac.NewContext(t.Context(), acl), role, organizationID) != nil {
			return "deny"
		}

		return "allow"
	default:
		t.Fatalf("unknown query kind %q", scenario.Query.Kind)

		return "deny"
	}
}

func loadVectors(t *testing.T) vectorDocument {
	t.Helper()

	raw, err := os.ReadFile(vectorsPath)
	require.NoError(t, err, "read %s (regenerate with `make regenerate-vectors`)", vectorsPath)

	var document vectorDocument

	require.NoError(t, json.Unmarshal(raw, &document))
	require.NotEmpty(t, document.Scenarios, "no scenarios in %s", vectorsPath)

	return document
}

// TestModelConformance drives every generated vector through the real rbac
// package and asserts the decision matches the formal model.
func TestModelConformance(t *testing.T) {
	t.Parallel()

	document := loadVectors(t)

	for i := range document.Scenarios {
		scenario := document.Scenarios[i]

		t.Run(scenario.Name, func(t *testing.T) {
			t.Parallel()

			require.Contains(t, []string{"allow", "deny"}, scenario.Expected, "bad expected decision")

			// For hand-written cases, the model must still agree with the outcome a
			// human asserted. If this fails, the model changed meaning and the vectors
			// need regenerating (or the change is a genuine regression).
			if scenario.HumanExpect != nil {
				require.Equal(t, scenario.Expected, *scenario.HumanExpect,
					"model expected diverged from hand-written humanExpect; run `make regenerate-vectors`")
			}

			require.Equal(t, scenario.Expected, decide(t, scenario),
				"rbac decision disagrees with the formal model for this scenario")
		})
	}
}
