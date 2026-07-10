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

package cerbos_test

import (
	"testing"

	sdk "github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/authz/cerbos"
	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// principalBindings extracts the bindings attribute from a built principal as
// plain strings, failing the test if the attribute is missing or is not the
// list form the generated CEL conditions match against.
func principalBindings(t *testing.T, principal *sdk.Principal) []string {
	t.Helper()

	value, ok := principal.Obj.GetAttr()["bindings"]
	require.True(t, ok, "principal must carry the bindings attribute")

	list := value.GetListValue()
	require.NotNil(t, list, "the bindings attribute must be a list, not a map")

	bindings := make([]string, 0, len(list.GetValues()))

	for _, element := range list.GetValues() {
		bindings = append(bindings, element.GetStringValue())
	}

	return bindings
}

// resourceAttributes extracts a built resource's attribute map as plain
// strings.  Key ABSENCE is load-bearing (it is how scope is encoded), so
// callers compare whole maps, never individual lookups.
func resourceAttributes(resource *sdk.Resource) map[string]string {
	attributes := map[string]string{}

	for key, value := range resource.Obj.GetAttr() {
		attributes[key] = value.GetStringValue()
	}

	return attributes
}

// TestBindingStringFormats pins the byte-exact binding-string wire formats —
// <roleID>#global, <roleID>#org#<orgID>, <roleID>#project#<orgID>#<projectID>
// — the cross-component contract shared with the generated CEL conditions
// (generate.bindingExpr).  Any drift here silently denies every request, so
// the formats are pinned at unit level and again against the committed policy
// fixtures in request_parity_test.go.
func TestBindingStringFormats(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		binding  cerbos.RoleBinding
		expected string
	}{
		"global": {
			binding:  cerbos.RoleBinding{RoleID: "00000000-0000-0000-0000-000000000001"},
			expected: "00000000-0000-0000-0000-000000000001#global",
		},
		"organization": {
			binding:  cerbos.RoleBinding{RoleID: "00000000-0000-0000-0000-000000000003", OrganizationID: "org-acme"},
			expected: "00000000-0000-0000-0000-000000000003#org#org-acme",
		},
		"project": {
			binding:  cerbos.RoleBinding{RoleID: "00000000-0000-0000-0000-000000000006", OrganizationID: "org-acme", ProjectID: "proj-1"},
			expected: "00000000-0000-0000-0000-000000000006#project#org-acme#proj-1",
		},
	}

	for name, testcase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rendered, err := testcase.binding.BindingString()
			require.NoError(t, err)
			require.Equal(t, testcase.expected, rendered)
		})
	}
}

// TestBindingStringValidation pins the rejection of bindings the wire format
// cannot represent: an empty role ID renders an unmatchable string, and a
// project without an organization has no format at all (a project binding
// embeds its organization — that embedding is what stops the same project ID
// in another organization from matching).
func TestBindingStringValidation(t *testing.T) {
	t.Parallel()

	cases := map[string]cerbos.RoleBinding{
		"empty role ID":                {OrganizationID: "org-acme"},
		"project without organization": {RoleID: "00000000-0000-0000-0000-000000000006", ProjectID: "proj-1"},
	}

	for name, binding := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := binding.BindingString()
			require.ErrorIs(t, err, cerbos.ErrInvalidBinding)
		})
	}
}

// TestBuildPrincipalActorClasses documents the binding shapes each identity
// actor class produces, mirroring pkg/rbac ground truth: users get org and
// project bindings from group memberships (groups NEVER yield global
// bindings); platform administrators get ONLY global bindings (rbac.go
// early-returns before any group accumulation); service accounts get org and
// project bindings within exactly one owning organization; system accounts
// get exactly one global binding from the CN→role map.  The builder itself is
// class-agnostic — it renders whatever bindings it is given — so these cases
// are the pinned reference for the A5 resolver, not builder branching.
func TestBuildPrincipalActorClasses(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		subjectID string
		bindings  []cerbos.RoleBinding
		expected  []string
	}{
		"user with two organizations and one linked project": {
			subjectID: "user@example.com",
			bindings: []cerbos.RoleBinding{
				{RoleID: "role-reader", OrganizationID: "org-acme"},
				{RoleID: "role-admin", OrganizationID: "org-other"},
				{RoleID: "role-reader", OrganizationID: "org-acme", ProjectID: "proj-1"},
			},
			expected: []string{
				"role-admin#org#org-other",
				"role-reader#org#org-acme",
				"role-reader#project#org-acme#proj-1",
			},
		},
		"platform administrator": {
			subjectID: "admin@platform",
			bindings: []cerbos.RoleBinding{
				{RoleID: "role-platform-admin"},
				{RoleID: "role-platform-reader"},
			},
			expected: []string{
				"role-platform-admin#global",
				"role-platform-reader#global",
			},
		},
		"service account within one owning organization": {
			subjectID: "service-account-1",
			bindings: []cerbos.RoleBinding{
				{RoleID: "role-automation", OrganizationID: "org-acme"},
				{RoleID: "role-automation", OrganizationID: "org-acme", ProjectID: "proj-1"},
				{RoleID: "role-automation", OrganizationID: "org-acme", ProjectID: "proj-2"},
			},
			expected: []string{
				"role-automation#org#org-acme",
				"role-automation#project#org-acme#proj-1",
				"role-automation#project#org-acme#proj-2",
			},
		},
		"system account": {
			subjectID: "region-service",
			bindings: []cerbos.RoleBinding{
				{RoleID: "role-region-service"},
			},
			expected: []string{
				"role-region-service#global",
			},
		},
		"subject with no bindings": {
			// A subject in no groups is a valid principal that denies
			// everywhere: the bindings attribute is present but empty.
			subjectID: "nobody@example.com",
			bindings:  nil,
			expected:  []string{},
		},
	}

	for name, testcase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			principal, err := cerbos.BuildPrincipal(testcase.subjectID, testcase.bindings)
			require.NoError(t, err)

			require.Equal(t, testcase.subjectID, principal.Obj.GetId())

			// The static parent role is mandatory: every generated derived
			// role declares parentRoles [principal], so omitting it means no
			// derived role can ever activate.
			require.Equal(t, []string{"principal"}, principal.Obj.GetRoles())

			require.Equal(t, testcase.expected, principalBindings(t, principal))
		})
	}
}

// TestBuildPrincipalDeterminism pins that binding order and duplicates in the
// input never change the request: bindings are deduplicated and sorted, so
// byte-identical requests come out of semantically identical inputs — the
// property the A15 cache key and decision logging rely on.
func TestBuildPrincipalDeterminism(t *testing.T) {
	t.Parallel()

	bindings := []cerbos.RoleBinding{
		{RoleID: "role-reader", OrganizationID: "org-acme"},
		{RoleID: "role-admin", OrganizationID: "org-other"},
		{RoleID: "role-reader", OrganizationID: "org-acme", ProjectID: "proj-1"},
	}

	expected := []string{
		"role-admin#org#org-other",
		"role-reader#org#org-acme",
		"role-reader#project#org-acme#proj-1",
	}

	permutations := [][]int{
		{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0},
	}

	for _, permutation := range permutations {
		shuffled := make([]cerbos.RoleBinding, 0, len(bindings)+1)

		for _, index := range permutation {
			shuffled = append(shuffled, bindings[index])
		}

		// A duplicate grant (the same role reachable through two groups)
		// must collapse to one binding string.
		shuffled = append(shuffled, bindings[permutation[0]])

		principal, err := cerbos.BuildPrincipal("user@example.com", shuffled)
		require.NoError(t, err)
		require.Equal(t, expected, principalBindings(t, principal), "input order %v must not change the request", permutation)
	}
}

// TestBuildPrincipalValidation pins the loud failures: an empty subject ID
// violates the engine proto's min_len 1 and would otherwise surface as an
// opaque PDP validation error at check time, and an invalid binding must
// propagate rather than being silently skipped (a dropped binding is a
// silently narrowed grant).
func TestBuildPrincipalValidation(t *testing.T) {
	t.Parallel()

	_, err := cerbos.BuildPrincipal("", nil)
	require.ErrorIs(t, err, cerbos.ErrInvalidPrincipal)

	_, err = cerbos.BuildPrincipal("user@example.com", []cerbos.RoleBinding{{}})
	require.ErrorIs(t, err, cerbos.ErrInvalidBinding)
}

// TestBuildResourceScopeShapes pins the three scope shapes as attribute
// PRESENCE, never values: a global check has no attributes at all, an org
// check has organization ONLY (an absent — not empty — project attribute is
// the no-flow-up invariant: presence would let project bindings activate on
// an org-level check), and a project check has both, so one request activates
// global + matching-org + matching-project bindings simultaneously — the Go
// three-level cascade collapsed into a single Cerbos check.
func TestBuildResourceScopeShapes(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		organizationID string
		projectID      string
		expected       map[string]string
	}{
		"global": {
			expected: map[string]string{},
		},
		"organization": {
			organizationID: "org-acme",
			expected:       map[string]string{"organization": "org-acme"},
		},
		"project": {
			organizationID: "org-acme",
			projectID:      "proj-1",
			expected:       map[string]string{"organization": "org-acme", "project": "proj-1"},
		},
	}

	for name, testcase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			resource, err := cerbos.BuildResource("identity:projects", "resource-1", testcase.organizationID, testcase.projectID)
			require.NoError(t, err)

			require.Equal(t, "identity:projects", resource.Obj.GetKind())
			require.Equal(t, "resource-1", resource.Obj.GetId())
			require.Equal(t, testcase.expected, resourceAttributes(resource))
		})
	}
}

// TestBuildResourceCoarseID pins the synthetic id for coarse (no-instance)
// checks: the engine proto requires a non-empty resource id, so an empty id
// becomes the pinned CoarseResourceID constant, which is also part of the
// future A15 cache key.
func TestBuildResourceCoarseID(t *testing.T) {
	t.Parallel()

	resource, err := cerbos.BuildResource("identity:projects", "", "org-acme", "")
	require.NoError(t, err)
	require.Equal(t, cerbos.CoarseResourceID, resource.Obj.GetId())
	require.Equal(t, "*", cerbos.CoarseResourceID)
}

// TestBuildResourceValidation pins the loud failures: an empty kind can never
// match a resource policy, and a project without an organization has no scope
// shape (organizationID=="" means GLOBAL, and a global check must not carry a
// project attribute).
func TestBuildResourceValidation(t *testing.T) {
	t.Parallel()

	_, err := cerbos.BuildResource("", "resource-1", "org-acme", "")
	require.ErrorIs(t, err, cerbos.ErrInvalidResource)

	_, err = cerbos.BuildResource("identity:projects", "resource-1", "", "proj-1")
	require.ErrorIs(t, err, cerbos.ErrInvalidResource)
}

// TestBuildBatch pins the happy path: every entry lands in the batch with its
// resource verbatim and its actions rendered from openapi.AclOperation
// values, deduplicated and sorted (deterministic requests aid caching and
// logging; the proto requires unique actions).
func TestBuildBatch(t *testing.T) {
	t.Parallel()

	cluster, err := cerbos.BuildResource("kubernetes:clusters", "cluster-1", "org-acme", "proj-1")
	require.NoError(t, err)

	projects, err := cerbos.BuildResource("identity:projects", "", "org-acme", "")
	require.NoError(t, err)

	batch, err := cerbos.BuildBatch([]cerbos.BatchEntry{
		{Resource: cluster, Actions: []openapi.AclOperation{openapi.Update, openapi.Read, openapi.Read}},
		{Resource: projects, Actions: []openapi.AclOperation{openapi.Create}},
	})
	require.NoError(t, err)

	require.Len(t, batch.Batch, 2)

	require.Equal(t, "kubernetes:clusters", batch.Batch[0].GetResource().GetKind())
	require.Equal(t, "cluster-1", batch.Batch[0].GetResource().GetId())
	require.Equal(t, []string{"read", "update"}, batch.Batch[0].GetActions())

	require.Equal(t, "identity:projects", batch.Batch[1].GetResource().GetKind())
	require.Equal(t, cerbos.CoarseResourceID, batch.Batch[1].GetResource().GetId())
	require.Equal(t, []string{"create"}, batch.Batch[1].GetActions())
}

// TestBuildBatchValidation pins the guard over the SDK's silent-drop footgun:
// ResourceBatch.Add silently no-ops on nil resources and empty action lists,
// which would turn a coding error into an authorization check that checks
// nothing.  The builder fails LOUDLY instead: no resources, a nil resource,
// no actions, and an empty action string (the proto requires min_len 1) are
// all errors.
func TestBuildBatchValidation(t *testing.T) {
	t.Parallel()

	resource, err := cerbos.BuildResource("identity:projects", "resource-1", "org-acme", "")
	require.NoError(t, err)

	cases := map[string][]cerbos.BatchEntry{
		"no resources": {},
		"nil resource": {{Resource: nil, Actions: []openapi.AclOperation{openapi.Read}}},
		"no actions":   {{Resource: resource, Actions: nil}},
		"empty action": {{Resource: resource, Actions: []openapi.AclOperation{openapi.Read, ""}}},
	}

	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := cerbos.BuildBatch(entries)
			require.ErrorIs(t, err, cerbos.ErrInvalidBatch)
		})
	}
}
