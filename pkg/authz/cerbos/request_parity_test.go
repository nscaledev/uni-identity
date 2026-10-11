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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/authz/cerbos"

	"sigs.k8s.io/yaml"
)

// The committed policy-suite fixtures: hand-written principals and resources
// that `make validate-policies` runs against the generated policy store.
// They are the CI-validated half of the byte-exact wire contract; the parity
// tests below prove the request builder reproduces them exactly, so the
// builder and the policy suite can never drift apart silently.  If a fixture
// cannot be reproduced, that is a contract violation to escalate — never a
// test to relax.
const fixtureDirectory = "generate/testdata/store/tests/testdata"

// principalFixture mirrors a Cerbos test-suite principal fixture.  Strict
// unmarshalling ensures any new fixture field shows up here as a loud parity
// failure instead of being silently ignored.
type principalFixture struct {
	ID    string               `json:"id"`
	Roles []string             `json:"roles"`
	Attr  principalAttrFixture `json:"attr"`
}

type principalAttrFixture struct {
	Bindings []string `json:"bindings"`
}

type principalsFixtureFile struct {
	Principals map[string]principalFixture `json:"principals"`
}

// resourceFixture mirrors a Cerbos test-suite resource fixture.  The
// attribute map is deliberately untyped so the parity test can assert on the
// exact KEY SET — key absence is how the fixtures encode scope.
type resourceFixture struct {
	Kind string            `json:"kind"`
	ID   string            `json:"id"`
	Attr map[string]string `json:"attr"`
}

type resourcesFixtureFile struct {
	Resources map[string]resourceFixture `json:"resources"`
}

func loadFixture(t *testing.T, name string, out any) {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(fixtureDirectory, name))
	require.NoError(t, err)

	require.NoError(t, yaml.UnmarshalStrict(data, out))
}

// parseFixtureBinding recovers the semantic (role, scope) content of a
// fixture binding string so the parity test can feed it back through the
// builder.  An unrecognized shape is a fixture-contract failure, not a skip.
func parseFixtureBinding(t *testing.T, binding string) cerbos.RoleBinding {
	t.Helper()

	parts := strings.Split(binding, "#")

	switch {
	case len(parts) == 2 && parts[1] == "global":
		return cerbos.RoleBinding{RoleID: parts[0]}
	case len(parts) == 3 && parts[1] == "org":
		return cerbos.RoleBinding{RoleID: parts[0], OrganizationID: parts[2]}
	case len(parts) == 4 && parts[1] == "project":
		return cerbos.RoleBinding{RoleID: parts[0], OrganizationID: parts[2], ProjectID: parts[3]}
	default:
		require.Failf(t, "unrecognized fixture binding", "binding %q is not a known wire shape", binding)
		return cerbos.RoleBinding{}
	}
}

// TestPrincipalFixtureParity proves BuildPrincipal reproduces every committed
// principal fixture byte-for-byte: id, the mandatory static roles list, and
// the bindings attribute (list form, sorted).  Each fixture binding string is
// parsed back to its semantic (role, scope) content and re-rendered through
// the builder, which also pins BindingString as the exact inverse of the
// fixtures' wire format.
func TestPrincipalFixtureParity(t *testing.T) {
	t.Parallel()

	fixture := &principalsFixtureFile{}
	loadFixture(t, "principals.yaml", fixture)

	// The interesting shapes must exist — if the fixtures are renamed or
	// pruned, the parity claim silently weakens, so fail loudly instead.
	require.Contains(t, fixture.Principals, "platform_admin", "global-binding fixture missing")
	require.Contains(t, fixture.Principals, "reader_proj1", "project-binding fixture missing")
	require.Contains(t, fixture.Principals, "auditor_updater_acme", "multi-binding fixture missing")

	for name, principalFixture := range fixture.Principals {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			bindings := make([]cerbos.RoleBinding, 0, len(principalFixture.Attr.Bindings))

			for _, binding := range principalFixture.Attr.Bindings {
				parsed := parseFixtureBinding(t, binding)

				// Round-trip: the parsed semantic content must render back
				// to the exact fixture string.
				rendered, err := parsed.BindingString()
				require.NoError(t, err)
				require.Equal(t, binding, rendered)

				bindings = append(bindings, parsed)
			}

			principal, err := cerbos.BuildPrincipal(principalFixture.ID, bindings)
			require.NoError(t, err)

			require.Equal(t, principalFixture.ID, principal.Obj.GetId())
			require.Equal(t, principalFixture.Roles, principal.Obj.GetRoles())
			require.Equal(t, principalFixture.Attr.Bindings, principalBindings(t, principal))
		})
	}
}

// TestResourceFixtureParity proves BuildResource reproduces every committed
// resource fixture byte-for-byte: kind, id and the exact attribute map —
// including ABSENCE of keys (the org-level fixture has no project key and the
// platform-level fixture has no attributes at all), which is how the
// no-flow-up invariant is encoded on the wire.
func TestResourceFixtureParity(t *testing.T) {
	t.Parallel()

	fixture := &resourcesFixtureFile{}
	loadFixture(t, "resources.yaml", fixture)

	// The absence-shaped fixtures must exist for this parity claim to mean
	// anything.
	require.Contains(t, fixture.Resources, "projects_org", "org-level (absent project key) fixture missing")
	require.Contains(t, fixture.Resources, "projects_noattrs", "platform-level (no attributes) fixture missing")

	for name, resourceFixture := range fixture.Resources {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// The builder only emits the organization/project keys; any
			// other fixture key means the wire contract grew without the
			// builder knowing.
			for key := range resourceFixture.Attr {
				require.Contains(t, []string{"organization", "project"}, key, "fixture %q has an attribute the builder cannot produce", name)
			}

			resource, err := cerbos.BuildResource(resourceFixture.Kind, resourceFixture.ID, resourceFixture.Attr["organization"], resourceFixture.Attr["project"])
			require.NoError(t, err)

			require.Equal(t, resourceFixture.Kind, resource.Obj.GetKind())
			require.Equal(t, resourceFixture.ID, resource.Obj.GetId())

			expected := resourceFixture.Attr
			if expected == nil {
				expected = map[string]string{}
			}

			require.Equal(t, expected, resourceAttributes(resource))
		})
	}
}
