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

package generate_test

import (
	"flag"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos/generate"

	"sigs.k8s.io/yaml"
)

// update regenerates the golden policy store from the fixture roles instead
// of comparing against it: go test ./pkg/authz/cerbos/generate/... -update
//
//nolint:gochecknoglobals // Standard golden-file -update flag pattern.
var update = flag.Bool("update", false, "regenerate golden files")

const (
	rolesDir = "testdata/roles"
	storeDir = "testdata/store"
)

// loadFixtureRoles reads every Role CR fixture committed under
// testdata/roles.  The fixtures transcribe all nine built-in roles from
// charts/identity/values.yaml plus representative out-of-repo
// open-vocabulary roles and synthetic edge cases; see the per-file
// provenance comments.
func loadFixtureRoles(t *testing.T) []unikornv1.Role {
	t.Helper()

	paths, err := filepath.Glob(filepath.Join(rolesDir, "*.yaml"))
	require.NoError(t, err)
	require.NotEmpty(t, paths)

	roles := make([]unikornv1.Role, 0, len(paths))

	for _, path := range paths {
		data, err := os.ReadFile(path)
		require.NoError(t, err)

		var role unikornv1.Role

		require.NoError(t, yaml.UnmarshalStrict(data, &role), path)
		roles = append(roles, role)
	}

	return roles
}

// readStoreFiles returns the generated files committed at the top level of
// the golden store.  The tests/ subdirectory holds the hand-written Cerbos
// test suite and is not generator output.
func readStoreFiles(t *testing.T) map[string][]byte {
	t.Helper()

	entries, err := os.ReadDir(storeDir)
	require.NoError(t, err)

	files := map[string][]byte{}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(storeDir, entry.Name()))
		require.NoError(t, err)

		files[entry.Name()] = data
	}

	return files
}

// writeStoreFiles replaces the generated top level of the golden store,
// leaving the hand-written tests/ subdirectory untouched.
func writeStoreFiles(t *testing.T, files map[string][]byte) {
	t.Helper()

	for name := range readStoreFiles(t) {
		require.NoError(t, os.Remove(filepath.Join(storeDir, name)))
	}

	for name, data := range files {
		require.NoError(t, os.WriteFile(filepath.Join(storeDir, name), data, 0o600))
	}
}

// role is a convenience constructor for the edge-case tests.
func role(id string, scopes unikornv1.RoleScopes) unikornv1.Role {
	out := unikornv1.Role{}
	out.Name = id
	out.Spec.Scopes = scopes

	return out
}

func scope(name string, operations ...unikornv1.Operation) unikornv1.RoleScope {
	return unikornv1.RoleScope{Name: name, Operations: operations}
}

// TestGenerateGolden pins the full byte-exact output for the fixture roles.
// The golden store doubles as the Cerbos compile store validated by
// `make validate-policies`, so any change to these bytes must keep that
// target passing: determinism and the binding-string contract are enforced
// here, behavioural semantics in the Cerbos test suite.
func TestGenerateGolden(t *testing.T) {
	t.Parallel()

	output, err := generate.Generate(loadFixtureRoles(t))
	require.NoError(t, err)

	files, err := output.Files()
	require.NoError(t, err)

	if *update {
		writeStoreFiles(t, files)
		return
	}

	golden := readStoreFiles(t)

	require.Equal(t, slices.Sorted(maps.Keys(golden)), slices.Sorted(maps.Keys(files)),
		"generated file set differs from golden store; run: go test ./pkg/authz/cerbos/generate/... -update")

	for name, want := range golden {
		require.Equal(t, string(want), string(files[name]), name)
	}
}

// TestGenerateGrantsNothing verifies that inputs which grant nothing produce
// an empty store: emitting an empty derived-roles document or a resource
// policy with no rules would be rejected by Cerbos.
func TestGenerateGrantsNothing(t *testing.T) {
	t.Parallel()

	cases := map[string][]unikornv1.Role{
		"NoRoles": nil,
		"NilScopes": {
			role("00000000-0000-0000-0000-000000000001", unikornv1.RoleScopes{}),
		},
		"EmptyBuckets": {
			role("00000000-0000-0000-0000-000000000001", unikornv1.RoleScopes{
				Global:       []unikornv1.RoleScope{},
				Organization: []unikornv1.RoleScope{},
				Project:      []unikornv1.RoleScope{},
			}),
		},
		"NoOperations": {
			role("00000000-0000-0000-0000-000000000001", unikornv1.RoleScopes{
				Organization: []unikornv1.RoleScope{scope("identity:groups")},
			}),
		},
	}

	for name, roles := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			output, err := generate.Generate(roles)
			require.NoError(t, err)

			require.Nil(t, output.DerivedRoles)
			require.Empty(t, output.ResourcePolicies)

			files, err := output.Files()
			require.NoError(t, err)
			require.Empty(t, files)
		})
	}
}

// TestGenerateUnionAndDedup pins the byte-exact resource policy for two roles
// granting overlapping operations on one endpoint: the grants union as
// separate rules (Cerbos ALLOWs are additive, mirroring pkg/rbac's additive
// roles), and duplicate operations within one scope dedup into sorted
// actions.
func TestGenerateUnionAndDedup(t *testing.T) {
	t.Parallel()

	roles := []unikornv1.Role{
		role("00000000-0000-0000-0000-00000000000b", unikornv1.RoleScopes{
			Organization: []unikornv1.RoleScope{
				scope("example:widgets", unikornv1.Read, unikornv1.Read, unikornv1.Create),
			},
		}),
		role("00000000-0000-0000-0000-00000000000a", unikornv1.RoleScopes{
			Global: []unikornv1.RoleScope{
				scope("example:widgets", unikornv1.Update),
			},
		}),
	}

	output, err := generate.Generate(roles)
	require.NoError(t, err)

	files, err := output.Files()
	require.NoError(t, err)
	require.Len(t, files, 2)

	expected := `# Code generated by github.com/unikorn-cloud/identity/pkg/authz/cerbos/generate. DO NOT EDIT.
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  resource: example:widgets
  version: default
  scope: ""
  scopePermissions: SCOPE_PERMISSIONS_OVERRIDE_PARENT
  importDerivedRoles: [uni_roles]
  rules:
    - actions: [update]
      derivedRoles: [role_00000000-0000-0000-0000-00000000000a_global]
      effect: EFFECT_ALLOW
    - actions: [create, read]
      derivedRoles: [role_00000000-0000-0000-0000-00000000000b_org]
      effect: EFFECT_ALLOW
`

	require.Equal(t, expected, string(files["resource_example_widgets.yaml"]))
}

// TestGenerateMergesDuplicateEndpoints verifies that duplicate endpoint names
// within one bucket union their operations into a single rule, mirroring
// pkg/rbac's additive-union semantics.
func TestGenerateMergesDuplicateEndpoints(t *testing.T) {
	t.Parallel()

	roles := []unikornv1.Role{
		role("00000000-0000-0000-0000-00000000000a", unikornv1.RoleScopes{
			Organization: []unikornv1.RoleScope{
				scope("example:widgets", unikornv1.Read),
				scope("example:widgets", unikornv1.Create, unikornv1.Read),
			},
		}),
	}

	output, err := generate.Generate(roles)
	require.NoError(t, err)

	require.Len(t, output.ResourcePolicies, 1)

	rules := output.ResourcePolicies[0].ResourcePolicy.Rules
	require.Len(t, rules, 1)
	require.Equal(t, []string{"create", "read"}, rules[0].Actions)
}

// TestGenerateIsOrderInvariant verifies byte-stable output regardless of
// input order: the store is compared byte-for-byte by controllers and golden
// tests, so ordering must come from the data, not the caller.
func TestGenerateIsOrderInvariant(t *testing.T) {
	t.Parallel()

	roles := loadFixtureRoles(t)

	forward, err := generate.Generate(roles)
	require.NoError(t, err)

	slices.Reverse(roles)

	reversed, err := generate.Generate(roles)
	require.NoError(t, err)

	forwardFiles, err := forward.Files()
	require.NoError(t, err)

	reversedFiles, err := reversed.Files()
	require.NoError(t, err)

	require.Len(t, reversedFiles, len(forwardFiles))

	for name, data := range forwardFiles {
		require.Equal(t, string(data), string(reversedFiles[name]), name)
	}
}

// TestGenerateInvalidInput verifies the generator fails loudly on inputs the
// binding-string contract cannot represent, rather than emitting policies
// that are broken or ambiguous.
func TestGenerateInvalidInput(t *testing.T) {
	t.Parallel()

	grants := unikornv1.RoleScopes{
		Organization: []unikornv1.RoleScope{scope("identity:groups", unikornv1.Read)},
	}

	cases := map[string]struct {
		roles []unikornv1.Role
		err   error
	}{
		"EmptyRoleID": {
			roles: []unikornv1.Role{role("", grants)},
			err:   generate.ErrInvalidRole,
		},
		"RoleIDNotAKubernetesName": {
			roles: []unikornv1.Role{role("role#1", grants)},
			err:   generate.ErrInvalidRole,
		},
		"DuplicateRoleIDs": {
			roles: []unikornv1.Role{
				role("00000000-0000-0000-0000-00000000000a", grants),
				role("00000000-0000-0000-0000-00000000000a", grants),
			},
			err: generate.ErrInvalidRole,
		},
		"EmptyEndpointNameWithOperations": {
			roles: []unikornv1.Role{
				role("00000000-0000-0000-0000-00000000000a", unikornv1.RoleScopes{
					Organization: []unikornv1.RoleScope{scope("", unikornv1.Read)},
				}),
			},
			err: generate.ErrInvalidScope,
		},
		"EndpointNameWithGlobAsterisk": {
			roles: []unikornv1.Role{
				role("00000000-0000-0000-0000-00000000000a", unikornv1.RoleScopes{
					Organization: []unikornv1.RoleScope{scope("example:*", unikornv1.Read)},
				}),
			},
			err: generate.ErrInvalidScope,
		},
		"EndpointNameWithGlobQuestionMark": {
			roles: []unikornv1.Role{
				role("00000000-0000-0000-0000-00000000000a", unikornv1.RoleScopes{
					Organization: []unikornv1.RoleScope{scope("example:widgets?", unikornv1.Read)},
				}),
			},
			err: generate.ErrInvalidScope,
		},
		"EndpointNameWithGlobBrackets": {
			roles: []unikornv1.Role{
				role("00000000-0000-0000-0000-00000000000a", unikornv1.RoleScopes{
					Organization: []unikornv1.RoleScope{scope("example:widgets[1]", unikornv1.Read)},
				}),
			},
			err: generate.ErrInvalidScope,
		},
		"EndpointNameWithGlobBraces": {
			roles: []unikornv1.Role{
				role("00000000-0000-0000-0000-00000000000a", unikornv1.RoleScopes{
					Organization: []unikornv1.RoleScope{scope("example:{widgets}", unikornv1.Read)},
				}),
			},
			err: generate.ErrInvalidScope,
		},
		"EndpointNameWithGlobExclamationMark": {
			roles: []unikornv1.Role{
				role("00000000-0000-0000-0000-00000000000a", unikornv1.RoleScopes{
					Organization: []unikornv1.RoleScope{scope("example:widgets!", unikornv1.Read)},
				}),
			},
			err: generate.ErrInvalidScope,
		},
		"FileNameCollision": {
			roles: []unikornv1.Role{
				role("00000000-0000-0000-0000-00000000000a", unikornv1.RoleScopes{
					Organization: []unikornv1.RoleScope{
						scope("example:widgets", unikornv1.Read),
						scope("example/widgets", unikornv1.Read),
					},
				}),
			},
			err: generate.ErrFileNameCollision,
		},
		"CaseOnlyFileNameCollision": {
			roles: []unikornv1.Role{
				role("00000000-0000-0000-0000-00000000000a", unikornv1.RoleScopes{
					Organization: []unikornv1.RoleScope{
						scope("example:widgets", unikornv1.Read),
						scope("example:widgetS", unikornv1.Read),
					},
				}),
			},
			err: generate.ErrFileNameCollision,
		},
	}

	for name, testcase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := generate.Generate(testcase.roles)
			require.ErrorIs(t, err, testcase.err)
		})
	}
}

// TestGenerateEndpointNameValidationIsNotStricterThanCerbos pins the
// endpoint-name check to what Cerbos v0.53.0 actually loads: only glob
// metacharacters (and the empty string) are rejected, so names with a leading
// digit, a space or a '#' — which older Cerbos releases refused — must
// generate cleanly.  Endpoint names are an open vocabulary, so the generator
// must never reject a name the pinned Cerbos version accepts.
func TestGenerateEndpointNameValidationIsNotStricterThanCerbos(t *testing.T) {
	t.Parallel()

	roles := []unikornv1.Role{
		role("00000000-0000-0000-0000-00000000000a", unikornv1.RoleScopes{
			Organization: []unikornv1.RoleScope{
				scope("0day:reports", unikornv1.Read),
				scope("example:widget gadget", unikornv1.Read),
				scope("example:widgets#detail", unikornv1.Read),
			},
		}),
	}

	output, err := generate.Generate(roles)
	require.NoError(t, err)
	require.Len(t, output.ResourcePolicies, 3)
}
