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
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/yaml"
)

// splitIDNamespace is the UUIDv5 namespace for per-service role IDs. Other
// systems derive the same IDs, so it must never change.
const splitIDNamespace = "6f1c0b5e-8f4b-4a7e-9a39-6d1f2f0e9c11"

type builtinRoleSplits struct {
	Roles       []string          `json:"roles"`
	Prefixes    []string          `json:"prefixes"`
	OffPrefixes []string          `json:"offPrefixes"`
	IDs         map[string]string `json:"ids"`
}

// TestBuiltinRoleSplitIDs checks that every per-service role has a fixed ID,
// that the ID is the UUIDv5 of its name, and that no stale IDs are left.
func TestBuiltinRoleSplitIDs(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Clean(chartValuesPath))
	require.NoError(t, err)

	var values struct {
		Roles  map[string]chartRole `json:"roles"`
		Splits builtinRoleSplits    `json:"builtinRoleSplits"`
	}

	require.NoError(t, yaml.Unmarshal(raw, &values))

	splits := values.Splits
	require.NotEmpty(t, splits.Roles)

	for _, prefix := range splits.OffPrefixes {
		require.Containsf(t, splits.Prefixes, prefix, "offPrefixes entry %q is not in prefixes", prefix)
	}

	namespace := uuid.MustParse(splitIDNamespace)
	want := map[string]string{}

	for _, role := range splits.Roles {
		require.Containsf(t, values.Roles, role, "split role %q is not a built-in role", role)

		names := make([]string, 0, len(splits.Prefixes)+len(splits.OffPrefixes))

		for _, prefix := range splits.Prefixes {
			names = append(names, role+"-"+prefix)
		}

		for _, prefix := range splits.OffPrefixes {
			names = append(names, role+"-"+prefix+"-off")
		}

		for _, name := range names {
			want[name] = uuid.NewSHA1(namespace, []byte(name)).String()
		}
	}

	require.Equal(t, want, splits.IDs)
}
