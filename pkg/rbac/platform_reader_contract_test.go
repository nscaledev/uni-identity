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
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// The read-surface audit classification for platform-reader (ID-399).
// Every platform-administrator global scope that carries `read` MUST appear in
// exactly one place: platform-reader's global block, platformReaderExcludedScopes,
// or platformReaderOmittedScopes. The audit record with full evidence lives in
// docs/platform-reader.md.
//
// LIMITATION: this ratchet governs the identity role catalogue only. It cannot
// see a downstream service adding a credential-returning GET route under an
// already-included scope — route-level semantics are owned by the downstream
// services (see docs/platform-reader.md#follow-ups).

// platformReaderExcludedScopes lists read-bearing admin scopes whose read
// endpoints are credential- or control-equivalent. Functions rather than
// package-level vars: gochecknoglobals is enabled repo-wide and fires on
// test-file globals too.
func platformReaderExcludedScopes() map[string]string {
	return map[string]string{
		"region:identities":                         "read returns clouds.yaml application credential and SSH private key",
		"region:servers":                            "sshkey/console-session reads return credentials; v2 power actions are read-gated",
		"kubernetes:clusters":                       "kubeconfig download shares scope+read with listing and returns admin kubeconfig",
		"kubernetes:virtualclusters":                "kubeconfig download shares scope+read with listing and returns admin kubeconfig",
		"compute:instances":                         "proxies region sshkey/console-session; power actions are read-gated",
		"storage:objectstorageendpoints/accesskeys": "credential-class sub-resource; conservative exclusion, the scope's entire subject is credentials",
	}
}

// platformReaderOmittedScopes lists read-bearing admin scopes nothing serves
// today; omitted fail-closed so a future API forces a fresh classification.
func platformReaderOmittedScopes() map[string]string {
	return map[string]string{
		"identity:projects/references":  "write-only sub-resource; no read endpoint exists",
		"region:identities/references":  "scope string unserved by uni-region",
		"region:networks/references":    "scope string unserved by uni-region",
		"region:networks:v2/references": "write-only sub-resource; no read endpoint exists",
		"region:servers:v2":             "no code checks this scope; v2 server endpoints check region:servers",
		"region:volumes:v2":             "volumes API not shipped at audit time (2026-08-07)",
		"compute:clusters":              "scope unserved by uni-compute",
	}
}

// readProjection returns the scopes whose verb lists include read, projected
// from a role's global block. Extracted to keep TestPlatformReaderContract
// under the cyclop ceiling with headroom.
func readProjection(global endpointOperations) map[string]bool {
	projection := map[string]bool{}

	for scope, ops := range global {
		if slices.Contains(ops, "read") {
			projection[scope] = true
		}
	}

	return projection
}

func TestPlatformReaderContract(t *testing.T) {
	t.Parallel()

	roles := loadChartRoles(t)

	admin, ok := roles["platform-administrator"]
	require.True(t, ok, "platform-administrator missing from chart role catalogue")

	reader, ok := roles["platform-reader"]
	require.True(t, ok, "platform-reader missing from chart role catalogue")

	require.True(t, reader.Protected, "platform-reader must be protected: true")
	require.Empty(t, reader.Scopes.Organization, "platform-reader must be global-only: no organization block")
	require.Empty(t, reader.Scopes.Project, "platform-reader must be global-only: no project block")

	// The read-projection: every admin global scope whose verbs include read.
	projection := readProjection(admin.Scopes.Global)

	excluded := platformReaderExcludedScopes()
	omitted := platformReaderOmittedScopes()

	// Classification sets must partition cleanly and must not go stale:
	// every entry must still be read-bearing on platform-administrator.
	for scope, rationale := range excluded {
		require.NotEmpty(t, rationale, "exclusion %q must carry a rationale", scope)
		require.NotContains(t, omitted, scope, "scope classified as both excluded and omitted")
		require.Contains(t, projection, scope,
			"stale exclusion: %q is no longer read-bearing on platform-administrator; delete its entry so a future read-grant forces re-classification", scope)
	}

	for scope, rationale := range omitted {
		require.NotEmpty(t, rationale, "omission %q must carry a rationale", scope)
		require.Contains(t, projection, scope,
			"stale omission: %q is no longer read-bearing on platform-administrator; delete its entry so a future read-grant forces re-classification", scope)
	}

	// Expected reader surface = projection minus both classification sets.
	expected := maps.Clone(projection)

	maps.DeleteFunc(expected, func(scope string, _ bool) bool {
		_, isExcluded := excluded[scope]
		_, isOmitted := omitted[scope]

		return isExcluded || isOmitted
	})

	for scope, ops := range reader.Scopes.Global {
		require.Equal(t, []string{"read"}, ops, "platform-reader scope %q must grant exactly [read]", scope)
		require.Contains(t, expected, scope,
			"platform-reader grants %q, which is not an included read-projection scope of platform-administrator; either remove it or reclassify it in this test with an audit rationale", scope)
	}

	for scope := range expected {
		require.Contains(t, reader.Scopes.Global, scope,
			"unclassified read-bearing scope %q on platform-administrator: add %q: [read] to platform-reader after a read-surface audit, or add it to platformReaderExcludedScopes/platformReaderOmittedScopes with a rationale (see docs/platform-reader.md)", scope, scope)
	}
}
