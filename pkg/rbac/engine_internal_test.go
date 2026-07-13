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

// This file is package rbac (internal) so it can exercise the unexported
// per-kind mode resolver modeForKind directly; the *_internal_test.go suffix
// exempts it from the testpackage linter (the same reason cachekey_test.go
// carries a lint suppression).
package rbac

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// modeForKind is the A12 strangle-by-kind switch: it decides, per endpoint
// kind, whether Cerbos is authoritative regardless of the global
// --authorization-engine baseline.  It is what makes Cerbos the SERVED decision
// for a cut-over kind, so its correctness is security-critical and it is tested
// directly rather than only through dispatch (engine_cutover_test.go covers the
// observable dispatch behaviour on top).

// modeEngine builds an RBAC whose only configured surface is the global mode and
// the cutover set — modeForKind reads nothing else, so the nil client is safe.
func modeEngine(global EngineMode, cutover ...string) *RBAC {
	return New(nil, "", &Options{
		AuthorizationEngine:      global,
		CerbosAuthoritativeKinds: cutover,
	})
}

func TestModeForKind(t *testing.T) {
	t.Parallel()

	const (
		cutoverKind    = "identity:groups"
		nonCutoverKind = "identity:projects"
	)

	// Every global baseline the switch has to override or defer to.
	globals := []EngineMode{EngineLegacy, EngineShadow, EngineCerbos}

	t.Run("a cutover kind is Cerbos-authoritative regardless of the global baseline", func(t *testing.T) {
		t.Parallel()

		// The whole point of the strangle switch: a cut-over kind is served by
		// Cerbos even when the global engine is legacy or shadow.
		for _, global := range globals {
			engine := modeEngine(global, cutoverKind)
			require.Equal(t, EngineCerbos, engine.modeForKind(cutoverKind), "global=%s", global)
		}
	})

	t.Run("a non-cutover kind follows the global mode", func(t *testing.T) {
		t.Parallel()

		// A kind NOT in the set is untouched by the cutover — it resolves to the
		// same mode() every other kind would under this baseline.
		for _, global := range globals {
			engine := modeEngine(global, cutoverKind)
			require.Equal(t, engine.mode(), engine.modeForKind(nonCutoverKind), "global=%s", global)
		}
	})

	t.Run("an empty cutover set is always the global mode (the inert default and rollback)", func(t *testing.T) {
		t.Parallel()

		// The zero-behaviour-change contract: with no cutover, modeForKind is
		// mode() for every kind, so dispatch is byte-identical to pre-A12 — and
		// clearing the set is how a kind is rolled back.
		for _, global := range globals {
			engine := modeEngine(global)
			require.Equal(t, engine.mode(), engine.modeForKind(cutoverKind), "global=%s", global)
		}
	})

	t.Run("cutover entries are whitespace-trimmed and blanks ignored", func(t *testing.T) {
		t.Parallel()

		// --cerbos-authoritative-kinds is a StringSliceVar that does NOT trim, so
		// "identity:groups, identity:projects" stores a leading-space
		// " identity:projects".  New trims each entry (and drops blanks), so the
		// exact-match still lands and a stray space cannot silently defeat a
		// cutover; blanks must not create a spurious match either.
		engine := modeEngine(EngineShadow, " identity:groups ", "", "   ")
		require.Equal(t, EngineCerbos, engine.modeForKind("identity:groups"), "a whitespace-padded entry must still cut over the trimmed endpoint")
		require.Equal(t, EngineShadow, engine.modeForKind("identity:projects"), "blank entries are ignored, not matched")
	})
}
