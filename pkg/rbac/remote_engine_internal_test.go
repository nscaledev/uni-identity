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
// remoteEngineFromContext directly -- it has no caller yet (Task 6's
// dispatchCoarse is the first), so an external rbac_test file could not
// reach it at all.  The *_internal_test.go suffix exempts it from the
// testpackage linter, mirroring engine_internal_test.go's precedent.
package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// fakeCoarseEngine is a minimal CoarseEngine double for round-tripping
// through the context.  Task 5 only seeds and reads the context -- dispatch
// (Task 6) is what actually calls an engine -- so these methods are never
// invoked; they exist solely to satisfy the interface.
type fakeCoarseEngine struct{}

func (fakeCoarseEngine) AllowCoarse(context.Context, Resource, openapi.AclOperation) error {
	return nil
}

func (fakeCoarseEngine) AllowCoarseMany(context.Context, []Resource, openapi.AclOperation) ([]bool, error) {
	return nil, nil
}

var _ CoarseEngine = fakeCoarseEngine{}

func TestRemoteEngineContext(t *testing.T) {
	t.Parallel()

	t.Run("a seeded context returns the exact engine and mode", func(t *testing.T) {
		t.Parallel()

		engine := fakeCoarseEngine{}

		ctx := NewRemoteEngineContext(t.Context(), engine, RemoteEnforce)

		gotEngine, gotMode := remoteEngineFromContext(ctx)
		require.Equal(t, engine, gotEngine)
		require.Equal(t, RemoteEnforce, gotMode)
	})

	t.Run("an unseeded context defaults to (nil, RemoteOff)", func(t *testing.T) {
		t.Parallel()

		// This is the structural fail-safe: every context that predates Task
		// 6's dispatch fork -- which is every context in existence today --
		// must resolve here, and it must resolve to "do not consult a remote
		// engine", not merely to some zero-valued engine.
		gotEngine, gotMode := remoteEngineFromContext(t.Context())
		require.Nil(t, gotEngine)
		require.Equal(t, RemoteOff, gotMode)
	})
}

func TestParseRemoteMode(t *testing.T) {
	t.Parallel()

	t.Run("maps the three whitelisted strings", func(t *testing.T) {
		t.Parallel()

		mode, err := ParseRemoteMode("off")
		require.NoError(t, err)
		require.Equal(t, RemoteOff, mode)

		mode, err = ParseRemoteMode("shadow")
		require.NoError(t, err)
		require.Equal(t, RemoteShadow, mode)

		mode, err = ParseRemoteMode("enforce")
		require.NoError(t, err)
		require.Equal(t, RemoteEnforce, mode)
	})

	t.Run("rejects anything else", func(t *testing.T) {
		t.Parallel()

		_, err := ParseRemoteMode("bogus")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidRemoteMode)
		require.ErrorContains(t, err, "off")
		require.ErrorContains(t, err, "shadow")
		require.ErrorContains(t, err, "enforce")
	})
}
