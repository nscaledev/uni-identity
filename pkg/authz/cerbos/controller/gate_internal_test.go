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

package controller

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestExecGateBoundsAHungCompile pins that a compile that does not exit fails
// the gate.  Every Role event goes to one reconcile key.  Without the limit, a
// hung gate stops every later publication, revokes included.
func TestExecGateBoundsAHungCompile(t *testing.T) {
	t.Parallel()

	binary := filepath.Join(t.TempDir(), "cerbos")
	require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\nexec sleep 30\n"), 0o700)) //nolint:gosec // the stand-in compiler must be executable.

	gate := &ExecGate{binary: binary, timeout: 100 * time.Millisecond}

	start := time.Now()

	require.ErrorIs(t, gate.Compile(t.Context(), t.TempDir()), ErrGateFailed)
	require.Less(t, time.Since(start), 10*time.Second, "the gate must stop at its timeout")
}
