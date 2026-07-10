//go:build integration

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

// The tests in this file run the REAL compile gate against the pinned Cerbos
// binary and pin the hash-suffixed key scheme.  Run them with
// make test-cerbos-controller, which extracts the binary from the pinned
// image via docker create/cp (the same binary the controller image vendors)
// and sets CERBOS_BINARY and CERBOS_IMAGE.
//
// On Linux (CI, and the shape production takes: the controller exec's a
// binary path inside its own image) the gate exec's the extracted binary
// directly.  On other hosts a Linux ELF cannot exec, so the gate is pointed
// at a wrapper script driving the pinned image via docker run instead — the
// same ExecGate code path and the same pinned compiler, matching the A1
// client test's docker-run conventions.
package controller

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos/generate"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// brokenPolicy is structurally valid YAML that cannot compile: it imports a
// derived-roles document that does not exist, which is a load-time
// compilation error (`cerbos compile` exit code 3), not a test failure.
const brokenPolicy = `apiVersion: api.cerbos.dev/v1
resourcePolicy:
  resource: widget
  version: default
  importDerivedRoles:
    - does_not_exist
  rules:
    - actions: ["read"]
      effect: EFFECT_ALLOW
      derivedRoles:
        - ghost
`

// gateBinary returns the path ExecGate should exec to run the pinned
// `cerbos compile` on this platform.  Requiring the environment rather than
// falling back to a hardcoded image tag keeps the version pin in exactly the
// four places the Makefile's validate-cerbos-version guard checks.
func gateBinary(t *testing.T) string {
	t.Helper()

	if runtime.GOOS == "linux" {
		binary := os.Getenv("CERBOS_BINARY")
		require.NotEmpty(t, binary, "CERBOS_BINARY is not set: run via make test-cerbos-controller")

		return binary
	}

	image := os.Getenv("CERBOS_IMAGE")
	require.NotEmpty(t, image, "CERBOS_IMAGE is not set: run via make test-cerbos-controller")

	// ExecGate invokes `<binary> compile <dir>`: the wrapper discards the
	// literal "compile" ($1) and mounts the store directory ($2) where the
	// containerized compiler expects it.  docker run propagates the
	// container's exit code, so ExecGate's classification sees the real
	// cerbos exit codes.
	wrapper := fmt.Sprintf("#!/bin/sh\nexec docker run --rm --volume \"$2:/policies:ro\" %s compile /policies\n", image)

	path := filepath.Join(t.TempDir(), "cerbos-compile-wrapper")
	require.NoError(t, os.WriteFile(path, []byte(wrapper), 0o700)) //nolint:gosec // the wrapper must be executable.

	return path
}

// storeDir returns a scratch directory for a candidate store.  On non-Linux
// hosts the directory is mounted into the compiler container, so it must
// live under the repository (docker file sharing covers the home directory;
// t.TempDir lives outside it, e.g. /var/folders on darwin, which colima does
// not share).
func storeDir(t *testing.T) string {
	t.Helper()

	if runtime.GOOS == "linux" {
		return t.TempDir()
	}

	cwd, err := os.Getwd()
	require.NoError(t, err)

	dir, err := os.MkdirTemp(cwd, ".cerbos-gate-test-*")
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, os.RemoveAll(dir))
	})

	return dir
}

// generatedStore produces exactly what the reconciler would publish for a
// small role set: generate.Generate output under hash-suffixed keys.
func generatedStore(t *testing.T) map[string]string {
	t.Helper()

	role := unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "role-a"},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Organization: []unikornv1.RoleScope{
					{
						Name:       "identity:groups",
						Operations: []unikornv1.Operation{unikornv1.Read, unikornv1.Create},
					},
				},
			},
		},
	}

	output, err := generate.Generate([]unikornv1.Role{role})
	require.NoError(t, err)

	files, err := output.Files()
	require.NoError(t, err)

	return hashKeyedData(files)
}

func writeStore(t *testing.T, dir string, data map[string]string) {
	t.Helper()

	for name, content := range data {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644)) //nolint:gosec // world-readable like a ConfigMap volume projection.
	}
}

// TestExecGateAcceptsGeneratedStore pins that a store exactly as the
// reconciler publishes it — generated documents under hash-suffixed file
// names — compiles cleanly (exit 0) on the pinned compiler, i.e. the key
// scheme does not confuse Cerbos's loader.
func TestExecGateAcceptsGeneratedStore(t *testing.T) {
	gate := NewExecGate(gateBinary(t))

	dir := storeDir(t)
	writeStore(t, dir, generatedStore(t))

	require.NoError(t, gate.Compile(t.Context(), dir))
}

// TestExecGateClassifiesCompileFailure pins the refusal classification: a
// store with a broken policy exits 3 on the pinned compiler and surfaces as
// ErrCompileFailed (not ErrTestsFailed, not the unclassified ErrGateFailed).
func TestExecGateClassifiesCompileFailure(t *testing.T) {
	gate := NewExecGate(gateBinary(t))

	dir := storeDir(t)
	writeStore(t, dir, generatedStore(t))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "resource_broken-deadbeef.yaml"), []byte(brokenPolicy), 0o644)) //nolint:gosec

	err := gate.Compile(t.Context(), dir)
	require.ErrorIs(t, err, ErrCompileFailed)
	require.NotErrorIs(t, err, ErrTestsFailed)
	require.NotErrorIs(t, err, ErrGateFailed)
	require.Contains(t, err.Error(), "does_not_exist", "the compiler's diagnostics must be attached to the error")
}

// TestHashKeyScheme pins the publishing key contract the sidecar reload
// depends on: identical content keeps an identical key (no spurious volume
// events), changed content swaps the key (a visible delete+create the
// watcher reloads on), and every key stays a valid ConfigMap key.
func TestHashKeyScheme(t *testing.T) {
	t.Parallel()

	same := hashKey("resource_widget.yaml", []byte("content"))
	require.Equal(t, same, hashKey("resource_widget.yaml", []byte("content")), "identical content must keep an identical key")

	changed := hashKey("resource_widget.yaml", []byte("changed"))
	require.NotEqual(t, same, changed, "changed content must swap the key")

	require.Regexp(t, `^resource_widget-[0-9a-f]{8}\.yaml$`, same, "key shape is <base>-<sha256[:8]>.yaml")

	for key := range generatedStore(t) {
		require.Empty(t, validation.IsConfigMapKey(key), "generated key %q must be a valid ConfigMap key", key)
	}
}
