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

// The tests in this file run the pinned Cerbos image via Docker (like make
// validate-policies) with the hand-written allow/deny policy under
// testdata/policies, and exercise the client contract end to end: health,
// a CheckResources round-trip, the fail-closed unavailable sentinel and the
// per-call timeout.  Run them with make test-cerbos-client.
package cerbos_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdk "github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/unikorn-cloud/identity/pkg/authz/cerbos"
)

// defaultImage is the pinned Cerbos image; make test-cerbos-client overrides
// it via CERBOS_IMAGE from the Makefile's CERBOS_VERSION so there is a single
// source of truth in CI.  Keep the fallback tag consistent with the Makefile.
const defaultImage = "ghcr.io/cerbos/cerbos:0.53.0"

// cerbosUID mirrors the runAsUser the chart sets on the sidecar container
// (the upstream image defaults to root, which the pod's runAsNonRoot
// forbids), so the test continuously verifies the image works as that user.
const cerbosUID = "65534"

// startCerbos runs the pinned Cerbos image with the fixture policy store,
// mirroring the chart's pod constraints (non-root user, read-only root
// filesystem, writable /tmp and /.cache, read-only config and policies),
// waits for it to become healthy and returns the gRPC endpoint.
func startCerbos(t *testing.T) string {
	t.Helper()

	image := os.Getenv("CERBOS_IMAGE")
	if image == "" {
		image = defaultImage
	}

	cwd, err := os.Getwd()
	require.NoError(t, err)

	name := fmt.Sprintf("cerbos-client-test-%d", time.Now().UnixNano())

	// Registered before docker run so a partially-created container never
	// leaks; docker rm --force is idempotent and tolerates the container
	// not existing (the error is discarded).
	t.Cleanup(func() {
		//nolint:usetesting // t.Context() is already canceled inside Cleanup and would kill the removal command.
		_ = exec.CommandContext(context.Background(), "docker", "rm", "--force", name).Run()
	})

	cmd := exec.CommandContext(t.Context(), "docker", "run",
		"--detach",
		"--name", name,
		"--user", cerbosUID+":"+cerbosUID,
		"--read-only",
		"--tmpfs", "/tmp",
		"--tmpfs", "/.cache",
		"--volume", filepath.Join(cwd, "testdata", "config")+":/config:ro",
		"--volume", filepath.Join(cwd, "testdata", "policies")+":/policies:ro",
		"--publish", "127.0.0.1:0:3593",
		image,
		"server", "--config=/config/config.yaml",
	)

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "docker run: %s", out)

	waitHealthy(t, name)

	return hostPort(t, name, "3593/tcp")
}

// hostPort resolves the random host port Docker bound for a container port.
func hostPort(t *testing.T, name, port string) string {
	t.Helper()

	out, err := exec.CommandContext(t.Context(), "docker", "port", name, port).Output()
	require.NoError(t, err, "docker port %s %s", name, port)

	// Docker may report both IPv4 and IPv6 bindings; the first line is the
	// requested 127.0.0.1 one.
	addr, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	require.NotEmpty(t, addr)

	return addr
}

// waitHealthy polls the PDP until healthy by exec'ing the chart's exact
// probe command (healthcheckCommand — pinned byte-for-byte to the chart's
// exec probes by TestChartProbesExecHealthcheckCommand) inside the
// container, so the readiness signal the test relies on is the one the
// kubelet runs against the deployed sidecar.
func waitHealthy(t *testing.T, name string) {
	t.Helper()

	deadline := time.Now().Add(time.Minute)

	arguments := append([]string{"exec", name}, healthcheckCommand()...)

	for {
		if time.Now().After(deadline) {
			logs, _ := exec.CommandContext(t.Context(), "docker", "logs", name).CombinedOutput()
			require.FailNowf(t, "cerbos did not become healthy", "container logs:\n%s", logs)
		}

		if err := exec.CommandContext(t.Context(), "docker", arguments...).Run(); err == nil {
			return
		}

		time.Sleep(200 * time.Millisecond)
	}
}

// unusedEndpoint returns a localhost address nothing is listening on.
func unusedEndpoint(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := listener.Addr().String()
	require.NoError(t, listener.Close())

	return addr
}

// principalAndBatch builds the fixture request: role "tester" asking for the
// allowed action ("read") and a never-granted one ("delete") on a widget.
func principalAndBatch() (*sdk.Principal, *sdk.ResourceBatch) {
	principal := sdk.NewPrincipal("subject", "tester")
	batch := sdk.NewResourceBatch().Add(sdk.NewResource("widget", "widget1"), "read", "delete")

	return principal, batch
}

// TestClient exercises the client against a real PDP running the pinned
// image with the hand-written allow/deny policy under testdata/policies.
func TestClient(t *testing.T) {
	t.Parallel()

	endpoint := startCerbos(t)

	client, err := cerbos.New(&cerbos.Options{Endpoint: endpoint, CheckTimeout: 5 * time.Second})
	require.NoError(t, err)

	t.Run("HealthySucceedsAgainstServingPDP", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, client.Healthy(t.Context()))
	})

	t.Run("CheckResourcesRoundTripsAllowAndDeny", func(t *testing.T) {
		t.Parallel()

		principal, batch := principalAndBatch()

		response, err := client.CheckResources(t.Context(), principal, batch)
		require.NoError(t, err)

		result := response.GetResource("widget1")
		require.True(t, result.IsAllowed("read"), "the fixture policy allows tester to read widgets")
		require.False(t, result.IsAllowed("delete"), "delete is never granted, deny-by-default must apply")
	})

	// The per-call timeout must be applied as a context deadline on the
	// outgoing RPC: with an impossible timeout even a serving PDP yields a
	// DeadlineExceeded-class error, wrapped in the fail-closed sentinel.
	t.Run("CheckTimeoutIsAppliedPerCall", func(t *testing.T) {
		t.Parallel()

		client, err := cerbos.New(&cerbos.Options{Endpoint: endpoint, CheckTimeout: time.Nanosecond})
		require.NoError(t, err)

		principal, batch := principalAndBatch()

		response, err := client.CheckResources(t.Context(), principal, batch)
		require.Nil(t, response)
		require.ErrorIs(t, err, cerbos.ErrUnavailable)
		require.Equal(t, codes.DeadlineExceeded, status.Code(err))
	})
}

// TestClientFailsClosedWhenPDPUnavailable pins the fail-closed contract:
// when the PDP cannot be reached the client returns an error wrapping the
// static ErrUnavailable sentinel and never a response — it must not
// fabricate a decision.  The decision layer (A5) maps the sentinel to deny,
// so this error contract is what makes unavailability a deny.
//
// Deliberately NOT parallel: unusedEndpoint frees its port before the client
// dials it, and TestClient's docker run publishes on random host ports — run
// concurrently, Docker could rebind the freed port and a PDP would answer on
// the "unused" endpoint (freed-port TOCTOU).  Sequential ordering guarantees
// this test finishes before any parallel test starts a container.
func TestClientFailsClosedWhenPDPUnavailable(t *testing.T) {
	client, err := cerbos.New(&cerbos.Options{Endpoint: unusedEndpoint(t), CheckTimeout: time.Second})
	require.NoError(t, err)

	principal, batch := principalAndBatch()

	response, err := client.CheckResources(t.Context(), principal, batch)
	require.Nil(t, response)
	require.ErrorIs(t, err, cerbos.ErrUnavailable)

	require.ErrorIs(t, client.Healthy(t.Context()), cerbos.ErrUnavailable)
}
