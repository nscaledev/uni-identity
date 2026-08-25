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

// The tests in this file pin the integration-test fixtures to the chart, so
// the "boots the PDP as deployed" claim stays honest.  They read the chart
// templates from the repo tree and deliberately carry no build tag: they run
// in make test-unit.
package cerbos_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/yaml"
)

const (
	chartConfigPath     = "../../../charts/identity/templates/identity/cerbos-config.yaml"
	chartDeploymentPath = "../../../charts/identity/templates/identity/deployment.yaml"
	testConfigPath      = "testdata/config/config.yaml"
)

// healthcheckCommand is the sidecar probe command.  The chart's exec probes
// must carry it byte-for-byte (TestChartProbesExecHealthcheckCommand) and the
// integration test execs it against the test container (waitHealthy), so the
// probe the test proves working is exactly the probe the kubelet runs.
func healthcheckCommand() []string {
	return []string{"/cerbos", "healthcheck", "--config=/config/config.yaml"}
}

// chartConfigDocument extracts the cerbos config document embedded in the
// chart's ConfigMap template.  The data block is static text today; if a
// template expression ever creeps in, this fails loudly so the extraction
// (and the sync guarantee) gets revisited rather than silently rotting.
func chartConfigDocument(t *testing.T) []byte {
	t.Helper()

	raw, err := os.ReadFile(chartConfigPath)
	require.NoError(t, err)

	_, block, found := strings.Cut(string(raw), "  config.yaml: |\n")
	require.True(t, found, "config.yaml block not found in %s", chartConfigPath)

	blockLines := strings.Split(block, "\n")
	lines := make([]string, 0, len(blockLines))

	for _, line := range blockLines {
		if line != "" && !strings.HasPrefix(line, "    ") {
			break
		}

		lines = append(lines, strings.TrimPrefix(line, "    "))
	}

	document := strings.Join(lines, "\n")
	require.NotContains(t, document, "{{", "template expression inside the config document; extract literal YAML lines")

	return []byte(document)
}

// TestChartAndTestConfigsMatch requires the integration test's cerbos config
// to be the chart's config, modulo exactly the two listen addresses: the
// chart binds loopback because the PDP is unauthenticated and must never
// bind pod interfaces, while docker --publish forwards to the container IP,
// not container-loopback, so the test config must bind all interfaces to be
// reachable from the host.  Every other field must be identical, so a change
// to only one copy fails here.
func TestChartAndTestConfigsMatch(t *testing.T) {
	t.Parallel()

	var chartConfig, testConfig map[string]any

	require.NoError(t, yaml.Unmarshal(chartConfigDocument(t), &chartConfig))

	raw, err := os.ReadFile(testConfigPath)
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(raw, &testConfig))

	chartServer, ok := chartConfig["server"].(map[string]any)
	require.True(t, ok)

	testServer, ok := testConfig["server"].(map[string]any)
	require.True(t, ok)

	// The two exempted fields, asserted explicitly on both sides.
	require.Equal(t, "127.0.0.1:3592", chartServer["httpListenAddr"])
	require.Equal(t, "127.0.0.1:3593", chartServer["grpcListenAddr"])
	require.Equal(t, "0.0.0.0:3592", testServer["httpListenAddr"])
	require.Equal(t, "0.0.0.0:3593", testServer["grpcListenAddr"])

	delete(chartServer, "httpListenAddr")
	delete(chartServer, "grpcListenAddr")
	delete(testServer, "httpListenAddr")
	delete(testServer, "grpcListenAddr")

	require.Equal(t, chartConfig, testConfig, "chart and test cerbos configs differ beyond the listen addresses; update both copies")
}

// TestChartProbesExecHealthcheckCommand requires both sidecar probes in the
// chart to exec healthcheckCommand byte-for-byte — the same command the
// integration test execs against the test container.
func TestChartProbesExecHealthcheckCommand(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(chartDeploymentPath)
	require.NoError(t, err)

	block := "exec:\n            command:\n"
	for _, argument := range healthcheckCommand() {
		block += "            - " + argument + "\n"
	}

	require.Equal(t, 2, strings.Count(string(raw), block),
		"expected the readiness and liveness probes in %s to exec %v", chartDeploymentPath, healthcheckCommand())
}
