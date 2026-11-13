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

package common

import (
	"os"
	"regexp"
	"strings"
	"testing"

	promclient "github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// TestLeaseDashboardMetricNames checks every Lease metric the dashboard queries is
// one the Prometheus exporter stores, so renaming an instrument breaks here rather
// than leaving the dashboard empty.
func TestLeaseDashboardMetricNames(t *testing.T) {
	t.Parallel()

	registry := promclient.NewRegistry()
	exporter, err := prometheus.New(prometheus.WithRegisterer(registry))
	require.NoError(t, err)

	metrics := newLeaseMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter)).Meter("test"))
	metrics.acquired(t.Context(), leaseResultCreated, 0)
	metrics.sections.Add(t.Context(), 1, leaseResult(leaseResultOK))
	metrics.section.Record(t.Context(), 1, leaseResult(leaseResultOK))
	metrics.releases.Add(t.Context(), 1, leaseResult(leaseResultReleased))

	families, err := registry.Gather()
	require.NoError(t, err)

	stored := map[string]bool{}

	for _, family := range families {
		stored[family.GetName()] = true
	}

	dashboard, err := os.ReadFile("../../../charts/identity-observability/files/dashboards/uni-identity-leases.json")
	require.NoError(t, err)

	queried := regexp.MustCompile(`unikorn_identity_organization_lease_\w+`).FindAllString(string(dashboard), -1)
	require.NotEmpty(t, queried)

	for _, name := range queried {
		for _, suffix := range []string{"_bucket", "_count", "_sum"} {
			if base, ok := strings.CutSuffix(name, suffix); ok && strings.HasSuffix(base, "_seconds") {
				name = base
			}
		}

		require.True(t, stored[name], "the dashboard queries %s, which the exporter does not store", name)
	}
}
