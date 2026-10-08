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

package metrics_test

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/unikorn-cloud/core/pkg/util"
	"github.com/unikorn-cloud/identity/pkg/controllers/metrics"
)

func TestReporter(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	reporter, err := metrics.New(provider.Meter("test"), util.ServiceDescriptor{
		Name:     "unikorn-organization-controller",
		Version:  "v1.2.3",
		Revision: "abc123",
	})

	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := reporter.Close(); err != nil {
			t.Error(err)
		}
	})

	if !reporter.NeedLeaderElection() {
		t.Fatal("reporter must wait for leader election")
	}

	assertGauge(t, reader, "unikorn_identity_controller_build_info", 1)
	assertGauge(t, reader, "unikorn_controller_ready", 0)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)

	go func() {
		done <- reporter.Start(ctx)
	}()

	assertGaugeEventually(t, reader, "unikorn_controller_ready", 1)

	cancel()

	if err := <-done; err != nil {
		t.Fatal(err)
	}

	assertGauge(t, reader, "unikorn_controller_ready", 0)
}

func assertGaugeEventually(t *testing.T, reader *sdkmetric.ManualReader, name string, want int64) {
	t.Helper()

	deadline := time.Now().Add(time.Second)

	for {
		if gaugeValue(t, reader, name) == want {
			return
		}

		if time.Now().After(deadline) {
			t.Fatalf("metric %q did not reach %d", name, want)
		}

		time.Sleep(time.Millisecond)
	}
}

func assertGauge(t *testing.T, reader *sdkmetric.ManualReader, name string, want int64) {
	t.Helper()

	if got := gaugeValue(t, reader, name); got != want {
		t.Fatalf("metric %q has value %d, want %d", name, got, want)
	}
}

func gaugeValue(t *testing.T, reader *sdkmetric.ManualReader, name string) int64 {
	t.Helper()

	var collected metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &collected); err != nil {
		t.Fatal(err)
	}

	for _, scope := range collected.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != name {
				continue
			}

			data, ok := metric.Data.(metricdata.Gauge[int64])
			if !ok || len(data.DataPoints) != 1 {
				t.Fatalf("metric %q has unexpected data: %#v", name, metric.Data)
			}

			point := data.DataPoints[0]
			if !attributesMatch(point.Attributes) {
				t.Fatalf("metric %q has unexpected attributes %v", name, point.Attributes)
			}

			return point.Value
		}
	}

	t.Fatalf("metric %q not found", name)

	return 0
}

func attributesMatch(attributes attribute.Set) bool {
	for key, value := range map[string]string{
		"controller": "unikorn-organization-controller",
		"version":    "v1.2.3",
		"revision":   "abc123",
	} {
		attribute, ok := attributes.Value(attribute.Key(key))
		if !ok || attribute.AsString() != value {
			return false
		}
	}

	return attributes.Len() == 3
}
