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
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/getkin/kin-openapi/routers"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	"github.com/unikorn-cloud/identity/pkg/middleware/metrics"
)

func TestMetrics(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	reporter, err := metrics.New(provider.Meter("test"))

	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://identity.example/api/v1/projects/first", nil)
	context := context.WithValue(request.Context(), routeresolver.RouteInfoKey, &routeresolver.RouteInfo{
		Route: &routers.Route{Path: "/api/v1/projects/{projectID}"},
	})
	request = request.WithContext(context)

	response := httptest.NewRecorder()
	reporter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})).ServeHTTP(response, request)

	var collected metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &collected); err != nil {
		t.Fatal(err)
	}

	// The stored (Prometheus) names are asserted verbatim: dashboards shared
	// across services query these exact strings.
	assertMetricAttributes(t, collected, "http_server_request_duration_seconds", map[string]string{
		"route":        "/api/v1/projects/{projectID}",
		"method":       http.MethodGet,
		"status_class": "5xx",
	})
	assertHistogramBounds(t, collected, "http_server_request_duration_seconds", []float64{
		0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
	})
	assertMetricAttributes(t, collected, "http_server_active_requests", map[string]string{
		"route":  "/api/v1/projects/{projectID}",
		"method": http.MethodGet,
	})
}

func assertHistogramBounds(t *testing.T, collected metricdata.ResourceMetrics, name string, want []float64) {
	t.Helper()

	for _, scope := range collected.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != name {
				continue
			}

			data, ok := metric.Data.(metricdata.Histogram[float64])
			if !ok || len(data.DataPoints) != 1 {
				continue
			}

			if !reflect.DeepEqual(data.DataPoints[0].Bounds, want) {
				t.Fatalf("metric %q bounds = %v, want %v", name, data.DataPoints[0].Bounds, want)
			}

			return
		}
	}

	t.Fatalf("histogram metric %q not found", name)
}

func TestMetricsWithoutRoute(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	reporter, err := metrics.New(provider.Meter("test"))

	if err != nil {
		t.Fatal(err)
	}

	reporter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://identity.example/missing", nil))

	var collected metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &collected); err != nil {
		t.Fatal(err)
	}

	if len(collected.ScopeMetrics) != 0 {
		t.Fatalf("collected metrics without a resolved route: %#v", collected.ScopeMetrics)
	}
}

func assertMetricAttributes(t *testing.T, collected metricdata.ResourceMetrics, name string, want map[string]string) {
	t.Helper()

	for _, scope := range collected.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != name {
				continue
			}

			switch data := metric.Data.(type) {
			case metricdata.Sum[int64]:
				if len(data.DataPoints) == 1 && attributesMatch(data.DataPoints[0].Attributes, want) {
					return
				}
			case metricdata.Histogram[float64]:
				if len(data.DataPoints) == 1 && attributesMatch(data.DataPoints[0].Attributes, want) {
					return
				}
			}
		}
	}

	t.Fatalf("metric %q with attributes %v not found", name, want)
}

func attributesMatch(attributes attribute.Set, want map[string]string) bool {
	if attributes.Len() != len(want) {
		return false
	}

	for key, value := range want {
		attribute, ok := attributes.Value(attribute.Key(key))
		if !ok || attribute.AsString() != value {
			return false
		}
	}

	return true
}
