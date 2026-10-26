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

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/unikorn-cloud/core/pkg/openapi/helpers"
	"github.com/unikorn-cloud/core/pkg/server/middleware/cors"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

func TestNewRouterRecordsResolvedRoute(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	schema, err := helpers.NewSchema(identityapi.GetSwagger)
	require.NoError(t, err)
	router, err := (&Server{CORSOptions: cors.Options{AllowedOrigins: []string{"*"}}}).newRouterWithMeter(schema, provider.Meter("test"))
	require.NoError(t, err)
	router.Get("/api/v1/organizations", func(http.ResponseWriter, *http.Request) {})

	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://identity/api/v1/organizations", nil))

	var collected metricdata.ResourceMetrics
	err = reader.Collect(t.Context(), &collected)
	require.NoError(t, err)

	for _, scope := range collected.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != "http_server_request_duration_seconds" {
				continue
			}

			histogram, ok := metric.Data.(metricdata.Histogram[float64])
			require.True(t, ok)

			for _, point := range histogram.DataPoints {
				if point.Count != 1 {
					continue
				}

				route, ok := point.Attributes.Value(attribute.Key("route"))
				require.True(t, ok)
				require.Equal(t, "/api/v1/organizations", route.AsString())

				return
			}
		}
	}

	require.Fail(t, "no recorded request metric")
}
