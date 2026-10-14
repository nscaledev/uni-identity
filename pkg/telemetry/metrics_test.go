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

package telemetry_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/telemetry"
)

func TestNewMeterProvider(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	provider, err := telemetry.NewMeterProvider(registry)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(t.Context())) })

	counter, err := provider.Meter("test").Int64Counter("identity_test_requests")
	require.NoError(t, err)
	counter.Add(t.Context(), 1)

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), "identity_test_requests_total")
	require.NotContains(t, response.Body.String(), "identity_test_requests 1")
}
