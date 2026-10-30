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

package metrics

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/felixge/httpsnoop"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
)

// The names follow the OpenTelemetry HTTP server semantic conventions in
// their Prometheus-stored form, so every service emitting them lands on the
// same stored names and dashboards can aggregate across services. The emitting
// service is identified by the OTLP resource (service.name), not the metric
// name.
const (
	requestDurationName = "http_server_request_duration_seconds"
	activeRequestsName  = "http_server_active_requests"
)

func requestDurationBounds() []float64 {
	return []float64{
		0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
	}
}

// Metrics records the bounded API request metrics required by the platform.
// The duration histogram's count serves as the request counter.
type Metrics struct {
	duration metric.Float64Histogram
	active   metric.Int64UpDownCounter
}

// New creates the API request metric instruments.
func New(meter metric.Meter) (*Metrics, error) {
	duration, err := meter.Float64Histogram(
		requestDurationName,
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(requestDurationBounds()...),
	)
	if err != nil {
		return nil, fmt.Errorf("create request duration histogram: %w", err)
	}

	active, err := meter.Int64UpDownCounter(activeRequestsName, metric.WithUnit("{request}"))
	if err != nil {
		return nil, fmt.Errorf("create active request counter: %w", err)
	}

	return &Metrics{
		duration: duration,
		active:   active,
	}, nil
}

func routeAttributes(r *http.Request) ([]attribute.KeyValue, error) {
	route, err := routeresolver.FromContext(r.Context())
	if err != nil {
		return nil, err
	}

	return []attribute.KeyValue{
		attribute.String("route", route.Route.Path),
		attribute.String("method", r.Method),
	}, nil
}

func statusClass(status int) string {
	return strconv.Itoa(status/100) + "xx"
}

// Middleware records requests after route resolution so path parameters do not
// become metric labels.
func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attributes, err := routeAttributes(r)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		options := metric.WithAttributes(attributes...)
		m.active.Add(r.Context(), 1, options)
		defer m.active.Add(r.Context(), -1, options)

		started := time.Now()
		response := httpsnoop.CaptureMetrics(next, w, r)
		attributes = append(attributes,
			attribute.String("status_class", statusClass(response.Code)),
			attribute.String("code", strconv.Itoa(response.Code)),
		)
		options = metric.WithAttributes(attributes...)
		m.duration.Record(r.Context(), time.Since(started).Seconds(), options)
	})
}
