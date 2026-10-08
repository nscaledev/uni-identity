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
	"context"
	"net"
	"net/http"
	"sync/atomic"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/unikorn-cloud/core/pkg/util"
)

// Build info keeps the per-service prefix, following the Prometheus
// convention for build_info families. Readiness uses a platform-generic name
// so one query can aggregate it across services; the emitting service is
// identified by the OTLP resource (service.name), not the metric name.
const (
	buildInfoName = "unikorn_identity_server_build_info"
	readyName     = "unikorn_server_ready"
)

// Reporter publishes server identity and listener-ready state.
type Reporter struct {
	ready        atomic.Int64
	attributes   []attribute.KeyValue
	registration metric.Registration
}

// New creates a reporter for the API server process.
func New(meter metric.Meter, service util.ServiceDescriptor) (*Reporter, error) {
	buildInfo, err := meter.Int64ObservableGauge(buildInfoName)
	if err != nil {
		return nil, err
	}

	ready, err := meter.Int64ObservableGauge(readyName)
	if err != nil {
		return nil, err
	}

	reporter := &Reporter{
		attributes: []attribute.KeyValue{
			attribute.String("version", service.Version),
			attribute.String("revision", service.Revision),
		},
	}

	registration, err := meter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		options := metric.WithAttributes(reporter.attributes...)
		observer.ObserveInt64(buildInfo, 1, options)
		observer.ObserveInt64(ready, reporter.ready.Load(), options)

		return nil
	}, buildInfo, ready)
	if err != nil {
		return nil, err
	}

	reporter.registration = registration

	return reporter, nil
}

// Serve reports readiness while the server owns a bound listener.
func (r *Reporter) Serve(server *http.Server, listener net.Listener) error {
	r.ready.Store(1)
	defer r.ready.Store(0)

	return server.Serve(listener)
}

// Close removes the metric callback.
func (r *Reporter) Close() error {
	return r.registration.Unregister()
}
