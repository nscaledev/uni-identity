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

// Package telemetry configures Identity metric publication.
package telemetry

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	prometheusexporter "go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// NewMeterProvider exposes OpenTelemetry instruments through registerer.
func NewMeterProvider(registerer prometheus.Registerer) (*sdkmetric.MeterProvider, error) {
	exporter, err := prometheusexporter.New(prometheusexporter.WithRegisterer(registerer))
	if err != nil {
		return nil, fmt.Errorf("create Prometheus exporter: %w", err)
	}

	return sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter)), nil
}

// Configure replaces the OTLP metric reader with a Prometheus reader.
func Configure(ctx context.Context, registerer prometheus.Registerer) error {
	if provider, ok := otel.GetMeterProvider().(*sdkmetric.MeterProvider); ok {
		if err := provider.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutdown existing metric provider: %w", err)
		}
	}

	provider, err := NewMeterProvider(registerer)
	if err != nil {
		return err
	}

	otel.SetMeterProvider(provider)

	return nil
}
