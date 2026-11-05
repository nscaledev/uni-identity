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

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	openapimiddleware "github.com/unikorn-cloud/identity/pkg/middleware/openapi"
)

const authenticationsName = "unikorn_identity_system_account_authentications"

// Authentications counts the system account authentications that use a client
// certificate.
type Authentications struct {
	counter metric.Int64Counter
}

// NewAuthentications creates the authentication counter.
func NewAuthentications(meter metric.Meter) (*Authentications, error) {
	counter, err := meter.Int64Counter(authenticationsName,
		metric.WithDescription("System account authentications with a client certificate, by listener and result."),
		metric.WithUnit("{authentication}"))
	if err != nil {
		return nil, err
	}

	return &Authentications{counter: counter}, nil
}

// Record counts one event.  Each field that has a value becomes an attribute, so
// the validator decides which labels an event carries.
func (a *Authentications) Record(ctx context.Context, event openapimiddleware.AuthenticationEvent) {
	fields := []attribute.KeyValue{
		attribute.String("listener", event.Listener),
		attribute.String("result", event.Result),
		attribute.String("reason", event.Reason),
		attribute.String("peer", event.Peer),
		attribute.String("subject", event.Subject),
	}

	attributes := make([]attribute.KeyValue, 0, len(fields))

	for _, field := range fields {
		if field.Value.AsString() != "" {
			attributes = append(attributes, field)
		}
	}

	a.counter.Add(ctx, 1, metric.WithAttributes(attributes...))
}
