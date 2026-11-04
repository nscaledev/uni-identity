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
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	openapimiddleware "github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/server/metrics"
)

// TestAuthenticationsLabelsOnlySetFields checks that an empty field gives no
// label, so a refusal never carries a subject and a legacy event never carries
// a peer.  The values of those labels must stay bounded.
func TestAuthenticationsLabelsOnlySetFields(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		event openapimiddleware.AuthenticationEvent
		want  attribute.Set
	}{
		{
			name: "refusal on the legacy listener",
			event: openapimiddleware.AuthenticationEvent{
				Listener: "legacy",
				Result:   "refused",
				Reason:   "not_registered",
			},
			want: attribute.NewSet(
				attribute.String("listener", "legacy"),
				attribute.String("result", "refused"),
				attribute.String("reason", "not_registered"),
			),
		},
		{
			name: "refusal on the spiffe listener",
			event: openapimiddleware.AuthenticationEvent{
				Listener: "spiffe",
				Result:   "refused",
				Reason:   "relay_not_permitted",
				Peer:     "spiffe://example.org/region",
			},
			want: attribute.NewSet(
				attribute.String("listener", "spiffe"),
				attribute.String("result", "refused"),
				attribute.String("reason", "relay_not_permitted"),
				attribute.String("peer", "spiffe://example.org/region"),
			),
		},
		{
			name: "success on the spiffe listener",
			event: openapimiddleware.AuthenticationEvent{
				Listener: "spiffe",
				Result:   "ok",
				Peer:     "spiffe://example.org/region",
				Subject:  "unikorn-compute",
			},
			want: attribute.NewSet(
				attribute.String("listener", "spiffe"),
				attribute.String("result", "ok"),
				attribute.String("peer", "spiffe://example.org/region"),
				attribute.String("subject", "unikorn-compute"),
			),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reader := sdkmetric.NewManualReader()

			counter, err := metrics.NewAuthentications(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test"))
			require.NoError(t, err)

			counter.Record(t.Context(), tc.event)

			points := authenticationPoints(t, reader)
			require.Len(t, points, 1)
			require.Equal(t, int64(1), points[0].Value)
			require.True(t, tc.want.Equals(&points[0].Attributes), "got labels %v", points[0].Attributes.ToSlice())
		})
	}
}

func authenticationPoints(t *testing.T, reader *sdkmetric.ManualReader) []metricdata.DataPoint[int64] {
	t.Helper()

	var collected metricdata.ResourceMetrics

	require.NoError(t, reader.Collect(t.Context(), &collected))

	for _, scope := range collected.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != "unikorn_identity_system_account_authentications" {
				continue
			}

			sum, ok := metric.Data.(metricdata.Sum[int64])
			require.True(t, ok, "the authentication metric is a counter")

			return sum.DataPoints
		}
	}

	require.Fail(t, "the authentication metric was not recorded")

	return nil
}
