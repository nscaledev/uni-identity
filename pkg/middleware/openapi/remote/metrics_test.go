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

package authorizer_test

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	authorizer "github.com/unikorn-cloud/identity/pkg/middleware/openapi/remote"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// These tests pin Task 9's CALLER-side decision telemetry: RemoteEngine's own
// observation of the CheckMany round trip it drives through AllowCoarse/
// AllowCoarseMany (network latency and the consumer-observed outcome), as
// distinct from identity's server-side A10 records (pkg/rbac/decision_log.go
// and its TestDecisionMetrics/TestDecisionLog* tests), which this suite
// deliberately mirrors the shape of.

// remoteDecisionMessage is duplicated from metrics.go deliberately, exactly
// as pkg/rbac/decision_log_test.go duplicates decisionMessage from
// decision_log.go: the record stream is an observability contract, so a
// rename must break tests.
const remoteDecisionMessage = "remote authorization decision"

// logCapture, logRecord and logAttrs below are duplicated from
// pkg/rbac/decision_log_test.go's own unexported helper of the same shape
// (it cannot be imported across packages): a minimal logr.LogSink recording
// every emission, seeded into the context exactly where log.FromContext
// looks for the request-scoped logger.
type logCapture struct {
	mu      sync.Mutex
	records []logRecord
}

type logRecord struct {
	level   int
	message string
	fields  []any
}

func (c *logCapture) Init(logr.RuntimeInfo) {}

// Enabled returns true for every level: V(1) allow records must be captured
// even though production drops them at default verbosity.
func (c *logCapture) Enabled(int) bool {
	return true
}

func (c *logCapture) Info(level int, message string, fields ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.records = append(c.records, logRecord{level: level, message: message, fields: fields})
}

func (c *logCapture) Error(_ error, message string, fields ...any) {
	c.Info(0, message, fields...)
}

func (c *logCapture) WithValues(...any) logr.LogSink {
	return c
}

func (c *logCapture) WithName(string) logr.LogSink {
	return c
}

// into seeds a logger backed by the capture into the context, exactly where
// log.FromContext looks for the request-scoped logger.
func (c *logCapture) into(ctx context.Context) context.Context {
	return log.IntoContext(ctx, logr.New(c))
}

// messages returns every captured record carrying remoteDecisionMessage —
// this file's only log stream (unlike pkg/rbac's decision+shadow pair), so
// unlike its rbac counterpart this filters by a fixed message, not a
// parameter.
func (c *logCapture) messages() []logRecord {
	c.mu.Lock()
	defer c.mu.Unlock()

	var out []logRecord

	for _, record := range c.records {
		if record.message == remoteDecisionMessage {
			out = append(out, record)
		}
	}

	return out
}

// logAttrs flattens a record's key/value fields for assertion.
func logAttrs(t *testing.T, record logRecord) map[string]string {
	t.Helper()

	require.Zero(t, len(record.fields)%2, "a record must carry complete key/value pairs")

	out := map[string]string{}

	for i := 0; i+1 < len(record.fields); i += 2 {
		key, ok := record.fields[i].(string)
		require.True(t, ok, "field keys must be strings")

		out[key] = fmt.Sprintf("%v", record.fields[i+1])
	}

	return out
}

// installManualReader is duplicated from pkg/rbac/decision_log_test.go's own
// helper of the same name (unexported): it swaps the process-global OTel
// meter provider for one backed by a manual reader, parking a noop provider
// on cleanup.  Callers must be serial (//nolint:paralleltest) and must
// construct their RemoteEngine AFTER calling this so its instruments bind to
// the reader.
func installManualReader(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	otel.SetMeterProvider(provider)

	t.Cleanup(func() {
		otel.SetMeterProvider(noop.NewMeterProvider())

		//nolint:usetesting // t.Context() is already canceled inside Cleanup and would fail the shutdown.
		require.NoError(t, provider.Shutdown(context.Background()))
	})

	return reader
}

// findMetric locates a metric by name across all instrumentation scopes.
func findMetric(rm *metricdata.ResourceMetrics, name string) (metricdata.Metrics, bool) {
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name == name {
				return m, true
			}
		}
	}

	return metricdata.Metrics{}, false
}

// outcomeValue returns the remote-decision counter value for one outcome
// attribute, or zero when that outcome has no data point.
func outcomeValue(t *testing.T, sum metricdata.Sum[int64], outcome string) int64 {
	t.Helper()

	for _, dp := range sum.DataPoints {
		v, _ := dp.Attributes.Value(attribute.Key("outcome"))

		if v.AsString() == outcome {
			return dp.Value
		}
	}

	return 0
}

// TestRemoteMetricsOutcomes pins the three-way outcome vocabulary and proves
// AllowCoarse's delegation to AllowCoarseMany (see engine.go) does not
// double-record: three single-check AllowCoarse calls, one per outcome, must
// yield exactly three counter increments and three latency samples — never
// six.
//
//nolint:paralleltest // installManualReader swaps the process-global OTel meter provider.
func TestRemoteMetricsOutcomes(t *testing.T) {
	reader := installManualReader(t)

	resource := rbac.Resource{Kind: "identity:groups", OrganizationID: "org-1"}

	// Each scenario constructs its own RemoteEngine (and thus its own
	// instrument handles) AFTER the reader is installed, exactly as
	// pkg/rbac's TestDecisionMetrics constructs a fresh *RBAC per test, so
	// every instrument funnels into the one installed reader.
	allowEngine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}}}))
	require.NoError(t, allowEngine.AllowCoarse(checkAuthContext(t, "", false), resource, identityapi.Read))

	denyEngine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: false}}}))
	require.ErrorIs(t, denyEngine.AllowCoarse(checkAuthContext(t, "", false), resource, identityapi.Read), rbac.ErrPolicyDenied)

	unavailableEngine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, &checkHandler{status: http.StatusInternalServerError}))
	require.ErrorIs(t, unavailableEngine.AllowCoarse(checkAuthContext(t, "", false), resource, identityapi.Read), rbac.ErrDecisionUnavailable)

	var rm metricdata.ResourceMetrics

	require.NoError(t, reader.Collect(t.Context(), &rm))

	counter, found := findMetric(&rm, "unikorn_identity_authz_remote_decision_total")
	require.True(t, found, "the remote decision counter must exist")
	require.Equal(t, "{decision}", counter.Unit)

	sum, ok := counter.Data.(metricdata.Sum[int64])
	require.True(t, ok, "the remote decision counter must be an Int64Counter")

	require.Equal(t, int64(1), outcomeValue(t, sum, "allow"))
	require.Equal(t, int64(1), outcomeValue(t, sum, "deny"))
	require.Equal(t, int64(1), outcomeValue(t, sum, "unavailable"))

	// The attribute vocabulary is CLOSED to outcome ONLY: three data points,
	// nothing keyed by subject/endpoint (which would be a cardinality
	// explosion).
	require.Len(t, sum.DataPoints, 3)

	histogram, found := findMetric(&rm, "unikorn_identity_authz_remote_decision_latency")
	require.True(t, found, "the remote decision latency histogram must exist")
	require.Equal(t, "s", histogram.Unit)

	data, ok := histogram.Data.(metricdata.Histogram[float64])
	require.True(t, ok, "the latency instrument must be a Float64Histogram")
	require.Len(t, data.DataPoints, 1, "the histogram carries no attributes")

	require.Equal(t, uint64(3), data.DataPoints[0].Count,
		"one latency sample per CALL (allow + deny + unavailable) — AllowCoarse's delegation to AllowCoarseMany must not double-record")
	require.Equal(t, []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5}, data.DataPoints[0].Bounds,
		"explicit buckets sized for a cross-service network hop, larger than A10's localhost-gRPC pdp_latency")

	t.Logf("metrics sample: outcome data points=%d, latency count=%d sum=%.6fs", len(sum.DataPoints), data.DataPoints[0].Count, data.DataPoints[0].Sum)
}

// TestRemoteMetricsBatch pins the batch primitive (AllowCoarseMany): N
// per-check counter increments but exactly ONE latency observation for the
// whole round trip, and one log record per (resource, action) entry in
// request order — mirroring pkg/rbac's TestDecisionLogBatchPerEntry batch
// shape.
//
//nolint:paralleltest // installManualReader swaps the process-global OTel meter provider.
func TestRemoteMetricsBatch(t *testing.T) {
	reader := installManualReader(t)

	h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}, {Allowed: false}, {Allowed: true}}}
	engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

	capture := &logCapture{}
	ctx := capture.into(checkAuthContext(t, "", false))

	allowed, err := engine.AllowCoarseMany(ctx, []rbac.Resource{
		{Kind: "identity:groups", OrganizationID: "org-1"},
		{Kind: "identity:roles", OrganizationID: "org-1"},
		{Kind: "identity:projects", OrganizationID: "org-1"},
	}, identityapi.Read)
	require.NoError(t, err)
	require.Equal(t, []bool{true, false, true}, allowed)

	records := capture.messages()
	require.Len(t, records, 3, "one record per (resource, action) entry, in request order")

	require.Equal(t, "identity:groups", logAttrs(t, records[0])["endpoint"])
	require.Equal(t, "allow", logAttrs(t, records[0])["decision"])
	require.Equal(t, 1, records[0].level, "allows are quiet by default: V(1)")

	require.Equal(t, "identity:roles", logAttrs(t, records[1])["endpoint"])
	require.Equal(t, "deny", logAttrs(t, records[1])["decision"])
	require.Zero(t, records[1].level, "denies are unconditional: Info")

	require.Equal(t, "identity:projects", logAttrs(t, records[2])["endpoint"])
	require.Equal(t, "allow", logAttrs(t, records[2])["decision"])

	var rm metricdata.ResourceMetrics

	require.NoError(t, reader.Collect(t.Context(), &rm))

	counter, found := findMetric(&rm, "unikorn_identity_authz_remote_decision_total")
	require.True(t, found)

	sum, ok := counter.Data.(metricdata.Sum[int64])
	require.True(t, ok)

	require.Equal(t, int64(2), outcomeValue(t, sum, "allow"), "two of the three checks in the batch allowed")
	require.Equal(t, int64(1), outcomeValue(t, sum, "deny"), "one of the three checks in the batch denied")

	histogram, found := findMetric(&rm, "unikorn_identity_authz_remote_decision_latency")
	require.True(t, found)

	data, ok := histogram.Data.(metricdata.Histogram[float64])
	require.True(t, ok)
	require.Len(t, data.DataPoints, 1)
	require.Equal(t, uint64(1), data.DataPoints[0].Count,
		"ONE latency observation for the whole 3-check batch round trip, not three")
}

// TestRemoteMetricsDenyLogsAtInfo pins the deny log line: unconditional Info,
// credential-free fields, and the acting subject read cleanly from context.
func TestRemoteMetricsDenyLogsAtInfo(t *testing.T) {
	t.Parallel()

	h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: false}}}
	engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

	capture := &logCapture{}
	ctx := capture.into(checkAuthContext(t, "", false))

	err := engine.AllowCoarse(ctx, rbac.Resource{Kind: "identity:groups", OrganizationID: "org-1"}, identityapi.Read)
	require.ErrorIs(t, err, rbac.ErrPolicyDenied)

	records := capture.messages()
	require.Len(t, records, 1)
	require.Zero(t, records[0].level, "denies must be emitted unconditionally at Info")

	attrs := logAttrs(t, records[0])
	require.Equal(t, "deny", attrs["decision"])
	require.Equal(t, "remote", attrs["source"], "disambiguates this caller-side record from identity's own A10 stream")
	require.Equal(t, "identity:groups", attrs["endpoint"])
	require.Equal(t, "read", attrs["operation"])
	require.Equal(t, "org-1", attrs["organization_id"])
	require.Empty(t, attrs["project_id"])
	require.Equal(t, "actor@example.com", attrs["subject"], "the acting subject is read cleanly from context, never a token or claim")
	require.NotEmpty(t, attrs["latency"])

	t.Logf("sample deny record: level=%d fields=%v", records[0].level, attrs)
}

// TestRemoteMetricsUnavailableLogsAtInfo pins the unavailable outcome's log
// level: like a deny, it is unconditional Info, never quieted to V(1).
func TestRemoteMetricsUnavailableLogsAtInfo(t *testing.T) {
	t.Parallel()

	h := &checkHandler{status: http.StatusInternalServerError}
	engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

	capture := &logCapture{}
	ctx := capture.into(checkAuthContext(t, "", false))

	err := engine.AllowCoarse(ctx, rbac.Resource{Kind: "identity:groups", OrganizationID: "org-1"}, identityapi.Read)
	require.ErrorIs(t, err, rbac.ErrDecisionUnavailable)

	records := capture.messages()
	require.Len(t, records, 1)
	require.Zero(t, records[0].level, "an unavailable outcome must be emitted unconditionally at Info")
	require.Equal(t, "unavailable", logAttrs(t, records[0])["decision"])
}

// TestRemoteMetricsAllowLogsAtV1 pins the allow log level: quiet by default
// (V(1)), never part of the unconditional stream.
func TestRemoteMetricsAllowLogsAtV1(t *testing.T) {
	t.Parallel()

	h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}}}
	engine := authorizer.NewRemoteEngine(newCheckAuthorizer(t, h))

	capture := &logCapture{}
	ctx := capture.into(checkAuthContext(t, "", false))

	require.NoError(t, engine.AllowCoarse(ctx, rbac.Resource{Kind: "identity:groups", OrganizationID: "org-1"}, identityapi.Read))

	records := capture.messages()
	require.Len(t, records, 1)
	require.Equal(t, 1, records[0].level, "allows must be quiet by default: V(1), not unconditional Info")
	require.Equal(t, "allow", logAttrs(t, records[0])["decision"])
}
