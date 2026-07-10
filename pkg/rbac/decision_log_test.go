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

package rbac_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// These tests pin the A10 decision observability contract: every SERVED
// Cerbos-path decision emits exactly one structured record per (resource,
// action) through the request-scoped logger — denies unconditionally at Info,
// allows at V(1) — and increments the decision counter with a CLOSED
// attribute vocabulary, while shadow evaluations emit no decision records and
// no counter increments (shadow.go owns that path's taxonomy) but do share
// the PDP latency histogram (transport health is path-independent).

// decisionMessage is duplicated from decision_log.go deliberately: the record
// stream is the A10 observability contract, so a rename must break tests.
const decisionMessage = "authorization decision"

// decisionFieldCount is the CLOSED decision-record field set size: the
// guarantee that no token, passport or claim material can ride along.
const decisionFieldCount = 12

// impersonatedDecisionFieldCount is the closed field set for impersonated
// decisions (A14): exactly two more fields — the impersonated subject and its
// principal type — alongside the acting service's subject, preserving the
// design's (impersonated-sub, actor) pair in every record.
const impersonatedDecisionFieldCount = decisionFieldCount + 2

// logCapture is a minimal logr.LogSink recording every record emitted through
// a logger backed by it.  It is seeded per-test into the CONTEXT
// (log.IntoContext) — the exact seam the core OTel middleware uses for the
// per-request trace-correlated logger — so captures are test-scoped and safe
// for parallel tests.  The decision log and the shadow comparator never use
// WithName/WithValues, so both are identity.
type logCapture struct {
	mu      sync.Mutex
	records []logRecord
}

// logRecord is one captured emission: the logr V level (0 for plain Info),
// the message constant, and the flat key/value field list.
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

// messages returns the captured records carrying the given message, filtering
// out unrelated records other code may emit through the same logger.
func (c *logCapture) messages(message string) []logRecord {
	c.mu.Lock()
	defer c.mu.Unlock()

	var out []logRecord

	for _, record := range c.records {
		if record.message == message {
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

func TestDecisionLogAllow(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// The stamped policy metadata proves the A15 policy-correlate seam is
	// plumbed through to the record (a real PDP echoes empty values today).
	fx.rbac.WithCerbos(&stampedPDP{
		next:          &fakePDP{response: pdpResponse(pdpResult("identity:groups", "*", map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}))},
		policyVersion: "default",
		policyScope:   "acme",
	})

	capture := &logCapture{}
	ctx := capture.into(aliceContext(t))

	require.NoError(t, fx.rbac.Check(ctx, rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Read))

	records := capture.messages(decisionMessage)
	require.Len(t, records, 1, "exactly one record per served (resource, action)")

	// Allows are V(1): visible at raised verbosity, quiet by default —
	// denies are the unconditional signal.
	require.Equal(t, 1, records[0].level, "allows must be emitted at V(1)")

	// The full record, and NOTHING but the record: the closed field set is
	// the guarantee no token or credential material can ride along.
	attrs := logAttrs(t, records[0])
	require.Len(t, attrs, decisionFieldCount)
	require.Equal(t, parityAliceSubject, attrs["subject"])
	require.Equal(t, "user", attrs["actor_type"])
	require.Equal(t, "identity:groups", attrs["endpoint"])
	require.Empty(t, attrs["resource_id"], "a coarse check names no resource instance")
	require.Equal(t, "read", attrs["operation"])
	require.Equal(t, parityOrgA, attrs["organization_id"])
	require.Empty(t, attrs["project_id"])
	require.Equal(t, "allow", attrs["decision"])
	require.Equal(t, "policy", attrs["reason"])
	require.Equal(t, "default", attrs["policy_version"])
	require.Equal(t, "acme", attrs["policy_scope"])
	require.NotEmpty(t, attrs["latency"])

	t.Logf("sample allow record: level=%d message=%q fields=%v", records[0].level, records[0].message, attrs)
}

func TestDecisionLogPolicyDeny(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)
	fx.rbac.WithCerbos(&fakePDP{response: pdpResponse(pdpResult("identity:groups", "*", map[string]effectv1.Effect{"delete": effectv1.Effect_EFFECT_DENY}))})

	capture := &logCapture{}
	ctx := capture.into(aliceContext(t))

	err := fx.rbac.Check(ctx, rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Delete)
	require.ErrorIs(t, err, rbac.ErrPolicyDenied)

	records := capture.messages(decisionMessage)
	require.Len(t, records, 1)

	// Denies are unconditional: plain Info, never V(1).
	require.Zero(t, records[0].level, "denies must be emitted unconditionally")

	attrs := logAttrs(t, records[0])
	require.Len(t, attrs, decisionFieldCount)
	require.Equal(t, "deny", attrs["decision"])
	require.Equal(t, "policy", attrs["reason"], "an explicit policy deny is a verdict, not a failure class")
	require.Equal(t, "delete", attrs["operation"])
	require.Empty(t, attrs["policy_version"], "an unstamped PDP response carries no policy correlate")

	t.Logf("sample policy-deny record: level=%d message=%q fields=%v", records[0].level, records[0].message, attrs)
}

func TestDecisionLogFailureClasses(t *testing.T) {
	t.Parallel()

	// Every fail-closed sentinel maps to its own reason class, mirroring the
	// check.go taxonomy via errors.Is — operators must be able to tell an
	// outage from a resolver failure from an impersonated refusal by grep.
	t.Run("Unavailable", func(t *testing.T) {
		t.Parallel()

		fx := newParityFixture(t)
		fx.rbac.WithCerbos(&fakePDP{err: errFakeTransport})

		capture := &logCapture{}
		ctx := capture.into(aliceContext(t))

		err := fx.rbac.Check(ctx, rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Read)
		require.ErrorIs(t, err, rbac.ErrDecisionUnavailable)

		records := capture.messages(decisionMessage)
		require.Len(t, records, 1)
		require.Zero(t, records[0].level)

		attrs := logAttrs(t, records[0])
		require.Len(t, attrs, decisionFieldCount)
		require.Equal(t, "deny", attrs["decision"])
		require.Equal(t, "unavailable", attrs["reason"])
		require.Empty(t, attrs["policy_version"], "no verdict was obtained, so no policy correlate may be claimed")

		t.Logf("sample unavailable record: level=%d message=%q fields=%v", records[0].level, records[0].message, attrs)
	})

	t.Run("NoPDPConfigured", func(t *testing.T) {
		t.Parallel()

		fx := newParityFixture(t)

		capture := &logCapture{}
		ctx := capture.into(aliceContext(t))

		err := fx.rbac.Check(ctx, rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Read)
		require.ErrorIs(t, err, rbac.ErrDecisionUnavailable)

		records := capture.messages(decisionMessage)
		require.Len(t, records, 1)
		require.Equal(t, "unavailable", logAttrs(t, records[0])["reason"])
	})

	t.Run("Resolution", func(t *testing.T) {
		t.Parallel()

		fx := newParityFixture(t)
		fx.rbac.WithCerbos(&fakePDP{})

		// No authorization info in the context: the deny is a resolution
		// failure and the subject fields are empty, never invented.
		capture := &logCapture{}
		ctx := capture.into(t.Context())

		err := fx.rbac.Check(ctx, rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Read)
		require.ErrorIs(t, err, rbac.ErrResolutionFailed)

		records := capture.messages(decisionMessage)
		require.Len(t, records, 1)

		attrs := logAttrs(t, records[0])
		require.Len(t, attrs, decisionFieldCount)
		require.Equal(t, "deny", attrs["decision"])
		require.Equal(t, "resolution", attrs["reason"])
		require.Empty(t, attrs["subject"])
		require.Empty(t, attrs["actor_type"])
	})

	t.Run("Impersonation", func(t *testing.T) {
		t.Parallel()

		fx := newParityFixture(t)
		pdp := &fakePDP{}
		fx.rbac.WithCerbos(pdp)

		// The NARROWED (A14) meaning of the impersonation class: only the
		// type-gate refusal — an impersonated principal type that cannot be
		// impersonated (here System) — lands here; valid User/Service
		// impersonations are served by the dual check and classify as
		// policy/failure classes like any other decision.
		capture := &logCapture{}
		ctx := principal.NewContext(capture.into(aliceContext(t)), &principal.Principal{Actor: "impersonated@example.com", Type: openapi.System})
		ctx = principal.NewImpersonateContext(ctx)

		err := fx.rbac.Check(ctx, rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Read)
		require.ErrorIs(t, err, rbac.ErrImpersonationNotSupported)
		require.Zero(t, pdp.calls)

		records := capture.messages(decisionMessage)
		require.Len(t, records, 1, "a pre-PDP refusal is still a served decision and must be recorded")

		attrs := logAttrs(t, records[0])
		require.Len(t, attrs, impersonatedDecisionFieldCount)
		require.Equal(t, "deny", attrs["decision"])
		require.Equal(t, "impersonation", attrs["reason"])
		require.Equal(t, "impersonated@example.com", attrs["impersonated_subject"])
		require.Equal(t, "system", attrs["impersonated_type"])
	})
}

func TestDecisionLogImpersonatedDualCheck(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)
	fx.rbac.WithCerbos(&fakePDP{response: pdpResponse(pdpResult("identity:groups", "*", map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}))})

	capture := &logCapture{}
	ctx := capture.into(impersonatedContext(t, &principal.Principal{Actor: parityAliceSubject, Type: openapi.User, OrganizationIDs: []string{parityOrgA}}))

	require.NoError(t, fx.rbac.Check(ctx, rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Read))

	// ONE record per decision — never one per dual-check side — with the
	// AND-ed outcome and the (impersonated-sub, actor) pair the design's
	// cache-key clause requires every impersonated record to carry.
	records := capture.messages(decisionMessage)
	require.Len(t, records, 1, "an impersonated decision is one record, not one per PDP call")

	attrs := logAttrs(t, records[0])
	require.Len(t, attrs, impersonatedDecisionFieldCount)
	require.Equal(t, paritySystemCN, attrs["subject"], "the subject stays the acting service, matching the legacy cache-key convention")
	require.Equal(t, "system", attrs["actor_type"])
	require.Equal(t, parityAliceSubject, attrs["impersonated_subject"])
	require.Equal(t, "user", attrs["impersonated_type"])
	require.Equal(t, "allow", attrs["decision"])
	require.Equal(t, "policy", attrs["reason"])

	t.Logf("sample impersonated allow record: fields=%v", attrs)
}

func TestDecisionLogBatchPerEntry(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)
	fx.rbac.WithCerbos(&fakePDP{response: pdpResponse(
		pdpResult("identity:groups", "*", map[string]effectv1.Effect{"create": effectv1.Effect_EFFECT_ALLOW}),
		pdpResult("identity:groups", "*", map[string]effectv1.Effect{"delete": effectv1.Effect_EFFECT_DENY}),
	)})

	capture := &logCapture{}
	ctx := capture.into(aliceContext(t))

	allowed, err := fx.rbac.CheckMany(ctx, []rbac.CheckRequest{
		{Resource: rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, Action: openapi.Create},
		{Resource: rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, Action: openapi.Delete},
	})
	require.NoError(t, err)
	require.Equal(t, []bool{true, false}, allowed)

	// One record per (resource, action) entry, in request order — the flat,
	// greppable batch shape.
	records := capture.messages(decisionMessage)
	require.Len(t, records, 2)

	first := logAttrs(t, records[0])
	require.Len(t, first, decisionFieldCount)
	require.Equal(t, "create", first["operation"])
	require.Equal(t, "allow", first["decision"])
	require.Equal(t, 1, records[0].level)

	second := logAttrs(t, records[1])
	require.Len(t, second, decisionFieldCount)
	require.Equal(t, "delete", second["operation"])
	require.Equal(t, "deny", second["decision"])
	require.Zero(t, records[1].level)
}

func TestDecisionLogShadowEvaluationsExcluded(t *testing.T) {
	t.Parallel()

	// A shadow evaluation rides the same CheckMany funnel through the shallow
	// engine copy, so it must be positively discriminated: the PDP is
	// consulted, shadow's OWN records are emitted, and ZERO decision records
	// appear — shadow.go owns that path's divergence/failure taxonomy.
	pdp := &capturePDP{allow: true}
	engine := newDispatchEngine(t, rbac.EngineShadow, pdp)

	capture := &logCapture{}
	ctx := rbac.NewEngineContext(rbac.NewContext(capture.into(aliceContext(t)), globalACL("candy", openapi.Read)), engine)

	// The PDP allows what the ACL does not grant: a divergence, the noisiest
	// shadow outcome, with the legacy deny still served.
	err := rbac.AllowGlobalScope(ctx, "candy", openapi.Delete)
	require.True(t, coreerrors.IsForbidden(err))
	require.Equal(t, 1, pdp.calls, "the shadow evaluation must still consult the PDP")

	require.Empty(t, capture.messages(decisionMessage), "shadow evaluations must emit zero decision records")
	require.Len(t, capture.messages(shadowDivergenceMessage), 1, "the divergence signal is shadow's own record, in the same sink")

	// An agreeing evaluation emits nothing at all on either taxonomy.
	require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))
	require.Equal(t, 2, pdp.calls)
	require.Empty(t, capture.messages(decisionMessage))
}

// installManualReader swaps the process-global OTel meter provider for one
// backed by a manual reader, parking a noop provider on cleanup (the global
// delegate refuses reinstallation, and later tests must bind inert
// instruments).  Callers must be serial (//nolint:paralleltest) and must
// construct their RBAC AFTER calling this so instruments bind to the reader.
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

// findMetric locates a metric by name across all instrumentation scopes (the
// scope name is argv-derived in tests, so it is not asserted).
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

// counterValue returns the decision-counter value for one (decision, class)
// attribute pair, or zero when that pair has no data point.
func counterValue(t *testing.T, sum metricdata.Sum[int64], decision, class string) int64 {
	t.Helper()

	for _, dp := range sum.DataPoints {
		d, _ := dp.Attributes.Value(attribute.Key("decision"))
		c, _ := dp.Attributes.Value(attribute.Key("class"))

		if d.AsString() == decision && c.AsString() == class {
			return dp.Value
		}
	}

	return 0
}

//nolint:paralleltest // installManualReader swaps the process-global OTel meter provider.
func TestDecisionMetrics(t *testing.T) {
	reader := installManualReader(t)

	fx := newParityFixture(t)
	pdp := &fakePDP{response: pdpResponse(pdpResult("identity:groups", "*", map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}))}
	fx.rbac.WithCerbos(pdp)

	resource := rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}

	// One decision per (decision, class) attribute pair, plus a dual-check
	// decision at the end.  The first three reach the PDP (an errored round
	// trip still measures transport latency); resolution and the
	// impersonation type-gate refusal fail before the PDP is asked; the
	// dual-check decision reaches it twice.
	require.NoError(t, fx.rbac.Check(aliceContext(t), resource, openapi.Read))

	pdp.response = pdpResponse(pdpResult("identity:groups", "*", map[string]effectv1.Effect{"delete": effectv1.Effect_EFFECT_DENY}))

	require.ErrorIs(t, fx.rbac.Check(aliceContext(t), resource, openapi.Delete), rbac.ErrPolicyDenied)

	pdp.err = errFakeTransport

	require.ErrorIs(t, fx.rbac.Check(aliceContext(t), resource, openapi.Read), rbac.ErrDecisionUnavailable)

	require.ErrorIs(t, fx.rbac.Check(t.Context(), resource, openapi.Read), rbac.ErrResolutionFailed)

	// The impersonation class is NARROWED (A14) to the type-gate refusal:
	// a System principal cannot be impersonated, refused pre-PDP.
	ictx := principal.NewContext(aliceContext(t), &principal.Principal{Actor: "impersonated@example.com", Type: openapi.System})
	ictx = principal.NewImpersonateContext(ictx)
	require.ErrorIs(t, fx.rbac.Check(ictx, resource, openapi.Read), rbac.ErrImpersonationNotSupported)

	// A VALID impersonation is served by the dual check: TWO PDP round trips
	// (both in the histogram) but ONE decision (one counter increment, with
	// the AND-ed outcome under the ordinary policy class).
	pdp.err = nil
	pdp.response = pdpResponse(pdpResult("identity:groups", "*", map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}))

	dctx := impersonatedContext(t, &principal.Principal{Actor: parityAliceSubject, Type: openapi.User, OrganizationIDs: []string{parityOrgA}})
	require.NoError(t, fx.rbac.Check(dctx, resource, openapi.Read))

	var rm metricdata.ResourceMetrics

	require.NoError(t, reader.Collect(t.Context(), &rm))

	counter, found := findMetric(&rm, "unikorn_identity_authz_decisions_total")
	require.True(t, found, "the decision counter must exist")

	sum, ok := counter.Data.(metricdata.Sum[int64])
	require.True(t, ok, "the decision counter must be an Int64Counter")

	require.Equal(t, int64(2), counterValue(t, sum, "allow", "policy"), "the dual-check decision counts ONCE, not once per side")
	require.Equal(t, int64(1), counterValue(t, sum, "deny", "policy"))
	require.Equal(t, int64(1), counterValue(t, sum, "deny", "unavailable"))
	require.Equal(t, int64(1), counterValue(t, sum, "deny", "resolution"))
	require.Equal(t, int64(1), counterValue(t, sum, "deny", "impersonation"))

	// The attribute vocabulary is CLOSED (decision × class): open-vocabulary
	// attributes like subject or endpoint would be a cardinality explosion.
	require.Len(t, sum.DataPoints, 5)

	histogram, found := findMetric(&rm, "unikorn_identity_authz_pdp_latency")
	require.True(t, found, "the PDP latency histogram must exist")
	require.Equal(t, "s", histogram.Unit)

	data, ok := histogram.Data.(metricdata.Histogram[float64])
	require.True(t, ok, "the latency instrument must be a Float64Histogram")
	require.Len(t, data.DataPoints, 1, "the histogram carries no attributes")

	point := data.DataPoints[0]
	require.Equal(t, uint64(5), point.Count, "one sample per PDP round trip — two for the dual check, none for pre-PDP denials")
	require.Equal(t, []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2}, point.Bounds,
		"explicit sub-second boundaries sized for localhost gRPC")

	t.Logf("metrics sample: decisions data points=%d, pdp latency count=%d sum=%.6fs", len(sum.DataPoints), point.Count, point.Sum)
}

//nolint:paralleltest // installManualReader swaps the process-global OTel meter provider.
func TestDecisionMetricsShadowLatencyOnly(t *testing.T) {
	reader := installManualReader(t)

	// A shadow evaluation measures PDP transport latency (path-independent
	// health signal) but never counts as a served decision — the A12 gate
	// reads shadow's log records, not this counter.
	pdp := &capturePDP{allow: true}
	engine := newDispatchEngine(t, rbac.EngineShadow, pdp)

	capture := &logCapture{}
	ctx := rbac.NewEngineContext(rbac.NewContext(capture.into(aliceContext(t)), globalACL("candy", openapi.Read)), engine)

	require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))
	require.Equal(t, 1, pdp.calls)

	var rm metricdata.ResourceMetrics

	require.NoError(t, reader.Collect(t.Context(), &rm))

	_, found := findMetric(&rm, "unikorn_identity_authz_decisions_total")
	require.False(t, found, "shadow evaluations must not increment the decision counter")

	histogram, found := findMetric(&rm, "unikorn_identity_authz_pdp_latency")
	require.True(t, found, "shadow evaluations must still measure PDP latency")

	data, ok := histogram.Data.(metricdata.Histogram[float64])
	require.True(t, ok)
	require.Len(t, data.DataPoints, 1)
	require.Equal(t, uint64(1), data.DataPoints[0].Count)
}
