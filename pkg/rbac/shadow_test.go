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
	"log/slog"
	"sync"
	"testing"

	sdk "github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// These tests pin the A7 shadow-mode comparator: in shadow mode every
// dispatched scope check serves the LEGACY verdict unconditionally while the
// Cerbos path is evaluated alongside it and disagreement is logged.  The log
// taxonomy is load-bearing for the A12 cutover gate: verdict disagreements
// are "divergence", failures to obtain a verdict are "evaluation failure",
// and the two must never blur — a PDP restart must not read as policy
// divergence.

// The exact log messages are the shadow-phase observability contract (A12's
// cutover gate consumes them); duplicated from shadow.go deliberately so a
// rename breaks these tests.
const (
	shadowDivergenceMessage = "cerbos shadow divergence"
	shadowFailureMessage    = "cerbos shadow evaluation failure"
)

// shadowLogCapture is a minimal slog.Handler recording every record emitted
// while installed as the default logger.  Safe for concurrent emitters; the
// shadow comparator never uses WithAttrs/WithGroup so both are identity.
type shadowLogCapture struct {
	mu      sync.Mutex
	records []slog.Record
}

func (c *shadowLogCapture) Enabled(context.Context, slog.Level) bool {
	return true
}

func (c *shadowLogCapture) Handle(_ context.Context, record slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.records = append(c.records, record.Clone())

	return nil
}

func (c *shadowLogCapture) WithAttrs([]slog.Attr) slog.Handler {
	return c
}

func (c *shadowLogCapture) WithGroup(string) slog.Handler {
	return c
}

// messages returns the captured records carrying the given message, filtering
// out unrelated records other code may emit through the default logger.
func (c *shadowLogCapture) messages(message string) []slog.Record {
	c.mu.Lock()
	defer c.mu.Unlock()

	var out []slog.Record

	for _, record := range c.records {
		if record.Message == message {
			out = append(out, record)
		}
	}

	return out
}

// captureShadowLogs installs a recording default logger for the duration of
// the test.  The default logger is process-global, so tests using this helper
// must NOT call t.Parallel(): serial tests never overlap with each other or
// with (parked) parallel tests.
func captureShadowLogs(t *testing.T) *shadowLogCapture {
	t.Helper()

	capture := &shadowLogCapture{}
	previous := slog.Default()

	slog.SetDefault(slog.New(capture))

	t.Cleanup(func() {
		slog.SetDefault(previous)
	})

	return capture
}

// recordAttrs flattens a record's attributes for assertion.
func recordAttrs(record slog.Record) map[string]string {
	out := map[string]string{}

	record.Attrs(func(attr slog.Attr) bool {
		out[attr.Key] = attr.Value.String()

		return true
	})

	return out
}

// stampedPDP decorates another PDP, stamping the in-band per-result policy
// metadata a real PDP returns, so the divergence log's policy correlate is
// observable in unit tests.
type stampedPDP struct {
	next          rbac.PolicyDecisionPoint
	policyVersion string
	policyScope   string
}

func (s *stampedPDP) CheckResources(ctx context.Context, checkPrincipal *sdk.Principal, resources *sdk.ResourceBatch) (*sdk.CheckResourcesResponse, error) {
	response, err := s.next.CheckResources(ctx, checkPrincipal, resources)

	if response != nil {
		for _, result := range response.Results {
			result.Resource.PolicyVersion = s.policyVersion
			result.Resource.Scope = s.policyScope
		}
	}

	return response, err
}

// panicPDP panics on every call: the worst-case shadow failure.
type panicPDP struct{}

func (panicPDP) CheckResources(context.Context, *sdk.Principal, *sdk.ResourceBatch) (*sdk.CheckResourcesResponse, error) {
	panic("deliberate test panic")
}

// shadowContext builds the exact context shape the middleware produces in
// shadow mode: authorization info (for the Cerbos side), an ACL (for the
// legacy walk) and the seeded engine.
func shadowContext(t *testing.T, engine *rbac.RBAC, acl *openapi.Acl) context.Context {
	t.Helper()

	return rbac.NewEngineContext(rbac.NewContext(aliceContext(t), acl), engine)
}

func TestShadowEngineModeFlag(t *testing.T) {
	t.Parallel()

	// Config-gating is the existing --authorization-engine flag taking the
	// new whitelisted value; the enum round-trips through pflag.
	var mode rbac.EngineMode

	require.NoError(t, mode.Set("shadow"))
	require.Equal(t, rbac.EngineShadow, mode)
	require.Equal(t, "shadow", mode.String())

	options := &rbac.Options{}
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	options.AddFlags(flags)

	require.NoError(t, flags.Parse([]string{"--authorization-engine=shadow"}))
	require.Equal(t, rbac.EngineShadow, options.AuthorizationEngine)
}

//nolint:paralleltest // captureShadowLogs swaps the process-global default logger.
func TestShadowAgreementIsSilent(t *testing.T) {
	capture := captureShadowLogs(t)

	// Allow-agreement: the ACL grants the operation and the PDP allows it.
	pdp := &capturePDP{allow: true}
	engine := newDispatchEngine(t, rbac.EngineShadow, pdp)
	ctx := shadowContext(t, engine, globalACL("candy", openapi.Read))

	require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))
	require.Equal(t, 1, pdp.calls, "exactly one PDP call per shadowed check")

	// The shadow evaluation must ask the SAME coarse question cerbos mode
	// would: global is kind-only with the coarse ID...
	entry := batchEntry(t, pdp, 0)
	require.Equal(t, "candy", entry.GetResource().GetKind())
	require.Equal(t, cerbos.CoarseResourceID, entry.GetResource().GetId())
	require.Empty(t, entry.GetResource().GetAttr(), "a global check must carry no scope attributes")
	require.Equal(t, []string{"read"}, entry.GetActions())

	// ...organization carries the organization attribute only (the project
	// attribute ABSENT — the no-flow-up invariant)...
	require.NoError(t, rbac.AllowOrganizationScope(ctx, "candy", openapi.Read, parityOrgA))

	entry = batchEntry(t, pdp, 1)
	attrs := entry.GetResource().GetAttr()
	require.Len(t, attrs, 1)
	require.Equal(t, parityOrgA, attrs["organization"].GetStringValue())

	// ...and project carries both.
	require.NoError(t, rbac.AllowProjectScope(ctx, "candy", openapi.Read, parityOrgA, parityProjectX))

	entry = batchEntry(t, pdp, 2)
	attrs = entry.GetResource().GetAttr()
	require.Len(t, attrs, 2)
	require.Equal(t, parityOrgA, attrs["organization"].GetStringValue())
	require.Equal(t, parityProjectX, attrs["project"].GetStringValue())

	// Deny-agreement: the ACL lacks the operation and the PDP denies it.
	denyPDP := &capturePDP{}
	denyEngine := newDispatchEngine(t, rbac.EngineShadow, denyPDP)
	denyCtx := shadowContext(t, denyEngine, globalACL("candy", openapi.Read))

	err := rbac.AllowGlobalScope(denyCtx, "candy", openapi.Delete)
	require.True(t, coreerrors.IsForbidden(err))
	require.Equal(t, 1, denyPDP.calls)

	require.Empty(t, capture.messages(shadowDivergenceMessage), "agreement must not log divergence")
	require.Empty(t, capture.messages(shadowFailureMessage), "agreement must not log evaluation failure")
}

//nolint:paralleltest // captureShadowLogs swaps the process-global default logger.
func TestShadowDivergenceCerbosAllows(t *testing.T) {
	capture := captureShadowLogs(t)

	// The PDP allows what the ACL does not grant: a divergence, with the
	// legacy DENY still served.
	engine := newDispatchEngine(t, rbac.EngineShadow, &stampedPDP{
		next:          &capturePDP{allow: true},
		policyVersion: "default",
		policyScope:   "acme",
	})
	ctx := shadowContext(t, engine, globalACL("candy", openapi.Read))

	err := rbac.AllowOrganizationScope(ctx, "candy", openapi.Delete, parityOrgA)
	require.True(t, coreerrors.IsForbidden(err), "the served verdict must be the legacy deny")

	records := capture.messages(shadowDivergenceMessage)
	require.Len(t, records, 1)

	// The full record, and NOTHING but the record: the closed field set is
	// the guarantee no token or credential material can ride along.
	attrs := recordAttrs(records[0])
	require.Len(t, attrs, 11)
	require.Equal(t, parityAliceSubject, attrs["subject"])
	require.Equal(t, "user", attrs["actor_type"])
	require.Equal(t, "candy", attrs["endpoint"])
	require.Equal(t, "delete", attrs["operation"])
	require.Equal(t, parityOrgA, attrs["organization_id"])
	require.Empty(t, attrs["project_id"])
	require.Equal(t, "deny", attrs["legacy_verdict"])
	require.Equal(t, "allow", attrs["cerbos_verdict"])
	require.Equal(t, "allowed", attrs["cerbos_class"])
	require.Equal(t, "default", attrs["policy_version"])
	require.Equal(t, "acme", attrs["policy_scope"])

	require.Empty(t, capture.messages(shadowFailureMessage))
}

//nolint:paralleltest // captureShadowLogs swaps the process-global default logger.
func TestShadowDivergenceCerbosDenies(t *testing.T) {
	capture := captureShadowLogs(t)

	// The PDP denies what the ACL grants: a divergence, with the legacy
	// ALLOW still served.
	pdp := &capturePDP{}
	engine := newDispatchEngine(t, rbac.EngineShadow, pdp)
	ctx := shadowContext(t, engine, globalACL("candy", openapi.Read))

	require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read), "the served verdict must be the legacy allow")
	require.Equal(t, 1, pdp.calls)

	records := capture.messages(shadowDivergenceMessage)
	require.Len(t, records, 1)

	attrs := recordAttrs(records[0])
	require.Equal(t, "allow", attrs["legacy_verdict"])
	require.Equal(t, "deny", attrs["cerbos_verdict"])
	require.Equal(t, "policy_denied", attrs["cerbos_class"])

	require.Empty(t, capture.messages(shadowFailureMessage))
}

//nolint:paralleltest // captureShadowLogs swaps the process-global default logger.
func TestShadowEvaluationFailureIsNotDivergence(t *testing.T) {
	// The taxonomy split this test pins is what keeps A12's zero-divergence
	// gate honest: a PDP outage (or restart) during the shadow phase is infra
	// signal and must NEVER register as policy divergence.
	t.Run("PDPUnavailable", func(t *testing.T) {
		capture := captureShadowLogs(t)

		pdp := &capturePDP{err: errFakeTransport}
		engine := newDispatchEngine(t, rbac.EngineShadow, pdp)
		ctx := shadowContext(t, engine, globalACL("candy", openapi.Read))

		require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read), "a PDP outage must not alter the served legacy verdict")

		require.Empty(t, capture.messages(shadowDivergenceMessage), "unavailability is infra signal, never divergence")

		records := capture.messages(shadowFailureMessage)
		require.Len(t, records, 1)
		require.Equal(t, "decision_unavailable", recordAttrs(records[0])["cerbos_class"])
	})

	t.Run("NoPDPConfigured", func(t *testing.T) {
		capture := captureShadowLogs(t)

		engine := newDispatchEngine(t, rbac.EngineShadow, nil)
		ctx := shadowContext(t, engine, globalACL("candy", openapi.Read))

		require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))

		require.Empty(t, capture.messages(shadowDivergenceMessage))

		records := capture.messages(shadowFailureMessage)
		require.Len(t, records, 1)
		require.Equal(t, "decision_unavailable", recordAttrs(records[0])["cerbos_class"])
	})

	t.Run("ResolutionFailure", func(t *testing.T) {
		capture := captureShadowLogs(t)

		// No authorization info in the context: the legacy walk still serves
		// from the ACL while the Cerbos side fails before the PDP is asked.
		pdp := &capturePDP{allow: true}
		engine := newDispatchEngine(t, rbac.EngineShadow, pdp)
		ctx := rbac.NewEngineContext(rbac.NewContext(t.Context(), globalACL("candy", openapi.Read)), engine)

		require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))
		require.Zero(t, pdp.calls, "resolution fails before the PDP is asked")

		require.Empty(t, capture.messages(shadowDivergenceMessage))

		records := capture.messages(shadowFailureMessage)
		require.Len(t, records, 1)
		require.Equal(t, "resolution_failed", recordAttrs(records[0])["cerbos_class"])
	})
}

//nolint:paralleltest // captureShadowLogs swaps the process-global default logger.
func TestShadowPanicIsRecovered(t *testing.T) {
	capture := captureShadowLogs(t)

	engine := newDispatchEngine(t, rbac.EngineShadow, panicPDP{})
	ctx := shadowContext(t, engine, globalACL("candy", openapi.Read))

	// The zero-behaviour-change contract under the worst case: a panicking
	// shadow evaluation must never escape the dispatcher, and both legacy
	// verdicts must be served untouched.
	require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))

	err := rbac.AllowGlobalScope(ctx, "candy", openapi.Delete)
	require.True(t, coreerrors.IsForbidden(err))

	require.Empty(t, capture.messages(shadowDivergenceMessage), "a panic is an evaluation failure, never divergence")

	records := capture.messages(shadowFailureMessage)
	require.Len(t, records, 2)

	attrs := recordAttrs(records[0])
	require.Equal(t, "panic", attrs["cerbos_class"])
	require.Contains(t, attrs["panic"], "deliberate test panic")
	require.NotEmpty(t, attrs["stack"])
}

//nolint:paralleltest // captureShadowLogs swaps the process-global default logger.
func TestShadowImpersonatedSkipsComparison(t *testing.T) {
	capture := captureShadowLogs(t)

	pdp := &capturePDP{allow: true}
	engine := newDispatchEngine(t, rbac.EngineShadow, pdp)

	// The exact legacy impersonation predicate: a principal in context, the
	// impersonation marker, and a non-empty actor.  Until the A14 dual-check
	// the Cerbos path has no impersonation story, so such requests are
	// excluded from the comparison entirely: no PDP call, no log.
	ctx := shadowContext(t, engine, globalACL("candy", openapi.Read))
	ctx = principal.NewContext(ctx, &principal.Principal{Actor: "impersonated@example.com", Type: openapi.User})
	ctx = principal.NewImpersonateContext(ctx)

	require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))
	require.Error(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Delete))

	require.Zero(t, pdp.calls, "impersonated requests are excluded from shadow comparison until A14")
	require.Empty(t, capture.messages(shadowDivergenceMessage))
	require.Empty(t, capture.messages(shadowFailureMessage))

	// Predicate parity with the legacy detection: the marker WITHOUT an
	// actor is not impersonation, so the comparison runs.
	ctx = shadowContext(t, engine, globalACL("candy", openapi.Read))
	ctx = principal.NewContext(ctx, &principal.Principal{Type: openapi.User})
	ctx = principal.NewImpersonateContext(ctx)

	require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))
	require.Equal(t, 1, pdp.calls)
}

//nolint:paralleltest // captureShadowLogs swaps the process-global default logger.
func TestShadowAbsentEngineTakesPlainLegacy(t *testing.T) {
	capture := captureShadowLogs(t)

	// A shadow-mode engine EXISTS (the server configured one) but was never
	// seeded into this context: the structural absence rule applies exactly
	// as in cerbos mode — plain legacy, no comparison, no logs.
	pdp := &capturePDP{allow: true}
	newDispatchEngine(t, rbac.EngineShadow, pdp)

	ctx := rbac.NewContext(aliceContext(t), globalACL("candy", openapi.Read))

	require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))
	require.Error(t, rbac.AllowGlobalScope(ctx, "wibble", openapi.Read))

	require.Zero(t, pdp.calls, "an un-seeded context must never consult the PDP")
	require.Empty(t, capture.messages(shadowDivergenceMessage))
	require.Empty(t, capture.messages(shadowFailureMessage))
}

//nolint:paralleltest // captureShadowLogs swaps the process-global default logger.
func TestShadowCreateAndRoleStayUnshadowed(t *testing.T) {
	capture := captureShadowLogs(t)

	// AllowProjectScopeCreate and AllowRole are never shadowed — their Cerbos
	// stories are A9 and A16 respectively: zero PDP calls, zero shadow logs.
	pdp := &capturePDP{}
	engine := newDispatchEngine(t, rbac.EngineShadow, pdp)

	ctx := shadowContext(t, engine, globalACL("candy", openapi.Create))
	require.NoError(t, rbac.AllowProjectScopeCreate(ctx, nil, "candy", openapi.Create, organizationID, projectID))

	roleCtx := rbac.NewEngineContext(rbac.NewContext(aliceContext(t), aclFixture()), engine)

	role := &unikornv1.Role{
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Organization: []unikornv1.RoleScope{
					{Name: resourceType1, Operations: []unikornv1.Operation{unikornv1.Read}},
				},
			},
		},
	}

	require.NoError(t, rbac.AllowRole(roleCtx, role, ids.MustParseOrganizationID(organizationID)))

	require.Zero(t, pdp.calls, "create and role grantability must stay legacy-only in shadow mode")
	require.Empty(t, capture.messages(shadowDivergenceMessage))
	require.Empty(t, capture.messages(shadowFailureMessage))
}
