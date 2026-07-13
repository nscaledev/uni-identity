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
	"testing"

	"github.com/stretchr/testify/require"

	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// These tests pin the A12 strangle-by-kind cutover DISPATCH behaviour on top of
// the modeForKind resolver (unit-tested directly in engine_internal_test.go):
// under a shadow (or legacy) global baseline, a kind in the cutover set is
// served AUTHORITATIVELY by Cerbos — the PDP verdict is the served verdict, the
// legacy walk is never a fallback, and it fails closed when the PDP is down —
// while every other kind still follows the global mode.  An empty cutover set
// is the zero-behaviour-change default and the config-only rollback.
//
// They ride the same parity fixture, capturePDP call-counting fake, and shadow
// log capture (logCapture, decisionlog_test.go) as the A6/A7 dispatch tests.

// newCutoverEngine builds an RBAC over the parity fixture with the given global
// mode, PDP, and per-kind Cerbos-authoritative cutover set — the A12
// strangle-by-kind switch.  It mirrors newDispatchEngine but sets
// CerbosAuthoritativeKinds, the only field A12 adds to the dispatch path.
func newCutoverEngine(t *testing.T, mode rbac.EngineMode, pdp rbac.PolicyDecisionPoint, cutoverKinds ...string) *rbac.RBAC {
	t.Helper()

	fx := newParityFixture(t)

	options := &rbac.Options{
		AuthorizationEngine:      mode,
		CerbosAuthoritativeKinds: cutoverKinds,
	}

	return rbac.New(fx.client, parityNamespace, options).WithCerbos(pdp)
}

// globalACLBoth grants read on two endpoints at global scope, so the legacy
// walk would ALLOW both — letting a served deny on either be attributed solely
// to the PDP.
func globalACLBoth(a, b string) *openapi.Acl {
	return &openapi.Acl{
		Global: &openapi.AclEndpoints{
			{Name: a, Operations: openapi.AclOperations{openapi.Read}},
			{Name: b, Operations: openapi.AclOperations{openapi.Read}},
		},
	}
}

func TestCutoverKindServedAuthoritativelyUnderShadow(t *testing.T) {
	t.Parallel()

	const (
		cutoverKind = "identity:groups"   // cut over to Cerbos
		shadowKind  = "identity:projects" // still on the global shadow baseline
	)

	t.Run("the cutover kind serves the PDP deny with no legacy fallback, and is not shadow-compared", func(t *testing.T) {
		t.Parallel()

		// Global baseline is shadow; only cutoverKind is cut over.  The PDP
		// denies while the ACL GRANTS read — so a served deny can only be the
		// PDP's, proving Cerbos is authoritative with NO legacy fallback.
		capture := &logCapture{}
		pdp := &capturePDP{}
		engine := newCutoverEngine(t, rbac.EngineShadow, pdp, cutoverKind)
		ctx := shadowContext(t, capture, engine, globalACLBoth(cutoverKind, shadowKind))

		err := rbac.AllowGlobalScope(ctx, cutoverKind, openapi.Read)
		require.True(t, coreerrors.IsForbidden(err), "the cutover kind must serve the PDP deny, not the legacy allow")
		require.ErrorIs(t, err, rbac.ErrPolicyDenied)
		require.Equal(t, 1, pdp.calls, "the cutover kind is served by the PDP")

		// Authoritative-served, never shadowed: the shadow comparator did not run.
		require.Empty(t, capture.messages(shadowDivergenceMessage), "a cutover kind is served by Cerbos, never shadow-compared")
		require.Empty(t, capture.messages(shadowFailureMessage))
	})

	t.Run("the cutover kind serves the PDP allow over a legacy deny", func(t *testing.T) {
		t.Parallel()

		// The other direction, so the proof is not vacuously always-deny: the
		// ACL grants nothing (legacy would DENY) but the PDP allows — the served
		// allow can only be the PDP's verdict.
		capture := &logCapture{}
		pdp := &capturePDP{allow: true}
		engine := newCutoverEngine(t, rbac.EngineShadow, pdp, cutoverKind)
		ctx := shadowContext(t, capture, engine, &openapi.Acl{})

		require.NoError(t, rbac.AllowGlobalScope(ctx, cutoverKind, openapi.Read), "the cutover kind must serve the PDP allow, not the legacy deny")
		require.Equal(t, 1, pdp.calls)
		require.Empty(t, capture.messages(shadowDivergenceMessage), "a cutover kind is served by Cerbos, never shadow-compared")
		require.Empty(t, capture.messages(shadowFailureMessage))
	})

	t.Run("a non-cutover kind under the same engine still shadows", func(t *testing.T) {
		t.Parallel()

		// Same engine config (shadow baseline, cutover {cutoverKind}), but a kind
		// NOT in the set follows the global shadow mode: the legacy verdict is
		// served (ACL grants read -> allow) while the PDP is shadow-evaluated and
		// the disagreement is logged.
		capture := &logCapture{}
		pdp := &capturePDP{}
		engine := newCutoverEngine(t, rbac.EngineShadow, pdp, cutoverKind)
		ctx := shadowContext(t, capture, engine, globalACLBoth(cutoverKind, shadowKind))

		require.NoError(t, rbac.AllowGlobalScope(ctx, shadowKind, openapi.Read), "a non-cutover kind serves the legacy verdict")
		require.Equal(t, 1, pdp.calls, "a non-cutover kind is shadow-evaluated")

		records := capture.messages(shadowDivergenceMessage)
		require.Len(t, records, 1, "the non-cutover kind still shadow-compares")

		attrs := logAttrs(t, records[0])
		require.Equal(t, shadowKind, attrs["endpoint"], "only the non-cutover kind is shadowed")
		require.Equal(t, "allow", attrs["legacy_verdict"])
		require.Equal(t, "deny", attrs["cerbos_verdict"])
		require.Empty(t, capture.messages(shadowFailureMessage))
	})
}

func TestCutoverKindAuthoritativeUnderLegacyBaseline(t *testing.T) {
	t.Parallel()

	const (
		cutoverKind = "identity:groups"
		legacyKind  = "identity:projects"
	)

	// The realistic rollout starting point: the service is on the DEFAULT legacy
	// baseline and one kind is cut over.  The cutover kind is served by Cerbos
	// while every other kind stays fully legacy — no PDP contact at all (legacy
	// has no shadow evaluation either).
	pdp := &capturePDP{} // deny everything
	engine := newCutoverEngine(t, rbac.EngineLegacy, pdp, cutoverKind)

	// The ACL grants read on BOTH kinds, so the legacy walk would ALLOW both.
	ctx := rbac.NewEngineContext(rbac.NewContext(aliceContext(t), globalACLBoth(cutoverKind, legacyKind)), engine)

	// The cutover kind serves the PDP deny — the legacy allow is not a fallback —
	// even though the global baseline is legacy.
	err := rbac.AllowGlobalScope(ctx, cutoverKind, openapi.Read)
	require.True(t, coreerrors.IsForbidden(err), "the cutover kind must serve the PDP deny under a legacy baseline")
	require.ErrorIs(t, err, rbac.ErrPolicyDenied)
	require.Equal(t, 1, pdp.calls, "the cutover kind is served by the PDP")

	// A non-cutover kind stays fully legacy: the legacy allow is served and the
	// PDP is never consulted.
	require.NoError(t, rbac.AllowGlobalScope(ctx, legacyKind, openapi.Read), "a non-cutover kind serves the legacy verdict")
	require.Equal(t, 1, pdp.calls, "a non-cutover kind under a legacy baseline never consults the PDP")
}

func TestCutoverKindFailsClosedWhenPDPUnavailable(t *testing.T) {
	t.Parallel()

	const cutoverKind = "identity:groups"

	// The load-bearing safety property of an authoritative cutover: a cut-over
	// kind HARD-DEPENDS on the PDP.  With the PDP unavailable and the ACL
	// GRANTING read, a legacy fallback would ALLOW — so a served deny that
	// carries the outage sentinel (not a policy deny, not an allow) proves the
	// kind fails closed with no quiet fall back to the legacy walk.
	capture := &logCapture{}
	pdp := &capturePDP{err: errFakeTransport}
	engine := newCutoverEngine(t, rbac.EngineShadow, pdp, cutoverKind)
	ctx := shadowContext(t, capture, engine, globalACL(cutoverKind, openapi.Read))

	err := rbac.AllowGlobalScope(ctx, cutoverKind, openapi.Read)
	require.True(t, coreerrors.IsForbidden(err), "a cutover kind must fail closed when the PDP is unavailable")
	require.ErrorIs(t, err, rbac.ErrDecisionUnavailable, "the deny must be the PDP outage — never a legacy fallback, never a policy deny")
	require.Equal(t, 1, pdp.calls)

	// Served by the cerbos path (fail-closed), so the shadow comparator never ran.
	require.Empty(t, capture.messages(shadowDivergenceMessage))
	require.Empty(t, capture.messages(shadowFailureMessage))
}

func TestCutoverEmptySetRollsBackToGlobalMode(t *testing.T) {
	t.Parallel()

	const kind = "identity:groups"

	// The escape hatch: clearing the cutover set (an empty set) reverts dispatch
	// to the global baseline — config-only rollback, no code change.  This is the
	// exact contrast with TestCutoverKindServedAuthoritativelyUnderShadow: the
	// same kind, same deny-PDP, same granting ACL, but WITHOUT the cutover the
	// kind is back on the global shadow baseline — the legacy allow is served and
	// the PDP is only shadow-evaluated, not authoritative.
	capture := &logCapture{}
	pdp := &capturePDP{}
	engine := newCutoverEngine(t, rbac.EngineShadow, pdp) // empty cutover set
	ctx := shadowContext(t, capture, engine, globalACL(kind, openapi.Read))

	require.NoError(t, rbac.AllowGlobalScope(ctx, kind, openapi.Read), "an empty cutover set serves the legacy verdict (global shadow mode)")
	require.Equal(t, 1, pdp.calls, "shadow still evaluates the PDP")

	records := capture.messages(shadowDivergenceMessage)
	require.Len(t, records, 1, "with no cutover the kind is shadowed, so the disagreement is logged (not authoritative-served)")

	attrs := logAttrs(t, records[0])
	require.Equal(t, "allow", attrs["legacy_verdict"])
	require.Equal(t, "deny", attrs["cerbos_verdict"])
	require.Empty(t, capture.messages(shadowFailureMessage))
}
