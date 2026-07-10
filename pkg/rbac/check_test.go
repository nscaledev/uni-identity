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
	goerrors "errors"
	"testing"

	sdk "github.com/cerbos/cerbos-sdk-go/cerbos"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/stretchr/testify/require"

	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// These tests pin the decision API's error taxonomy: every failure mode is a
// distinct, deny-shaped static error, so callers can treat any non-nil error
// as a deny while operators can still tell a policy deny from an outage.

var errFakeTransport = goerrors.New("fake transport failure")

// fakePDP is a canned PolicyDecisionPoint recording what it was asked.
type fakePDP struct {
	response *sdk.CheckResourcesResponse
	err      error

	// steps, when non-empty, are consumed one per call — the A14 dual-check
	// tests need per-side verdicts and failures.  response/err answer every
	// call otherwise.
	steps []fakePDPStep

	calls      int
	principal  *sdk.Principal
	principals []*sdk.Principal
}

// fakePDPStep is one canned per-call reply.
type fakePDPStep struct {
	response *sdk.CheckResourcesResponse
	err      error
}

func (f *fakePDP) CheckResources(_ context.Context, checkPrincipal *sdk.Principal, _ *sdk.ResourceBatch) (*sdk.CheckResourcesResponse, error) {
	f.calls++
	f.principal = checkPrincipal
	f.principals = append(f.principals, checkPrincipal)

	if len(f.steps) > 0 {
		step := f.steps[0]
		f.steps = f.steps[1:]

		if step.err != nil {
			return nil, step.err
		}

		return step.response, nil
	}

	if f.err != nil {
		return nil, f.err
	}

	return f.response, nil
}

// principalBindings extracts the rendered binding strings a captured
// principal carries in its bindings attribute.
func principalBindings(t *testing.T, p *sdk.Principal) []string {
	t.Helper()

	list := p.Obj.GetAttr()["bindings"].GetListValue()
	require.NotNil(t, list, "a built principal must carry the bindings attribute")

	out := make([]string, 0, len(list.GetValues()))

	for _, value := range list.GetValues() {
		out = append(out, value.GetStringValue())
	}

	return out
}

// pdpResponse assembles a canned CheckResources response from result entries.
func pdpResponse(results ...*responsev1.CheckResourcesResponse_ResultEntry) *sdk.CheckResourcesResponse {
	return &sdk.CheckResourcesResponse{
		CheckResourcesResponse: &responsev1.CheckResourcesResponse{Results: results},
	}
}

// pdpResult builds one result entry echoing the checked resource.
func pdpResult(kind, id string, actions map[string]effectv1.Effect) *responsev1.CheckResourcesResponse_ResultEntry {
	return &responsev1.CheckResourcesResponse_ResultEntry{
		Resource: &responsev1.CheckResourcesResponse_ResultEntry_Resource{Kind: kind, Id: id},
		Actions:  actions,
	}
}

// aliceContext returns a context carrying alice's authorization info.
func aliceContext(t *testing.T) context.Context {
	t.Helper()

	return authorization.NewContext(t.Context(), parityUserInfo(parityAliceSubject, parityOrgA))
}

func TestCheckNilClientFailsClosed(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// An RBAC without an injected PDP client is legal (contexts without a
	// sidecar); decisions must fail closed, not panic or allow.
	err := fx.rbac.Check(aliceContext(t), rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Read)
	require.ErrorIs(t, err, rbac.ErrDecisionUnavailable)

	_, err = fx.rbac.CheckMany(aliceContext(t), []rbac.CheckRequest{{Resource: rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, Action: openapi.Read}})
	require.ErrorIs(t, err, rbac.ErrDecisionUnavailable)
}

// impersonatedContext returns the context shape an impersonated
// service-to-service request carries: the acting system account's
// authorization info plus the propagated principal and the impersonation
// marker.
func impersonatedContext(t *testing.T, p *principal.Principal) context.Context {
	t.Helper()

	ctx := authorization.NewContext(t.Context(), paritySystemInfo(paritySystemCN))
	ctx = principal.NewContext(ctx, p)

	return principal.NewImpersonateContext(ctx)
}

func TestCheckImpersonatedDualCheck(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)
	pdp := &fakePDP{response: pdpResponse(pdpResult("identity:groups", "*", map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}))}
	fx.rbac.WithCerbos(pdp)

	// An impersonated request (the exact legacy detection: a principal in
	// context, the impersonation marker, and a non-empty actor) is served by
	// the A14 dual check: two AND-ed single-principal evaluations over the
	// identical resource and action.
	ctx := impersonatedContext(t, &principal.Principal{Actor: parityAliceSubject, Type: openapi.User, OrganizationIDs: []string{parityOrgA}})

	require.NoError(t, fx.rbac.Check(ctx, rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Read))

	// Two PDP calls: the impersonated principal first, the acting service
	// second (the ordering shadow's response capture relies on).
	require.Equal(t, 2, pdp.calls, "an impersonated decision is two PDP calls")

	// The impersonated side is keyed by the propagated actor and carries
	// ITS resolved bindings, exactly as a direct request by that subject.
	require.Equal(t, parityAliceSubject, pdp.principals[0].Obj.GetId())
	require.Equal(t, []string{
		parityRoleMixed + "#org#" + parityOrgA,
		parityRoleOrgAdmin + "#org#" + parityOrgA,
		parityRoleOrgAdmin + "#project#" + parityOrgA + "#" + parityProjectX,
	}, principalBindings(t, pdp.principals[0]))

	// The service side is keyed by the acting system account's CN and
	// carries its configured global binding.
	require.Equal(t, paritySystemCN, pdp.principals[1].Obj.GetId())
	require.Equal(t, []string{parityRoleGlobalAdmin + "#global"}, principalBindings(t, pdp.principals[1]))

	t.Logf("dual-check request shapes: impersonated principal id=%q bindings=%v; service principal id=%q bindings=%v",
		pdp.principals[0].Obj.GetId(), principalBindings(t, pdp.principals[0]),
		pdp.principals[1].Obj.GetId(), principalBindings(t, pdp.principals[1]))
}

func TestCheckImpersonatedDualCheckAndSemantics(t *testing.T) {
	t.Parallel()

	allow := pdpResponse(pdpResult("identity:groups", "*", map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}))
	deny := pdpResponse(pdpResult("identity:groups", "*", map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_DENY}))

	cases := []struct {
		name         string
		impersonated *sdk.CheckResourcesResponse
		service      *sdk.CheckResourcesResponse
		wantAllow    bool
	}{
		{name: "AllowAndAllowIsAllow", impersonated: allow, service: allow, wantAllow: true},
		{name: "ImpersonatedSideDenyIsDeny", impersonated: deny, service: allow},
		{name: "ServiceSideDenyIsDeny", impersonated: allow, service: deny},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fx := newParityFixture(t)
			pdp := &fakePDP{steps: []fakePDPStep{{response: tc.impersonated}, {response: tc.service}}}
			fx.rbac.WithCerbos(pdp)

			ctx := impersonatedContext(t, &principal.Principal{Actor: parityAliceSubject, Type: openapi.User, OrganizationIDs: []string{parityOrgA}})

			err := fx.rbac.Check(ctx, rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Read)

			if tc.wantAllow {
				require.NoError(t, err)
			} else {
				// A one-sided deny is a plain policy deny: the policies were
				// consulted and the intersection did not allow the action.
				require.ErrorIs(t, err, rbac.ErrPolicyDenied)
			}

			// The record needs both verdicts: neither side may short-circuit
			// the other, even when the first side already denied.
			require.Equal(t, 2, pdp.calls, "both sides must always be evaluated — no short-circuit")
		})
	}
}

func TestCheckImpersonatedTypeGate(t *testing.T) {
	t.Parallel()

	// The type gate is PINNED: only User and Service principals can be
	// impersonated.  System and unknown/empty types are refused pre-PDP with
	// ErrImpersonationNotSupported — legacy parity, where GetACL hard-errors
	// with ErrInvalidPrincipalType — never resolved via the default-to-User
	// arm as the wrong principal class.
	for _, principalType := range []openapi.AuthClaimsAcctype{openapi.System, "", "wibble"} {
		t.Run(string(principalType), func(t *testing.T) {
			t.Parallel()

			fx := newParityFixture(t)
			pdp := &fakePDP{response: pdpResponse(pdpResult("identity:groups", "*", map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}))}
			fx.rbac.WithCerbos(pdp)

			ctx := impersonatedContext(t, &principal.Principal{Actor: "impersonated@example.com", Type: principalType, OrganizationIDs: []string{parityOrgA}})

			err := fx.rbac.Check(ctx, rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Read)
			require.ErrorIs(t, err, rbac.ErrImpersonationNotSupported)
			require.Zero(t, pdp.calls, "a type-gate refusal must never reach the PDP")
		})
	}
}

func TestCheckImpersonatedTransportFailureFailsClosed(t *testing.T) {
	t.Parallel()

	allow := pdpResponse(pdpResult("identity:groups", "*", map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}))

	// A transport failure on EITHER side of the dual check is the same
	// fail-closed unavailability a direct request maps to.
	cases := []struct {
		name  string
		steps []fakePDPStep
	}{
		{name: "ImpersonatedSideFails", steps: []fakePDPStep{{err: errFakeTransport}, {response: allow}}},
		{name: "ServiceSideFails", steps: []fakePDPStep{{response: allow}, {err: errFakeTransport}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fx := newParityFixture(t)
			pdp := &fakePDP{steps: tc.steps}
			fx.rbac.WithCerbos(pdp)

			ctx := impersonatedContext(t, &principal.Principal{Actor: parityAliceSubject, Type: openapi.User, OrganizationIDs: []string{parityOrgA}})

			err := fx.rbac.Check(ctx, rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Read)
			require.ErrorIs(t, err, rbac.ErrDecisionUnavailable)
			require.Equal(t, 2, pdp.calls, "both sides are evaluated before either error is inspected")
		})
	}
}

func TestCheckImpersonatedSingularOrganizationFallback(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)
	pdp := &fakePDP{response: pdpResponse(pdpResult("identity:groups", "*", map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}))}
	fx.rbac.WithCerbos(pdp)

	// The synthesized claims mirror the legacy rebuild exactly: an empty
	// plural OrganizationIDs falls back to the singular OrganizationID, so a
	// caller that only sets the latter still resolves the scoped
	// organization rather than an empty grant set.
	ctx := impersonatedContext(t, &principal.Principal{Actor: parityAliceSubject, Type: openapi.User, OrganizationID: parityOrgA})

	require.NoError(t, fx.rbac.Check(ctx, rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Read))
	require.Equal(t, 2, pdp.calls)

	require.Equal(t, []string{
		parityRoleMixed + "#org#" + parityOrgA,
		parityRoleOrgAdmin + "#org#" + parityOrgA,
		parityRoleOrgAdmin + "#project#" + parityOrgA + "#" + parityProjectX,
	}, principalBindings(t, pdp.principals[0]), "the singular fallback must resolve the scoped organization's bindings")
}

func TestCheckImpersonatedServicePrincipalResolvesServiceBindings(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)
	pdp := &fakePDP{response: pdpResponse(pdpResult("identity:projects", "*", map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}))}
	fx.rbac.WithCerbos(pdp)

	// The synthesized claims carry the propagated principal TYPE, so a
	// Service-type actor resolves through the service-account arm — its
	// home-org group memberships — not the user arm.
	ctx := impersonatedContext(t, &principal.Principal{Actor: paritySA1, Type: openapi.Service, OrganizationIDs: []string{parityOrgA}})

	require.NoError(t, fx.rbac.Check(ctx, rbac.Resource{Kind: "identity:projects", OrganizationID: parityOrgA}, openapi.Read))
	require.Equal(t, 2, pdp.calls)

	require.Equal(t, paritySA1, pdp.principals[0].Obj.GetId())
	require.Equal(t, []string{
		parityRoleProjectDev + "#org#" + parityOrgA,
		parityRoleProjectDev + "#project#" + parityOrgA + "#" + parityProjectX,
	}, principalBindings(t, pdp.principals[0]))
}

func TestCheckImpersonatedPlatformAdministratorActor(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)
	pdp := &fakePDP{response: pdpResponse(pdpResult("identity:organizations", "*", map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}))}
	fx.rbac.WithCerbos(pdp)

	// The platform-administrator short-circuit applies to the SYNTHESIZED
	// subject too (bindings.go, mirroring the legacy
	// processUserAccountACL early return): the actor string is
	// caller-propagated, so this is a distinct input path from a direct
	// admin request and pinned separately.
	ctx := impersonatedContext(t, &principal.Principal{Actor: parityAdminSubject, Type: openapi.User, OrganizationIDs: []string{parityOrgA}})

	require.NoError(t, fx.rbac.Check(ctx, rbac.Resource{Kind: "identity:organizations", OrganizationID: parityOrgA}, openapi.Read))
	require.Equal(t, 2, pdp.calls)

	require.Equal(t, parityAdminSubject, pdp.principals[0].Obj.GetId())
	require.Equal(t, []string{parityRoleGlobalAdmin + "#global"}, principalBindings(t, pdp.principals[0]),
		"the impersonated administrator resolves the configured global roles only, group memberships ignored")
}

func TestCheckImpersonationMarkerWithoutActorProceeds(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)
	pdp := &fakePDP{response: pdpResponse(pdpResult("identity:groups", "*", map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}))}
	fx.rbac.WithCerbos(pdp)

	// Parity with the legacy detection (getSystemAccountACL): the marker
	// without an actor is treated as not impersonated.
	ctx := principal.NewContext(aliceContext(t), &principal.Principal{Type: openapi.User})
	ctx = principal.NewImpersonateContext(ctx)

	err := fx.rbac.Check(ctx, rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Read)
	require.NoError(t, err)
}

func TestCheckMissingAuthorizationInfo(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)
	fx.rbac.WithCerbos(&fakePDP{})

	err := fx.rbac.Check(t.Context(), rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Read)
	require.ErrorIs(t, err, rbac.ErrResolutionFailed)
}

func TestCheckResolverErrorFailsClosed(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)
	pdp := &fakePDP{}
	fx.rbac.WithCerbos(pdp)

	// Erin's group references a nonexistent role: the resolver's hard
	// consistency error surfaces as a deny-shaped resolution failure, with
	// the cause preserved for diagnosis.
	ctx := authorization.NewContext(t.Context(), parityUserInfo(parityErinSubject, parityOrgA))

	err := fx.rbac.Check(ctx, rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Read)
	require.ErrorIs(t, err, rbac.ErrResolutionFailed)
	require.ErrorIs(t, err, coreerrors.ErrConsistency)
	require.Zero(t, pdp.calls)
}

func TestCheckTransportErrorFailsClosed(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)
	fx.rbac.WithCerbos(&fakePDP{err: goerrors.Join(cerbos.ErrUnavailable, errFakeTransport)})

	err := fx.rbac.Check(aliceContext(t), rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Read)
	require.ErrorIs(t, err, rbac.ErrDecisionUnavailable)

	// The client's fail-closed sentinel stays observable through the wrap.
	require.ErrorIs(t, err, cerbos.ErrUnavailable)
}

func TestCheckAllowAndPolicyDeny(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)
	pdp := &fakePDP{response: pdpResponse(pdpResult("identity:groups", "*", map[string]effectv1.Effect{
		"create": effectv1.Effect_EFFECT_ALLOW,
	}))}
	fx.rbac.WithCerbos(pdp)

	require.NoError(t, fx.rbac.Check(aliceContext(t), rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Create))

	// A response without an explicit EFFECT_ALLOW for the action is a plain
	// policy deny, distinguishable from the fail-closed sentinels.
	pdp.response = pdpResponse(pdpResult("identity:groups", "*", map[string]effectv1.Effect{
		"delete": effectv1.Effect_EFFECT_DENY,
	}))

	err := fx.rbac.Check(aliceContext(t), rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Delete)
	require.ErrorIs(t, err, rbac.ErrPolicyDenied)
	require.NotErrorIs(t, err, rbac.ErrDecisionUnavailable)
	require.NotErrorIs(t, err, rbac.ErrResolutionFailed)
}

func TestCheckManyMapsResultsInOrder(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// The PDP echoes results positionally (the engine evaluates inputs in
	// order); CheckMany must map allow/deny back onto the request order in
	// a single CheckResources round trip.
	pdp := &fakePDP{response: pdpResponse(
		pdpResult("identity:groups", "*", map[string]effectv1.Effect{"create": effectv1.Effect_EFFECT_ALLOW}),
		pdpResult("identity:groups", "*", map[string]effectv1.Effect{"delete": effectv1.Effect_EFFECT_DENY}),
		pdpResult("compute:clusters", "cluster-1", map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}),
	)}
	fx.rbac.WithCerbos(pdp)

	allowed, err := fx.rbac.CheckMany(aliceContext(t), []rbac.CheckRequest{
		{Resource: rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, Action: openapi.Create},
		{Resource: rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, Action: openapi.Delete},
		{Resource: rbac.Resource{Kind: "compute:clusters", ID: "cluster-1", OrganizationID: parityOrgA, ProjectID: parityProjectX}, Action: openapi.Read},
	})
	require.NoError(t, err)
	require.Equal(t, []bool{true, false, true}, allowed)

	// One batched call, keyed by the subject the resolver used.
	require.Equal(t, 1, pdp.calls)
	require.Equal(t, parityAliceSubject, pdp.principal.Obj.GetId())
}

func TestCheckManyResultCountMismatchFailsClosed(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)
	fx.rbac.WithCerbos(&fakePDP{response: pdpResponse()})

	_, err := fx.rbac.CheckMany(aliceContext(t), []rbac.CheckRequest{{Resource: rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, Action: openapi.Read}})
	require.ErrorIs(t, err, rbac.ErrDecisionUnavailable)
}

func TestCheckManyResultShapeMismatchFailsClosed(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// A result echoing a different resource than was asked at that position
	// is a malformed response: fail closed, never guess a verdict.
	fx.rbac.WithCerbos(&fakePDP{response: pdpResponse(
		pdpResult("identity:unexpected", "*", map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}),
	)})

	_, err := fx.rbac.CheckMany(aliceContext(t), []rbac.CheckRequest{{Resource: rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, Action: openapi.Read}})
	require.ErrorIs(t, err, rbac.ErrDecisionUnavailable)
}

func TestCheckManyEmptyBatchIsAnError(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)
	fx.rbac.WithCerbos(&fakePDP{})

	// The builder refuses empty batches (a request that checks nothing);
	// surfaced as a deny-shaped resolution failure, never a silent success.
	_, err := fx.rbac.CheckMany(aliceContext(t), nil)
	require.ErrorIs(t, err, rbac.ErrResolutionFailed)
}
