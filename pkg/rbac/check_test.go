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

	calls     int
	principal *sdk.Principal
}

func (f *fakePDP) CheckResources(_ context.Context, checkPrincipal *sdk.Principal, _ *sdk.ResourceBatch) (*sdk.CheckResourcesResponse, error) {
	f.calls++
	f.principal = checkPrincipal

	if f.err != nil {
		return nil, f.err
	}

	return f.response, nil
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

func TestCheckImpersonationRefused(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)
	pdp := &fakePDP{response: pdpResponse(pdpResult("identity:groups", "*", map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}))}
	fx.rbac.WithCerbos(pdp)

	// An impersonated request (the exact legacy detection: a principal in
	// context, the impersonation marker, and a non-empty actor) must be
	// refused outright until A14 — resolving the calling service's own
	// subject would answer for the wrong identity.
	ctx := principal.NewContext(aliceContext(t), &principal.Principal{Actor: "impersonated@example.com", Type: openapi.User})
	ctx = principal.NewImpersonateContext(ctx)

	err := fx.rbac.Check(ctx, rbac.Resource{Kind: "identity:groups", OrganizationID: parityOrgA}, openapi.Read)
	require.ErrorIs(t, err, rbac.ErrImpersonationNotSupported)
	require.Zero(t, pdp.calls, "an impersonated request must never reach the PDP")
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
