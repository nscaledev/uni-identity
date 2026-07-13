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

package handler_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	goerrors "errors"
	"net/http"
	"net/http/httptest"
	"testing"

	sdk "github.com/cerbos/cerbos-sdk-go/cerbos"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// These tests pin the internal POST /api/v1/authorization/check handler
// (migration task A8).  The handler is deliberately thin: its ONE security
// obligation is rejecting non-system-account (bearer) callers before any
// decision runs — the oauth2 scheme multiplexes bearer and mTLS onto the same
// route, so a bearer token reaches this route and must be refused here.  Every
// other behaviour (dual check, decision records, metrics) is inherited from
// rbac.CheckMany off the context the middleware already builds, so the tests
// drive the handler with a fakePDP-backed real RBAC and assert the wire
// contract: the SystemAccount gate, verbatim wire->CheckRequest mapping
// (crucially absence semantics — an org-only check must carry NO project
// attribute anywhere down the chain), per-check results in request order, and
// the fail-closed 5xx / 400 mappings.

const (
	authzSystemCN = "authz-system-cn"
	authzOrgID    = "authz-org-id"
	authzRoleID   = "authz-global-admin"
	authzNS       = "authz-identity-ns"
)

// errAuthzPDP is the static PDP transport failure the batch-failure test
// injects (err113 forbids a dynamic error at the call site).
var errAuthzPDP = goerrors.New("pdp transport failure")

// capturingPDP is a canned PolicyDecisionPoint that records the batch it was
// asked to evaluate so the handler's wire->request mapping (absence semantics
// included) can be asserted through the real CheckMany code path.
type capturingPDP struct {
	response *sdk.CheckResourcesResponse
	err      error

	batches []*sdk.ResourceBatch
}

func (p *capturingPDP) CheckResources(_ context.Context, _ *sdk.Principal, batch *sdk.ResourceBatch) (*sdk.CheckResourcesResponse, error) {
	p.batches = append(p.batches, batch)

	if p.err != nil {
		return nil, p.err
	}

	return p.response, nil
}

// authzPDPResult builds one positional result entry echoing the checked
// resource (always the coarse identity:groups kind / "*" id in these tests,
// since what each check allows is the canned effect, not policy), with the
// given per-action effects.
func authzPDPResult(actions map[string]effectv1.Effect) *responsev1.CheckResourcesResponse_ResultEntry {
	return &responsev1.CheckResourcesResponse_ResultEntry{
		Resource: &responsev1.CheckResourcesResponse_ResultEntry_Resource{Kind: "identity:groups", Id: "*"},
		Actions:  actions,
	}
}

func authzPDPResponse(results ...*responsev1.CheckResourcesResponse_ResultEntry) *sdk.CheckResourcesResponse {
	return &sdk.CheckResourcesResponse{
		CheckResourcesResponse: &responsev1.CheckResourcesResponse{Results: results},
	}
}

// newAuthzHandler builds a Handler backed by a real RBAC over a fake client
// holding one system-account CN with a global-admin role, and attaches the
// supplied PDP.  The system account resolves to a single global binding, so
// what each check allows is entirely the PDP's canned response — the handler
// under test does not depend on policy content, only on the mapping and gate.
func newAuthzHandler(t *testing.T, pdp rbac.PolicyDecisionPoint) *handler.Handler {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	role := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: authzNS, Name: authzRoleID},
		Spec: unikornv1.RoleSpec{Scopes: unikornv1.RoleScopes{
			Global: []unikornv1.RoleScope{{
				Name:       "identity:groups",
				Operations: []unikornv1.Operation{unikornv1.Read, unikornv1.Create},
			}},
		}},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(role).Build()

	r := rbac.New(c, authzNS, &rbac.Options{
		SystemAccountRoleIDs: map[string]string{authzSystemCN: authzRoleID},
	})

	if pdp != nil {
		r.WithCerbos(pdp)
	}

	h, err := handler.New(c, c, authzNS, nil, nil, nil, r, &handler.Options{})
	require.NoError(t, err)

	return h
}

// systemContext seeds the authorization info the mTLS middleware yields for a
// system account (SystemAccount true, Acctype System) — the only shape this
// endpoint accepts.
func systemContext(t *testing.T) context.Context {
	t.Helper()

	return authorization.NewContext(t.Context(), &authorization.Info{
		SystemAccount: true,
		Userinfo: &openapi.Userinfo{
			Sub: authzSystemCN,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.System,
			},
		},
	})
}

// bearerContext seeds the authorization info a bearer-authenticated user
// yields (SystemAccount false) — a caller this endpoint must reject.
func bearerContext(t *testing.T) context.Context {
	t.Helper()

	return authorization.NewContext(t.Context(), &authorization.Info{
		Token: "a-bearer-token",
		Userinfo: &openapi.Userinfo{
			Sub: "user@example.com",
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.User,
			},
		},
	})
}

// doCheck serializes the request body, dispatches the handler in the given
// context, and returns the recorder.
func doCheck(ctx context.Context, t *testing.T, h *handler.Handler, body openapi.AuthorizationCheckRequest) *httptest.ResponseRecorder {
	t.Helper()

	raw, err := json.Marshal(body)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/authorization/check", bytes.NewReader(raw))

	h.PostApiV1AuthorizationCheck(w, r)

	return w
}

// doCheckWithHeaders is doCheck with caller-controlled request headers, used to
// plant forged principal-propagation headers on the wire request and prove the
// handler derives no trust from them.
func doCheckWithHeaders(ctx context.Context, t *testing.T, h *handler.Handler, body openapi.AuthorizationCheckRequest, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	raw, err := json.Marshal(body)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/authorization/check", bytes.NewReader(raw))

	for k, v := range headers {
		r.Header.Set(k, v)
	}

	h.PostApiV1AuthorizationCheck(w, r)

	return w
}

// forgedPrincipalHeader base64url-encodes a principal so a test can plant a
// caller-supplied X-Principal on the wire request, exactly as a malicious client
// would.
func forgedPrincipalHeader(t *testing.T, actor string) string {
	t.Helper()

	raw, err := json.Marshal(&principal.Principal{Actor: actor})
	require.NoError(t, err)

	return base64.RawURLEncoding.EncodeToString(raw)
}

// TestAuthorizationCheckRejectsBearer is the mTLS-only guarantee: a
// bearer-authenticated caller (SystemAccount false) is refused with a 401
// BEFORE any decision is attempted.  A nil PDP proves no CheckMany call ran:
// were the gate skipped, CheckMany would fail-closed with 500, not 401.
func TestAuthorizationCheckRejectsBearer(t *testing.T) {
	t.Parallel()

	pdp := &capturingPDP{}
	h := newAuthzHandler(t, pdp)

	w := doCheck(bearerContext(t), t, h, openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{{
			Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups"},
			Action:   openapi.Read,
		}},
	})

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Empty(t, pdp.batches, "the decision layer must not be consulted for a rejected caller")
}

// TestAuthorizationCheckIgnoresForgedPrincipalHeaders is the A18 trust-boundary
// regression guard for the decision endpoint.  The system-account gate is
// established by the middleware from the VERIFIED transport identity (the mTLS
// peer CN, or a cert-bound service token) and carried on the context as
// authorization.Info — NEVER from headers on the wire request.  A non-system
// (bearer) caller that plants a forged X-Principal naming a system account, plus
// X-Impersonate:true, must therefore still be refused with a 401 and must never
// reach the decision layer.
//
// WHY this matters: the endpoint's ONE security obligation is the SystemAccount
// gate; were the handler to derive that (or the acting identity) from
// caller-supplied X-Principal/X-Impersonate, a forged header would spoof a system
// account and reach Cerbos — the exact escalation the mTLS + ingress
// header-stripping boundary exists to prevent.  A nil PDP confirms no CheckMany
// ran: the forged headers gained nothing.
func TestAuthorizationCheckIgnoresForgedPrincipalHeaders(t *testing.T) {
	t.Parallel()

	pdp := &capturingPDP{}
	h := newAuthzHandler(t, pdp)

	w := doCheckWithHeaders(bearerContext(t), t, h, openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{{
			Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups"},
			Action:   openapi.Read,
		}},
	}, map[string]string{
		// The propagation headers a trusted mTLS peer would set, here forged by a
		// bearer caller: an X-Principal impersonating the system account CN and the
		// impersonation marker.
		principal.Header:            forgedPrincipalHeader(t, authzSystemCN),
		principal.ImpersonateHeader: "true",
	})

	require.Equal(t, http.StatusUnauthorized, w.Code, "a forged principal header must not satisfy the system-account gate")
	require.Empty(t, pdp.batches, "a forged principal header must not reach the decision layer")
}

// TestAuthorizationCheckMissingInfo covers a request with no authorization
// info in context at all (no middleware ran): it must fail closed, never
// treat the absence as a system caller.
func TestAuthorizationCheckMissingInfo(t *testing.T) {
	t.Parallel()

	pdp := &capturingPDP{}
	h := newAuthzHandler(t, pdp)

	w := doCheck(t.Context(), t, h, openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{{
			Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups"},
			Action:   openapi.Read,
		}},
	})

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Empty(t, pdp.batches)
}

// TestAuthorizationCheckResultsInOrder pins the happy path: a system caller
// gets per-check results in REQUEST ORDER, an allow and a deny, at HTTP 200.
func TestAuthorizationCheckResultsInOrder(t *testing.T) {
	t.Parallel()

	// The PDP allows identity:groups read, denies identity:groups create.
	pdp := &capturingPDP{response: authzPDPResponse(
		authzPDPResult(map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}),
		authzPDPResult(map[string]effectv1.Effect{"create": effectv1.Effect_EFFECT_DENY}),
	)}
	h := newAuthzHandler(t, pdp)

	w := doCheck(systemContext(t), t, h, openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{
			{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(authzOrgID)}, Action: openapi.Read},
			{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(authzOrgID)}, Action: openapi.Create},
		},
	})

	require.Equal(t, http.StatusOK, w.Code)

	var response openapi.AuthorizationCheckResponse

	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

	require.Len(t, response.Results, 2)
	require.True(t, response.Results[0].Allowed, "identity:groups read must be allowed")
	require.False(t, response.Results[1].Allowed, "identity:groups create must be denied")
}

// TestAuthorizationCheckAbsenceSemantics is the load-bearing wire test: an
// ORG-scope check (organizationId present, projectId omitted) must reach the
// PDP with the organization attribute set and NO project attribute at all — a
// present-but-empty project would let project-scoped bindings flow up.  A
// GLOBAL check (both omitted) must carry NO scope attributes.  The handler
// must set OrganizationID/ProjectID on the rbac.CheckRequest only when the
// JSON field is present.
func TestAuthorizationCheckAbsenceSemantics(t *testing.T) {
	t.Parallel()

	pdp := &capturingPDP{response: authzPDPResponse(
		authzPDPResult(map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}),
		authzPDPResult(map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}),
	)}
	h := newAuthzHandler(t, pdp)

	w := doCheck(systemContext(t), t, h, openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{
			// Global check: organizationId omitted.
			{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups"}, Action: openapi.Read},
			// Org check: organizationId present, projectId omitted.
			{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(authzOrgID)}, Action: openapi.Read},
		},
	})

	require.Equal(t, http.StatusOK, w.Code)

	require.Len(t, pdp.batches, 1, "one batched CheckResources call for the whole request")
	entries := pdp.batches[0].Batch
	require.Len(t, entries, 2)

	globalAttrs := entries[0].GetResource().GetAttr()
	require.NotContains(t, globalAttrs, "organization", "a global check must carry no organization attribute")
	require.NotContains(t, globalAttrs, "project", "a global check must carry no project attribute")

	orgAttrs := entries[1].GetResource().GetAttr()
	require.Contains(t, orgAttrs, "organization", "an org check must carry the organization attribute")
	require.Equal(t, authzOrgID, orgAttrs["organization"].GetStringValue())
	require.NotContains(t, orgAttrs, "project", "an org check must carry NO project attribute (no flow-up)")
}

// TestAuthorizationCheckProjectScope confirms a project-scope check (both IDs
// present) reaches the PDP with both attributes set.
func TestAuthorizationCheckProjectScope(t *testing.T) {
	t.Parallel()

	pdp := &capturingPDP{response: authzPDPResponse(
		authzPDPResult(map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}),
	)}
	h := newAuthzHandler(t, pdp)

	w := doCheck(systemContext(t), t, h, openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{
			{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(authzOrgID), ProjectId: ptr.To("authz-project")}, Action: openapi.Read},
		},
	})

	require.Equal(t, http.StatusOK, w.Code)

	entries := pdp.batches[0].Batch
	require.Len(t, entries, 1)

	attrs := entries[0].GetResource().GetAttr()
	require.Equal(t, authzOrgID, attrs["organization"].GetStringValue())
	require.Equal(t, "authz-project", attrs["project"].GetStringValue())
}

// TestAuthorizationCheckBatchFailure covers a batch-level failure
// (ErrDecisionUnavailable): the PDP transport errors, so every check denies
// and the caller MUST see a non-200 (500) they treat as deny — never a
// partial or allow.
func TestAuthorizationCheckBatchFailure(t *testing.T) {
	t.Parallel()

	pdp := &capturingPDP{err: errAuthzPDP}
	h := newAuthzHandler(t, pdp)

	w := doCheck(systemContext(t), t, h, openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{{
			Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(authzOrgID)},
			Action:   openapi.Read,
		}},
	})

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestAuthorizationCheckEmptyBatch covers an empty checks array: CheckMany
// errors on empty batches, and minItems on the wire schema is enforced by the
// validator middleware, but the handler must also fail safely (never 200 with
// an empty result) — a batch-level failure maps to 500.  (A live request is
// rejected 400 by the validator before reaching the handler; this asserts the
// handler is not a silent-success hole if reached directly.)
func TestAuthorizationCheckEmptyBatch(t *testing.T) {
	t.Parallel()

	pdp := &capturingPDP{}
	h := newAuthzHandler(t, pdp)

	w := doCheck(systemContext(t), t, h, openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{},
	})

	require.NotEqual(t, http.StatusOK, w.Code)
	require.Empty(t, pdp.batches)
}

// TestAuthorizationCheckAcceptsServiceBearer pins that the gate is the account
// TYPE, not the transport: a certificate-bound service ("svc") bearer token
// resolves to SystemAccount=true (the same trust tier as an mTLS peer, after
// proof-of-possession of the bound client certificate) and MUST be accepted,
// even though it arrives as a bearer. The endpoint refuses only NON-system
// callers, not all bearer-authenticated ones — closing the gap where the
// earlier tests conflated "bearer" with "non-system".
func TestAuthorizationCheckAcceptsServiceBearer(t *testing.T) {
	t.Parallel()

	pdp := &capturingPDP{response: authzPDPResponse(
		authzPDPResult(map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}),
	)}
	h := newAuthzHandler(t, pdp)

	// The svc-bearer shape: SystemAccount true (as the authorizer sets after
	// verifying the bound cert) AND a bearer Token present — unlike
	// systemContext (mTLS peer, empty Token).
	ctx := authorization.NewContext(t.Context(), &authorization.Info{
		SystemAccount: true,
		Token:         "a-cert-bound-svc-token",
		Userinfo: &openapi.Userinfo{
			Sub: authzSystemCN,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.System,
			},
		},
	})

	w := doCheck(ctx, t, h, openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{{
			Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups"},
			Action:   openapi.Read,
		}},
	})

	require.Equal(t, http.StatusOK, w.Code, "a system account arriving via a bearer token must be accepted")
	require.NotEmpty(t, pdp.batches, "the decision layer must be consulted for an accepted system-account caller")
}

// TestAuthorizationCheckProjectWithoutOrg pins the cross-field guard: a check
// carrying projectId but not organizationId is a client error (400). The
// OpenAPI 3.0 schema cannot express the dependency (kin-openapi ignores
// `dependencies`), so the handler rejects it rather than letting it surface as
// a 500 from cerbos.BuildResource. Fail-closed either way — this pins the
// correct status classification and that the decision layer is never consulted.
func TestAuthorizationCheckProjectWithoutOrg(t *testing.T) {
	t.Parallel()

	pdp := &capturingPDP{}
	h := newAuthzHandler(t, pdp)

	w := doCheck(systemContext(t), t, h, openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{{
			Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", ProjectId: ptr.To("authz-project")},
			Action:   openapi.Read,
		}},
	})

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Empty(t, pdp.batches, "a malformed check must be rejected before the decision layer")
}
