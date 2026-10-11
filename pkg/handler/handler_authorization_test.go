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
	"strings"
	"testing"
	"time"

	sdk "github.com/cerbos/cerbos-sdk-go/cerbos"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/require"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/handler"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/jose"
	josetesting "github.com/unikorn-cloud/identity/pkg/jose/testing"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// These tests pin the internal POST /api/v1/authorization/check handler.
// The handler is deliberately thin: its ONE security
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

	batches    []*sdk.ResourceBatch
	principals []*sdk.Principal
}

func (p *capturingPDP) CheckResources(_ context.Context, checkPrincipal *sdk.Principal, batch *sdk.ResourceBatch) (*sdk.CheckResourcesResponse, error) {
	p.batches = append(p.batches, batch)
	p.principals = append(p.principals, checkPrincipal)

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

// TestAuthorizationCheckIgnoresForgedPrincipalHeaders is the trust-boundary
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

const (
	passportUser    = "passport-user@example.com"
	passportSA      = "passport-sa"
	authzOtherOrgID = "authz-other-org-id"
	authzOrgNS      = "authz-org-ns"
	relayedCN       = "authz-relayed-cn"

	externalUser          = "external@example.com"
	misconfiguredIssuer   = "https://misconfigured.example.com/"
	unknownExternalIssuer = "https://external.example.com/"
)

var errStore = goerrors.New("store read failure")

func failGets[T client.Object]() interceptor.Funcs {
	return interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		if _, ok := obj.(T); ok {
			return errStore
		}

		return c.Get(ctx, key, obj, opts...)
	}}
}

func failLists[T client.ObjectList]() interceptor.Funcs {
	return interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
		if _, ok := list.(T); ok {
			return errStore
		}

		return c.List(ctx, list, opts...)
	}}
}

type passportHandlerEnv struct {
	handler   *handler.Handler
	jwtIssuer *jose.JWTIssuer
}

func newPassportHandler(t *testing.T, pdp rbac.PolicyDecisionPoint, funcs interceptor.Funcs) *passportHandlerEnv {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	objects := []client.Object{
		josetesting.SigningKey(t, authzNS),
		&unikornv1.Role{
			ObjectMeta: metav1.ObjectMeta{Namespace: authzNS, Name: authzRoleID},
			Spec: unikornv1.RoleSpec{Scopes: unikornv1.RoleScopes{
				Global: []unikornv1.RoleScope{{Name: "identity:groups", Operations: []unikornv1.Operation{unikornv1.Read}}},
			}},
		},
		&unikornv1.Organization{
			ObjectMeta: metav1.ObjectMeta{Namespace: authzNS, Name: authzOrgID},
			Status:     unikornv1.OrganizationStatus{Namespace: authzOrgNS},
		},
		&unikornv1.User{
			ObjectMeta: metav1.ObjectMeta{Namespace: authzNS, Name: "passport-user"},
			Spec:       unikornv1.UserSpec{Subject: passportUser, State: unikornv1.UserStateActive},
		},
		&unikornv1.OrganizationUser{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: authzOrgNS,
				Name:      "passport-org-user",
				Labels: map[string]string{
					coreconstants.UserLabel:         "passport-user",
					coreconstants.OrganizationLabel: authzOrgID,
				},
			},
			Spec: unikornv1.OrganizationUserSpec{State: unikornv1.UserStateActive},
		},
		&unikornv1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: authzOrgNS,
				Name:      passportSA,
				Labels:    map[string]string{coreconstants.OrganizationLabel: authzOrgID},
			},
		},
		&unikornv1.OAuth2Provider{
			ObjectMeta: metav1.ObjectMeta{Namespace: authzNS, Name: "misconfigured"},
			Spec: unikornv1.OAuth2ProviderSpec{
				Issuer:      misconfiguredIssuer,
				BearerTrust: &unikornv1.BearerTrustSpec{AllowExternalIdentity: true},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).WithInterceptorFuncs(funcs).Build()
	clientWithoutInterceptors := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

	r := rbac.New(c, authzNS, &rbac.Options{
		SystemAccountRoleIDs: map[string]string{authzSystemCN: authzRoleID, relayedCN: authzRoleID},
	}).WithCerbos(pdp)

	users := userdb.NewUserDatabase(c, authzNS)
	jwtIssuer := jose.NewJWTIssuer(c, authzNS, &jose.Options{})

	authenticator, err := oauth2.New(&oauth2.Options{TokenCacheSize: 1, CodeCacheSize: 1}, authzNS, handlercommon.IssuerValue{}, c, c, jwtIssuer, users, r)
	require.NoError(t, err)

	h, err := handler.New(c, c, authzNS, jwtIssuer, authenticator, users, r, &handler.Options{})
	require.NoError(t, err)

	return &passportHandlerEnv{handler: h, jwtIssuer: jose.NewJWTIssuer(clientWithoutInterceptors, authzNS, &jose.Options{})}
}

func testPassportClaims(subject string, accountType openapi.AuthClaimsAcctype, audience string) *oauth2.PassportClaims {
	now := time.Now()

	return &oauth2.PassportClaims{
		Claims: jwt.Claims{
			Issuer:    oauth2.PassportIssuer,
			Subject:   subject,
			Audience:  jwt.Audience{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(now.Add(oauth2.PassportTTL)),
		},
		Type:    oauth2.PassportType,
		Acctype: accountType,
		Source:  oauth2.PassportSourceUNI,
		SrcIss:  oauth2.PassportSourceUNI,
	}
}

func signTestPassport(tb testing.TB, issuer *jose.JWTIssuer, claims *oauth2.PassportClaims) string {
	tb.Helper()

	token, err := issuer.EncodeJWT(tb.Context(), claims)
	require.NoError(tb, err)

	return token
}

func (e *passportHandlerEnv) passportFor(t *testing.T, subject string, accountType openapi.AuthClaimsAcctype, audience, organizationID string) string {
	t.Helper()

	claims := testPassportClaims(subject, accountType, audience)
	claims.OrgIDs = []string{authzOrgID}
	claims.OrgID = organizationID

	return signTestPassport(t, e.jwtIssuer, claims)
}

func presenterContext(t *testing.T, commonName string, p *principal.Principal) context.Context {
	t.Helper()

	ctx := authorization.NewContext(t.Context(), &authorization.Info{
		SystemAccount: true,
		Userinfo: &openapi.Userinfo{
			Sub:                       commonName,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{Acctype: openapi.System},
		},
	})

	return principal.NewContext(ctx, p)
}

func userPrincipal(actor string) *principal.Principal {
	return &principal.Principal{Actor: actor, Type: openapi.User, Issuer: constants.UNISentinel}
}

func passportCheckBody(passport string, checks ...openapi.AuthorizationCheck) openapi.AuthorizationCheckRequest {
	if len(checks) == 0 {
		checks = []openapi.AuthorizationCheck{{
			Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(authzOrgID)},
			Action:   openapi.Read,
		}}
	}

	return openapi.AuthorizationCheckRequest{Checks: checks, Passport: &passport}
}

func allowGroupsRead() *sdk.CheckResourcesResponse {
	return authzPDPResponse(authzPDPResult(map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW}))
}

func responseKeys(t *testing.T, w *httptest.ResponseRecorder) map[string]json.RawMessage {
	t.Helper()

	var keys map[string]json.RawMessage

	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &keys))

	return keys
}

func TestAuthorizationCheckPassportDecidesForSubject(t *testing.T) {
	t.Parallel()

	pdp := &capturingPDP{response: allowGroupsRead()}
	env := newPassportHandler(t, pdp, interceptor.Funcs{})

	passport := env.passportFor(t, passportUser, openapi.User, authzSystemCN, "")

	w := doCheck(presenterContext(t, authzSystemCN, userPrincipal(passportUser)), t, env.handler, passportCheckBody(passport))
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var response openapi.AuthorizationCheckResponse

	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	require.Len(t, response.Results, 1)
	require.True(t, response.Results[0].Allowed)
	require.NotNil(t, response.PassportSubject, "the caller must be able to make sure that identity decided for the subject it sent")
	require.Equal(t, passportUser, *response.PassportSubject)

	require.Len(t, pdp.principals, 1, "a passport decision is one evaluation, with no service side")
	require.Equal(t, passportUser, pdp.principals[0].Obj.GetId(), "the decision must be for the passport subject, not the presenting service")
}

func TestAuthorizationCheckPassportWithImpersonation(t *testing.T) {
	t.Parallel()

	pdp := &capturingPDP{response: allowGroupsRead()}
	env := newPassportHandler(t, pdp, interceptor.Funcs{})

	passport := env.passportFor(t, passportUser, openapi.User, authzSystemCN, "")
	ctx := principal.NewImpersonateContext(presenterContext(t, authzSystemCN, userPrincipal(passportUser)))

	w := doCheck(ctx, t, env.handler, passportCheckBody(passport))

	require.Equal(t, http.StatusBadRequest, w.Code, "a passport with impersonation must be refused")
	require.Empty(t, pdp.batches, "a refused request must not reach the decision layer")
}

func TestAuthorizationCheckPassportRelayedCertificate(t *testing.T) {
	t.Parallel()

	pdp := &capturingPDP{response: allowGroupsRead()}
	env := newPassportHandler(t, pdp, interceptor.Funcs{})

	passport := env.passportFor(t, passportUser, openapi.User, relayedCN, "")

	w := doCheckWithHeaders(presenterContext(t, relayedCN, userPrincipal(passportUser)), t, env.handler, passportCheckBody(passport), map[string]string{
		authorization.ClientCertificateHeader: "relayed-certificate",
	})

	require.Equal(t, http.StatusBadRequest, w.Code, "the audience must bind to the TLS peer, not to a relayed certificate")
	require.Empty(t, pdp.batches)
}

func TestAuthorizationCheckPassportUnregisteredPresenter(t *testing.T) {
	t.Parallel()

	const unregisteredCN = "authz-unregistered-cn"

	failAll := interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errStore
		},
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errStore
		},
	}

	pdp := &capturingPDP{response: allowGroupsRead()}
	env := newPassportHandler(t, pdp, failAll)

	// The passport is valid and names the unregistered CN as its audience, so only the
	// presenter check can refuse it.  The direct form refuses the same CN.
	passport := signTestPassport(t, env.jwtIssuer, testPassportClaims(passportUser, openapi.User, unregisteredCN))

	w := doCheck(presenterContext(t, unregisteredCN, userPrincipal(passportUser)), t, env.handler, passportCheckBody(passport))

	require.Equal(t, http.StatusUnauthorized, w.Code, "a presenter with no system account role must be refused as a caller; body: %s", w.Body.String())
	require.JSONEq(t, `"passport is not valid"`, string(responseKeys(t, w)["error_description"]))
	require.NotContains(t, responseKeys(t, w), "passportSubject")
	require.Empty(t, pdp.batches, "a refused presenter must not reach the decision layer")
}

func TestAuthorizationCheckPassportFromBearer(t *testing.T) {
	t.Parallel()

	pdp := &capturingPDP{response: allowGroupsRead()}
	env := newPassportHandler(t, pdp, interceptor.Funcs{})

	passport := env.passportFor(t, passportUser, openapi.User, "user@example.com", "")

	w := doCheck(principal.NewContext(bearerContext(t), userPrincipal(passportUser)), t, env.handler, passportCheckBody(passport))

	require.Equal(t, http.StatusUnauthorized, w.Code, "a passport must not open the endpoint to a bearer caller")
	require.Empty(t, pdp.batches)
}

func TestAuthorizationCheckPassportPrincipalMismatch(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		accountType openapi.AuthClaimsAcctype
		subject     string
		principal   *principal.Principal
		wantStatus  int
	}{
		{name: "ActorMismatch", accountType: openapi.User, subject: passportUser, principal: userPrincipal("someone-else@example.com"), wantStatus: http.StatusUnauthorized},
		{name: "TypeMismatch", accountType: openapi.User, subject: passportUser, principal: &principal.Principal{Actor: passportUser, Type: openapi.Service, Issuer: constants.UNISentinel}, wantStatus: http.StatusUnauthorized},
		{name: "IssuerMismatch", accountType: openapi.User, subject: passportUser, principal: &principal.Principal{Actor: passportUser, Type: openapi.User, Issuer: "https://external.example.com/"}, wantStatus: http.StatusUnauthorized},
		{name: "UserCaseOnly", accountType: openapi.User, subject: passportUser, principal: userPrincipal(strings.ToUpper(passportUser)), wantStatus: http.StatusOK},
		{name: "ServiceCaseDiffers", accountType: openapi.Service, subject: passportSA, principal: &principal.Principal{Actor: strings.ToUpper(passportSA), Type: openapi.Service, Issuer: constants.UNISentinel}, wantStatus: http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pdp := &capturingPDP{response: allowGroupsRead()}
			env := newPassportHandler(t, pdp, interceptor.Funcs{})

			passport := env.passportFor(t, tc.subject, tc.accountType, authzSystemCN, "")

			w := doCheck(presenterContext(t, authzSystemCN, tc.principal), t, env.handler, passportCheckBody(passport))
			require.Equal(t, tc.wantStatus, w.Code, "body: %s", w.Body.String())

			if tc.wantStatus != http.StatusOK {
				require.Empty(t, pdp.batches, "an X-Principal that does not name the passport subject must not reach the decision layer")
			}
		})
	}
}

func TestAuthorizationCheckPassportScope(t *testing.T) {
	t.Parallel()

	allow := effectv1.Effect_EFFECT_ALLOW
	deny := effectv1.Effect_EFFECT_DENY

	// The canned PDP answers by position, so the verdict of each check is the
	// verdict of the subject, not a function of the passport scope.
	cases := []struct {
		name        string
		effects     []effectv1.Effect
		wantAllowed []bool
	}{
		{name: "SubjectHasRights", effects: []effectv1.Effect{allow, deny}, wantAllowed: []bool{true, false}},
		{name: "SubjectLacksRights", effects: []effectv1.Effect{deny, allow}, wantAllowed: []bool{false, true}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pdp := &capturingPDP{response: authzPDPResponse(
				authzPDPResult(map[string]effectv1.Effect{"read": tc.effects[0]}),
				authzPDPResult(map[string]effectv1.Effect{"read": tc.effects[1]}),
			)}
			env := newPassportHandler(t, pdp, interceptor.Funcs{})

			passport := env.passportFor(t, passportUser, openapi.User, authzSystemCN, authzOrgID)

			w := doCheck(presenterContext(t, authzSystemCN, userPrincipal(passportUser)), t, env.handler, passportCheckBody(passport,
				openapi.AuthorizationCheck{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(authzOtherOrgID)}, Action: openapi.Read},
				openapi.AuthorizationCheck{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(authzOrgID)}, Action: openapi.Read},
			))
			require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

			var response openapi.AuthorizationCheckResponse

			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			require.Len(t, response.Results, 2)
			require.Equal(t, tc.wantAllowed[0], response.Results[0].Allowed, "the passport organization must not limit a check in another organization")
			require.Equal(t, tc.wantAllowed[1], response.Results[1].Allowed)

			require.Len(t, pdp.batches, 1)
			require.Len(t, pdp.batches[0].Batch, 2, "every check must reach the PDP, whatever the passport scope")
		})
	}
}

func TestAuthorizationCheckPassportProjectScope(t *testing.T) {
	t.Parallel()

	allow := effectv1.Effect_EFFECT_ALLOW
	deny := effectv1.Effect_EFFECT_DENY

	cases := []struct {
		name        string
		effects     []effectv1.Effect
		wantAllowed []bool
	}{
		{name: "SubjectHasRights", effects: []effectv1.Effect{allow, deny}, wantAllowed: []bool{true, false}},
		{name: "SubjectLacksRights", effects: []effectv1.Effect{deny, allow}, wantAllowed: []bool{false, true}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pdp := &capturingPDP{response: authzPDPResponse(
				authzPDPResult(map[string]effectv1.Effect{"read": tc.effects[0]}),
				authzPDPResult(map[string]effectv1.Effect{"read": tc.effects[1]}),
			)}
			env := newPassportHandler(t, pdp, interceptor.Funcs{})

			claims := testPassportClaims(passportUser, openapi.User, authzSystemCN)
			claims.OrgIDs = []string{authzOrgID}
			claims.OrgID = authzOrgID
			claims.ProjectID = "passport-project"

			groups := func(projectID string) openapi.AuthorizationCheck {
				return openapi.AuthorizationCheck{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(authzOrgID), ProjectId: ptr.To(projectID)}, Action: openapi.Read}
			}

			w := doCheck(presenterContext(t, authzSystemCN, userPrincipal(passportUser)), t, env.handler,
				passportCheckBody(signTestPassport(t, env.jwtIssuer, claims), groups("other-project"), groups("passport-project")))
			require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

			require.Len(t, pdp.batches, 1)
			require.Len(t, pdp.batches[0].Batch, 2, "every check must reach the decision layer, whatever the passport project")

			var response openapi.AuthorizationCheckResponse

			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			require.Len(t, response.Results, 2)
			require.Equal(t, tc.wantAllowed[0], response.Results[0].Allowed, "the passport project must not limit a check for another project")
			require.Equal(t, tc.wantAllowed[1], response.Results[1].Allowed)
		})
	}
}

func TestAuthorizationCheckPassportSubjectOnlyOnPassportPath(t *testing.T) {
	t.Parallel()

	pdp := &capturingPDP{response: allowGroupsRead()}
	env := newPassportHandler(t, pdp, interceptor.Funcs{})

	direct := doCheck(presenterContext(t, authzSystemCN, &principal.Principal{Actor: authzSystemCN, Type: openapi.System}), t, env.handler, openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(authzOrgID)}, Action: openapi.Read}},
	})
	require.Equal(t, http.StatusOK, direct.Code, "body: %s", direct.Body.String())
	require.NotContains(t, responseKeys(t, direct), "passportSubject", "a direct decision must not name a passport subject")

	impersonated := doCheck(principal.NewImpersonateContext(presenterContext(t, authzSystemCN, userPrincipal(passportUser))), t, env.handler, openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(authzOrgID)}, Action: openapi.Read}},
	})
	require.Equal(t, http.StatusOK, impersonated.Code, "body: %s", impersonated.Body.String())
	require.NotContains(t, responseKeys(t, impersonated), "passportSubject", "an impersonated decision must not name a passport subject")

	passport := env.passportFor(t, passportUser, openapi.User, authzSystemCN, "")

	withPassport := doCheck(presenterContext(t, authzSystemCN, userPrincipal(passportUser)), t, env.handler, passportCheckBody(passport))
	require.Equal(t, http.StatusOK, withPassport.Code, "body: %s", withPassport.Body.String())
	require.Contains(t, responseKeys(t, withPassport), "passportSubject")
}

func TestAuthorizationCheckPassportSubjectState(t *testing.T) {
	t.Parallel()

	servicePrincipal := &principal.Principal{Actor: passportSA, Type: openapi.Service, Issuer: constants.UNISentinel}

	t.Run("LiveServiceAccount", func(t *testing.T) {
		t.Parallel()

		pdp := &capturingPDP{response: allowGroupsRead()}
		env := newPassportHandler(t, pdp, interceptor.Funcs{})

		w := doCheck(presenterContext(t, authzSystemCN, servicePrincipal), t, env.handler, passportCheckBody(env.passportFor(t, passportSA, openapi.Service, authzSystemCN, "")))
		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	})

	t.Run("DeletedServiceAccount", func(t *testing.T) {
		t.Parallel()

		pdp := &capturingPDP{response: allowGroupsRead()}
		env := newPassportHandler(t, pdp, interceptor.Funcs{})

		deleted := &principal.Principal{Actor: "deleted-sa", Type: openapi.Service, Issuer: constants.UNISentinel}

		w := doCheck(presenterContext(t, authzSystemCN, deleted), t, env.handler, passportCheckBody(env.passportFor(t, "deleted-sa", openapi.Service, authzSystemCN, "")))
		require.Equal(t, http.StatusUnauthorized, w.Code, "a passport for a deleted subject must be refused")
		require.Empty(t, pdp.batches)
	})

	t.Run("StoreFailure", func(t *testing.T) {
		t.Parallel()

		pdp := &capturingPDP{response: allowGroupsRead()}
		env := newPassportHandler(t, pdp, failGets[*unikornv1.ServiceAccount]())

		w := doCheck(presenterContext(t, authzSystemCN, servicePrincipal), t, env.handler, passportCheckBody(env.passportFor(t, passportSA, openapi.Service, authzSystemCN, "")))
		require.Equal(t, http.StatusInternalServerError, w.Code, "a store failure is an outage, not a refusal of the passport")
		require.Empty(t, pdp.batches)
	})
}

func TestAuthorizationCheckPassportRefusalsShareOneMessage(t *testing.T) {
	t.Parallel()

	pdp := &capturingPDP{response: allowGroupsRead()}
	env := newPassportHandler(t, pdp, interceptor.Funcs{})

	refusals := []*httptest.ResponseRecorder{
		doCheck(presenterContext(t, authzSystemCN, userPrincipal(passportUser)), t, env.handler,
			passportCheckBody(env.passportFor(t, passportUser, openapi.User, "another-service", ""))),
		doCheck(presenterContext(t, authzSystemCN, userPrincipal("someone-else@example.com")), t, env.handler,
			passportCheckBody(env.passportFor(t, passportUser, openapi.User, authzSystemCN, ""))),
		doCheck(presenterContext(t, authzSystemCN, &principal.Principal{Actor: "deleted-sa", Type: openapi.Service, Issuer: constants.UNISentinel}), t, env.handler,
			passportCheckBody(env.passportFor(t, "deleted-sa", openapi.Service, authzSystemCN, ""))),
	}

	for _, w := range refusals {
		require.Equal(t, http.StatusUnauthorized, w.Code, "body: %s", w.Body.String())
		require.JSONEq(t, `"passport is not valid"`, string(responseKeys(t, w)["error_description"]), "every passport refusal must give the same description")
	}
}

func externalPassport(t *testing.T, env *passportHandlerEnv, issuer string) (string, *principal.Principal) {
	t.Helper()

	claims := testPassportClaims(externalUser, openapi.User, authzSystemCN)
	claims.SrcIss = issuer

	return signTestPassport(t, env.jwtIssuer, claims), &principal.Principal{Actor: externalUser, Type: openapi.User, Issuer: issuer}
}

func TestAuthorizationCheckPassportImpersonateHeader(t *testing.T) {
	t.Parallel()

	pdp := &capturingPDP{response: allowGroupsRead()}
	env := newPassportHandler(t, pdp, interceptor.Funcs{})

	passport := env.passportFor(t, passportUser, openapi.User, authzSystemCN, "")

	w := doCheckWithHeaders(presenterContext(t, authzSystemCN, userPrincipal(passportUser)), t, env.handler, passportCheckBody(passport), map[string]string{
		principal.ImpersonateHeader: "true",
	})

	require.Equal(t, http.StatusBadRequest, w.Code, "a signed X-Principal sets no impersonation marker, so the header itself must refuse the passport")
	require.Empty(t, pdp.batches)
}

func TestAuthorizationCheckPassportDecisionRecordNamesPresenter(t *testing.T) {
	t.Parallel()

	env := newPassportHandler(t, &capturingPDP{response: allowGroupsRead()}, interceptor.Funcs{})

	var logged []string

	logger := funcr.NewJSON(func(obj string) { logged = append(logged, obj) }, funcr.Options{Verbosity: 1})

	w := doCheck(logr.NewContext(presenterContext(t, authzSystemCN, userPrincipal(passportUser)), logger), t, env.handler,
		passportCheckBody(env.passportFor(t, passportUser, openapi.User, authzSystemCN, "")))
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	require.Len(t, logged, 1)

	var line map[string]any

	require.NoError(t, json.Unmarshal([]byte(logged[0]), &line))
	require.Equal(t, passportUser, line["subject"], "the record is for the passport subject")
	require.Equal(t, authzSystemCN, line["passport_presenter"], "the record must name the service that presented the passport, not the subject")
}

func TestAuthorizationCheckPassportPrincipalMismatchLogsCause(t *testing.T) {
	t.Parallel()

	env := newPassportHandler(t, &capturingPDP{response: allowGroupsRead()}, interceptor.Funcs{})

	var logged []string

	logger := funcr.NewJSON(func(obj string) { logged = append(logged, obj) }, funcr.Options{})
	actor := &principal.Principal{Actor: passportUser, Type: openapi.Service, Issuer: unknownExternalIssuer}

	w := doCheck(logr.NewContext(presenterContext(t, authzSystemCN, actor), logger), t, env.handler,
		passportCheckBody(env.passportFor(t, passportUser, openapi.User, authzSystemCN, "")))
	require.Equal(t, http.StatusUnauthorized, w.Code, "body: %s", w.Body.String())
	require.Len(t, logged, 1)

	var line struct {
		Error string `json:"error"`
	}

	require.NoError(t, json.Unmarshal([]byte(logged[0]), &line))

	for _, want := range []string{`"service"`, `"` + unknownExternalIssuer + `"`, `"user"`, `"` + constants.UNISentinel + `"`} {
		require.Contains(t, line.Error, want, "the refusal log must name the type and issuer on both sides")
	}
}

func TestAuthorizationCheckPassportReadFailures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		funcs      interceptor.Funcs
		issuer     string
		service    bool
		wantStatus int
	}{
		{name: "SigningKeyUnreadable", funcs: failGets[*unikornv1.SigningKey](), wantStatus: http.StatusInternalServerError},
		{name: "TrustListNotReady", funcs: failLists[*unikornv1.OAuth2ProviderList](), issuer: unknownExternalIssuer, wantStatus: http.StatusInternalServerError},
		{name: "TrustConfigError", issuer: misconfiguredIssuer, wantStatus: http.StatusUnauthorized},
		{name: "OrganizationUnreadable", funcs: failGets[*unikornv1.Organization](), service: true, wantStatus: http.StatusInternalServerError},
		{name: "UserListUnreadable", funcs: failLists[*unikornv1.UserList](), wantStatus: http.StatusInternalServerError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pdp := &capturingPDP{response: allowGroupsRead()}
			env := newPassportHandler(t, pdp, tc.funcs)

			passport, actor := env.passportFor(t, passportUser, openapi.User, authzSystemCN, ""), userPrincipal(passportUser)
			if tc.issuer != "" {
				passport, actor = externalPassport(t, env, tc.issuer)
			}

			if tc.service {
				passport = env.passportFor(t, passportSA, openapi.Service, authzSystemCN, "")
				actor = &principal.Principal{Actor: passportSA, Type: openapi.Service, Issuer: constants.UNISentinel}
			}

			w := doCheck(presenterContext(t, authzSystemCN, actor), t, env.handler, passportCheckBody(passport))
			require.Equal(t, tc.wantStatus, w.Code, "body: %s", w.Body.String())
			require.Empty(t, pdp.batches)
		})
	}
}

func TestAuthorizationCheckPassportServiceAccountLookup(t *testing.T) {
	t.Parallel()

	pdp := &capturingPDP{response: allowGroupsRead()}
	env := newPassportHandler(t, pdp, failLists[*unikornv1.ServiceAccountList]())

	servicePrincipal := &principal.Principal{Actor: passportSA, Type: openapi.Service, Issuer: constants.UNISentinel}

	w := doCheck(presenterContext(t, authzSystemCN, servicePrincipal), t, env.handler, passportCheckBody(env.passportFor(t, passportSA, openapi.Service, authzSystemCN, "")))
	require.Equal(t, http.StatusOK, w.Code, "the check must read one service account by name, not list them all; body: %s", w.Body.String())
}

func TestAuthorizationCheckPassportFromCertificateBoundToken(t *testing.T) {
	t.Parallel()

	pdp := &capturingPDP{response: allowGroupsRead()}
	env := newPassportHandler(t, pdp, interceptor.Funcs{})

	ctx := authorization.NewContext(t.Context(), &authorization.Info{
		Token:         "certificate-bound-service-token",
		SystemAccount: true,
		Userinfo: &openapi.Userinfo{
			Sub:                       authzSystemCN,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{Acctype: openapi.System, OrgIds: []string{}},
		},
	})

	w := doCheck(principal.NewContext(ctx, userPrincipal(passportUser)), t, env.handler,
		passportCheckBody(env.passportFor(t, passportUser, openapi.User, authzSystemCN, "")))
	require.Equal(t, http.StatusOK, w.Code, "a bound service token has the certificate CN as its subject, so the audience check accepts it; body: %s", w.Body.String())
	require.Contains(t, responseKeys(t, w), "passportSubject")
}
