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
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	authorizer "github.com/unikorn-cloud/identity/pkg/middleware/openapi/remote"
	"github.com/unikorn-cloud/identity/pkg/mtlstest"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// These tests pin the remote authorizer's decision call (migration task A8):
// the wire contract with identity's /api/v1/authorization/check, fail-closed
// error mapping, result-order fidelity, and the credential/principal header
// forwarding it shares with GetACL.  They stand up an mTLS identity stub that
// speaks the generated wire contract directly — the decision layer itself is
// exercised by the handler and parity tests.

// checkHandler captures the request identity's decision endpoint received and
// serves a canned response.
type checkHandler struct {
	status int
	// results is the canned per-check response served on a 200.
	results []identityapi.AuthorizationCheckResult

	// delay, when set, sleeps before serving the response, simulating a slow
	// backend for timeout tests.
	delay time.Duration

	// captured request state, for header/absence assertions.
	gotAuthorization string
	gotPrincipal     string
	gotImpersonate   string
	gotBody          identityapi.AuthorizationCheckRequest

	// requests counts every ServeHTTP invocation, i.e. every actual HTTP
	// round trip that reached the transport. The circuit-breaker tests drive
	// CheckMany sequentially from a single goroutine and assert on this
	// between calls, so no synchronization is needed here.
	requests int
}

func (h *checkHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.requests++
	h.gotAuthorization = r.Header.Get("Authorization")
	h.gotPrincipal = r.Header.Get(principal.Header)
	h.gotImpersonate = r.Header.Get(principal.ImpersonateHeader)

	_ = json.NewDecoder(r.Body).Decode(&h.gotBody)

	if h.delay > 0 {
		time.Sleep(h.delay)
	}

	status := h.status
	if status == 0 {
		status = http.StatusOK
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if status == http.StatusOK {
		writeJSON(w, identityapi.AuthorizationCheckResponse{Results: h.results})

		return
	}

	// Error responses carry the core Error shape PropagateError renders.
	writeJSON(w, coreapi.Error{Error: coreapi.AccessDenied, ErrorDescription: "denied"})
}

// writeJSON encodes v to the response, ignoring the write error (the client
// side is what these tests assert; a broken pipe here would surface there).
func writeJSON(w http.ResponseWriter, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}

	_, _ = w.Write(body)
}

// newCheckAuthorizer stands up an mTLS server serving the decision endpoint
// with the given handler, plus a remote authorizer pointed at it.  It reuses
// the mtlstest CA/client-cert plumbing and the createRemoteAuthorizer/secret
// conventions the exchange tests exercise; the decision path needs no JWT or
// oauth2 wiring, so this is a deliberately minimal stand-up.
func newCheckAuthorizer(t *testing.T, h *checkHandler, opts ...authorizer.Option) *authorizer.Authorizer {
	t.Helper()

	mtlsServer, err := mtlstest.NewMTLSServer(h)
	require.NoError(t, err)
	t.Cleanup(mtlsServer.Close)

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	// The client-cert and ca-cert secrets the identity HTTP client mutator
	// reads for mTLS, keyed exactly as createIdentityOptions/createCoreClientOptions expect.
	clientCertSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "client-cert"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       mtlsServer.ClientCertPEM,
			corev1.TLSPrivateKeyKey: mtlsServer.ClientKeyPEM,
		},
	}

	caCertSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "ca-cert"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       mtlsServer.CACertPEM,
			corev1.TLSPrivateKeyKey: mtlsServer.CAKeyPEM,
		},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(clientCertSecret, caCertSecret).
		Build()

	return createRemoteAuthorizer(t, k8sClient, mtlsServer.URL(), opts...)
}

// checkAuthContext seeds the context a downstream call carries: a principal
// (for the injector) and authorization info with the given bearer token
// (empty for an mTLS-only system caller); impersonate rides the marker.
func checkAuthContext(t *testing.T, token string, impersonate bool) context.Context {
	t.Helper()

	p := &principal.Principal{Actor: "actor@example.com", Type: identityapi.User, OrganizationIDs: []string{"org-1"}}

	ctx := principal.NewContext(t.Context(), p)
	if impersonate {
		ctx = principal.NewImpersonateContext(ctx)
	}

	return authorization.NewContext(ctx, &authorization.Info{
		Token: token,
		Userinfo: &identityapi.Userinfo{
			Sub: "actor@example.com",
			HttpsunikornCloudOrgauthz: &identityapi.AuthClaims{
				Acctype: identityapi.User,
			},
		},
	})
}

// checkSystemAccountAuthContext seeds the context an AUTHENTICATED caller
// presents to AllowCoarseMany, keyed on authorization.Info.SystemAccount —
// the dimension Fix B triggers impersonation from (an mTLS system-account
// caller vs. a bearer caller), never the propagated X-Principal's Type. A
// principal is always set: the principal.Injector (pkg/principal/injector.go)
// requires one in context to emit any header, X-Impersonate included.
func checkSystemAccountAuthContext(t *testing.T, systemAccount bool) context.Context {
	t.Helper()

	p := &principal.Principal{Actor: "actor@example.com", Type: identityapi.User, OrganizationIDs: []string{"org-1"}}

	ctx := principal.NewContext(t.Context(), p)

	return authorization.NewContext(ctx, &authorization.Info{SystemAccount: systemAccount})
}

// TestRemoteCheckManyResultsInOrder pins the happy path: a batch of checks
// yields per-check bools in request order, mapped from identity's response.
func TestRemoteCheckManyResultsInOrder(t *testing.T) {
	t.Parallel()

	h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}, {Allowed: false}}}
	auth := newCheckAuthorizer(t, h)

	ctx := checkAuthContext(t, "", false)

	allowed, err := auth.CheckMany(ctx, []authorizer.CheckRequest{
		{Resource: authorizer.Resource{Kind: "identity:groups", OrganizationID: "org-1"}, Action: identityapi.Read},
		{Resource: authorizer.Resource{Kind: "identity:groups", OrganizationID: "org-1"}, Action: identityapi.Create},
	})

	require.NoError(t, err)
	require.Equal(t, []bool{true, false}, allowed)
}

// TestRemoteCheckManyAbsenceSemantics is the load-bearing wire assertion: a
// global check sends no organizationId/projectId, an org check sends
// organizationId but NO projectId, and a project check sends both.
func TestRemoteCheckManyAbsenceSemantics(t *testing.T) {
	t.Parallel()

	h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}, {Allowed: true}, {Allowed: true}}}
	auth := newCheckAuthorizer(t, h)

	ctx := checkAuthContext(t, "", false)

	_, err := auth.CheckMany(ctx, []authorizer.CheckRequest{
		{Resource: authorizer.Resource{Kind: "identity:groups"}, Action: identityapi.Read},
		{Resource: authorizer.Resource{Kind: "identity:groups", OrganizationID: "org-1"}, Action: identityapi.Read},
		{Resource: authorizer.Resource{Kind: "compute:clusters", OrganizationID: "org-1", ProjectID: "proj-1"}, Action: identityapi.Read},
	})
	require.NoError(t, err)

	require.Len(t, h.gotBody.Checks, 3)

	global := h.gotBody.Checks[0].Resource
	require.Nil(t, global.OrganizationId, "a global check must send no organizationId")
	require.Nil(t, global.ProjectId, "a global check must send no projectId")

	org := h.gotBody.Checks[1].Resource
	require.NotNil(t, org.OrganizationId)
	require.Equal(t, "org-1", *org.OrganizationId)
	require.Nil(t, org.ProjectId, "an org check must send NO projectId (no flow-up)")

	project := h.gotBody.Checks[2].Resource
	require.NotNil(t, project.OrganizationId)
	require.Equal(t, "org-1", *project.OrganizationId)
	require.NotNil(t, project.ProjectId)
	require.Equal(t, "proj-1", *project.ProjectId)
}

// TestRemoteCheckManyForwardsPrincipal proves the principal is injected on the
// wire (attribution), and the impersonation marker rides when set.
func TestRemoteCheckManyForwardsPrincipal(t *testing.T) {
	t.Parallel()

	h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}}}
	auth := newCheckAuthorizer(t, h)

	ctx := checkAuthContext(t, "", true)

	_, err := auth.CheckMany(ctx, []authorizer.CheckRequest{
		{Resource: authorizer.Resource{Kind: "identity:groups", OrganizationID: "org-1"}, Action: identityapi.Read},
	})
	require.NoError(t, err)

	require.NotEmpty(t, h.gotPrincipal, "the principal must be injected for attribution")
	require.Equal(t, "true", h.gotImpersonate, "the impersonation marker must ride when set")
}

// TestRemoteCheckManyNeverForwardsBearer proves the check-endpoint client never
// sends an Authorization header — even when the request context carries a user
// bearer.  The endpoint is system-account-only and 401s any bearer
// (handler.PostApiV1AuthorizationCheck; TestRemoteAuthorizationCheckRejectsBearer);
// the caller is authenticated by mTLS and the acting user is conveyed by
// X-Principal, so forwarding the user's token would break every check.  This is
// why CheckMany diverges from GetACL, which DOES forward the bearer.
func TestRemoteCheckManyNeverForwardsBearer(t *testing.T) {
	t.Parallel()

	t.Run("a user bearer in context is not forwarded", func(t *testing.T) {
		t.Parallel()

		h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}}}
		auth := newCheckAuthorizer(t, h)

		// The realistic downstream shape: a live user request whose context
		// carries the user's bearer.  It must NOT reach the check endpoint.
		ctx := checkAuthContext(t, "the-bearer-token", false)

		_, err := auth.CheckMany(ctx, []authorizer.CheckRequest{
			{Resource: authorizer.Resource{Kind: "identity:groups", OrganizationID: "org-1"}, Action: identityapi.Read},
		})
		require.NoError(t, err)

		require.Empty(t, h.gotAuthorization, "a user bearer must never be forwarded to the system-account-only check endpoint (it would 401)")
		require.NotEmpty(t, h.gotPrincipal, "the acting user must still be conveyed via X-Principal")
	})

	t.Run("mtls only forwards no bearer", func(t *testing.T) {
		t.Parallel()

		h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}}}
		auth := newCheckAuthorizer(t, h)

		ctx := checkAuthContext(t, "", false)

		_, err := auth.CheckMany(ctx, []authorizer.CheckRequest{
			{Resource: authorizer.Resource{Kind: "identity:groups", OrganizationID: "org-1"}, Action: identityapi.Read},
		})
		require.NoError(t, err)

		require.Empty(t, h.gotAuthorization, "an mTLS-only caller must forward no bearer")
	})
}

// TestRemoteCheckManyFailClosed pins the fail-closed error mapping: a 5xx maps
// to ErrDecisionUnavailable, a 401 propagates (non-nil error the caller treats
// as deny), and a result-count mismatch is unavailability.
func TestRemoteCheckManyFailClosed(t *testing.T) {
	t.Parallel()

	t.Run("5xx is unavailable", func(t *testing.T) {
		t.Parallel()

		h := &checkHandler{status: http.StatusInternalServerError}
		auth := newCheckAuthorizer(t, h)

		ctx := checkAuthContext(t, "", false)

		allowed, err := auth.CheckMany(ctx, []authorizer.CheckRequest{
			{Resource: authorizer.Resource{Kind: "identity:groups", OrganizationID: "org-1"}, Action: identityapi.Read},
		})
		require.ErrorIs(t, err, authorizer.ErrDecisionUnavailable)
		require.Nil(t, allowed)
	})

	t.Run("401 is a non-nil deny", func(t *testing.T) {
		t.Parallel()

		h := &checkHandler{status: http.StatusUnauthorized}
		auth := newCheckAuthorizer(t, h)

		ctx := checkAuthContext(t, "", false)

		allowed, err := auth.CheckMany(ctx, []authorizer.CheckRequest{
			{Resource: authorizer.Resource{Kind: "identity:groups", OrganizationID: "org-1"}, Action: identityapi.Read},
		})
		require.Error(t, err)
		require.Nil(t, allowed)
	})

	t.Run("result count mismatch is unavailable", func(t *testing.T) {
		t.Parallel()

		// Two checks requested, one result returned.
		h := &checkHandler{results: []identityapi.AuthorizationCheckResult{{Allowed: true}}}
		auth := newCheckAuthorizer(t, h)

		ctx := checkAuthContext(t, "", false)

		allowed, err := auth.CheckMany(ctx, []authorizer.CheckRequest{
			{Resource: authorizer.Resource{Kind: "identity:groups", OrganizationID: "org-1"}, Action: identityapi.Read},
			{Resource: authorizer.Resource{Kind: "identity:groups", OrganizationID: "org-1"}, Action: identityapi.Create},
		})
		require.ErrorIs(t, err, authorizer.ErrDecisionUnavailable)
		require.Nil(t, allowed)
	})
}
