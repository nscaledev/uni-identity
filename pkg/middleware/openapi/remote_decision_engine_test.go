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

package openapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/local"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/mock"
	remoteauthorizer "github.com/unikorn-cloud/identity/pkg/middleware/openapi/remote"
	"github.com/unikorn-cloud/identity/pkg/mtlstest"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// These tests pin Task 8 of the downstream remote-authorization seam (Cut #1,
// docs/plans/2026-07-14-downstream-remote-authorization-cut1.md): the
// middleware seeds a remote rbac.CoarseEngine (and its rbac.RemoteMode) into
// the handler context when -- and only when -- its Authorizer optionally
// implements RemoteDecisionEngineProvider with a non-nil engine.  This is the
// sibling of the TestDecisionEngineSeeded* tests above for the LOCAL seed
// block: same assertion-not-widening rationale, mirrored for the remote seam.

const remoteSeedTestNamespace = "remote-seed-test"

// checkStub serves a canned per-check verdict from a stubbed
// /api/v1/authorization/check endpoint and counts how many times it was
// consulted, so tests can prove whether the remote engine was actually
// dispatched to.
type checkStub struct {
	allowed bool
	calls   atomic.Int32
}

func (s *checkStub) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	s.calls.Add(1)

	body, err := json.Marshal(identityapi.AuthorizationCheckResponse{
		Results: []identityapi.AuthorizationCheckResult{{Allowed: s.allowed}},
	})
	if err != nil {
		panic(err)
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// newRemoteAuthorizerForSeedTest stands up a real *remote.Authorizer against
// the stubbed check endpoint over mTLS -- mirroring
// pkg/middleware/openapi/remote's own newCheckAuthorizer/createRemoteAuthorizer
// fixtures (the decision path needs no JWT/oauth2 wiring, so this is a
// deliberately minimal stand-up) -- configured with whatever opts the test
// supplies (e.g. WithRemoteEngineMode).
func newRemoteAuthorizerForSeedTest(t *testing.T, stub *checkStub, opts ...remoteauthorizer.Option) *remoteauthorizer.Authorizer {
	t.Helper()

	mtlsServer, err := mtlstest.NewMTLSServer(stub)
	require.NoError(t, err)
	t.Cleanup(mtlsServer.Close)

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	clientCertSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: remoteSeedTestNamespace, Name: "client-cert"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       mtlsServer.ClientCertPEM,
			corev1.TLSPrivateKeyKey: mtlsServer.ClientKeyPEM,
		},
	}

	caCertSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: remoteSeedTestNamespace, Name: "ca-cert"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       mtlsServer.CACertPEM,
			corev1.TLSPrivateKeyKey: mtlsServer.CAKeyPEM,
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(clientCertSecret, caCertSecret).Build()

	identityFlags := pflag.NewFlagSet("remote-seed-test-identity", pflag.PanicOnError)
	identityOptions := identityclient.NewOptions()
	identityOptions.AddFlags(identityFlags)
	require.NoError(t, identityFlags.Set("identity-host", mtlsServer.URL()))
	require.NoError(t, identityFlags.Set("identity-ca-secret-namespace", remoteSeedTestNamespace))
	require.NoError(t, identityFlags.Set("identity-ca-secret-name", "ca-cert"))

	clientFlags := pflag.NewFlagSet("remote-seed-test-client", pflag.PanicOnError)
	clientOptions := &coreclient.HTTPClientOptions{}
	clientOptions.AddFlags(clientFlags)
	require.NoError(t, clientFlags.Set("client-certificate-namespace", remoteSeedTestNamespace))
	require.NoError(t, clientFlags.Set("client-certificate-name", "client-cert"))

	a, err := remoteauthorizer.NewAuthorizer(k8sClient, identityOptions, clientOptions, opts...)
	require.NoError(t, err)

	return a
}

// remoteProviderAuthorizer wraps a mocked openapi.Authorizer (handling
// Authorize/GetACL, exactly like providerAuthorizer above) with a REAL
// remote.Authorizer's RemoteDecisionEngine/RemoteEngineMode, so the test
// exercises the actual WithRemoteEngineMode-configured provider methods
// without needing to also drive the remote authorizer's own token-exchange
// path.
type remoteProviderAuthorizer struct {
	openapi.Authorizer

	remote *remoteauthorizer.Authorizer
}

func (p *remoteProviderAuthorizer) RemoteDecisionEngine() rbac.CoarseEngine {
	return p.remote.RemoteDecisionEngine()
}

func (p *remoteProviderAuthorizer) RemoteEngineMode() rbac.RemoteMode {
	return p.remote.RemoteEngineMode()
}

var _ openapi.RemoteDecisionEngineProvider = &remoteProviderAuthorizer{}

// allowRecordingHandler records the outcome of an Allow* call made against
// the request context that reaches the handler, so a test can distinguish a
// remote-authoritative verdict from the legacy (empty-ACL, deny) one.
type allowRecordingHandler struct {
	called bool
	err    error
}

func (h *allowRecordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
	h.err = rbac.AllowGlobalScope(r.Context(), "identity:groups", identityapi.Read)

	w.WriteHeader(http.StatusOK)
}

// serveAllowCheck drives one authenticated bearer-token request through the
// middleware to a handler that calls AllowGlobalScope, and returns what it
// observed.
func serveAllowCheck(t *testing.T, authorizer openapi.Authorizer) *allowRecordingHandler {
	t.Helper()

	h := &allowRecordingHandler{}
	m := getEngineMux(t, authorizer, h)

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)

	addAuthorizationHeader(t, r)

	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Result().StatusCode)
	require.True(t, h.called)

	return h
}

// TestRemoteDecisionEngineSeededFromProviderInEnforceMode proves the seed
// reached the handler context: with the remote authorizer constructed via
// WithRemoteEngineMode(rbac.RemoteEnforce), the handler's AllowGlobalScope
// call is served by the remote engine's ALLOW verdict even though the (empty)
// ACL the legacy path would consult denies everything -- so the success can
// only be explained by dispatchCoarse having taken the remote-enforce branch.
func TestRemoteDecisionEngineSeededFromProviderInEnforceMode(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	mockAuth := mock.NewMockAuthorizer(c)
	mockAuth.EXPECT().Authorize(gomock.Any()).Return(authInfoFixture(engineActor, identityapi.User), nil)
	mockAuth.EXPECT().GetACL(gomock.Any(), gomock.Any()).Return(&identityapi.Acl{}, nil)

	stub := &checkStub{allowed: true}
	remoteAuth := newRemoteAuthorizerForSeedTest(t, stub, remoteauthorizer.WithRemoteEngineMode(rbac.RemoteEnforce))

	h := serveAllowCheck(t, &remoteProviderAuthorizer{Authorizer: mockAuth, remote: remoteAuth})

	require.NoError(t, h.err, "the remote engine's allow verdict must be served even though the (empty) ACL would deny under the legacy path")
	require.Equal(t, int32(1), stub.calls.Load(), "the remote engine must have been consulted exactly once")
}

// TestRemoteDecisionEngineDefaultModeFallsThroughToLegacy proves the default
// (no WithRemoteEngineMode option, so the zero value rbac.RemoteOff) is
// harmless: even though RemoteDecisionEngine() unconditionally returns a
// non-nil engine and gets seeded, dispatchCoarse must fall through to the
// legacy path without ever consulting the remote engine -- preserving
// today's behavior for every existing remote-authorizer caller.
func TestRemoteDecisionEngineDefaultModeFallsThroughToLegacy(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	mockAuth := mock.NewMockAuthorizer(c)
	mockAuth.EXPECT().Authorize(gomock.Any()).Return(authInfoFixture(engineActor, identityapi.User), nil)
	mockAuth.EXPECT().GetACL(gomock.Any(), gomock.Any()).Return(&identityapi.Acl{}, nil)

	stub := &checkStub{allowed: true}
	remoteAuth := newRemoteAuthorizerForSeedTest(t, stub) // no WithRemoteEngineMode: defaults to RemoteOff

	h := serveAllowCheck(t, &remoteProviderAuthorizer{Authorizer: mockAuth, remote: remoteAuth})

	require.Error(t, h.err, "RemoteOff must fall through to the legacy path, which denies an empty ACL")
	require.Zero(t, stub.calls.Load(), "RemoteOff must never consult the remote engine")
}

// TestLocalAuthorizerDoesNotImplementRemoteDecisionEngineProvider is the
// runtime negative counterpart to the compile-time
// `var _ openapi.DecisionEngineProvider = (*local.Authorizer)(nil)` assertion
// above: local must NOT ALSO satisfy the remote provider interface, or a
// deployment using it would double-seed.
func TestLocalAuthorizerDoesNotImplementRemoteDecisionEngineProvider(t *testing.T) {
	t.Parallel()

	_, ok := any(&local.Authorizer{}).(openapi.RemoteDecisionEngineProvider)
	require.False(t, ok, "local.Authorizer must not implement RemoteDecisionEngineProvider -- exactly one seed block must match per deployment")
}

// TestRemoteAuthorizerDoesNotImplementDecisionEngineProvider is the runtime
// negative counterpart to the compile-time
// `var _ openapi.RemoteDecisionEngineProvider = &remoteauthorizer.Authorizer{}`
// assertion in the remote package: remote must NOT ALSO satisfy the local
// provider interface, or a deployment using it would double-seed.
func TestRemoteAuthorizerDoesNotImplementDecisionEngineProvider(t *testing.T) {
	t.Parallel()

	_, ok := any(&remoteauthorizer.Authorizer{}).(openapi.DecisionEngineProvider)
	require.False(t, ok, "remote.Authorizer must not implement DecisionEngineProvider -- exactly one seed block must match per deployment")
}
