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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	authorizer "github.com/unikorn-cloud/identity/pkg/middleware/openapi/remote"
	"github.com/unikorn-cloud/identity/pkg/mtlstest"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// These tests pin the separation an enclave authorization profile needs: the
// ACL fetch and the decision call may move to a separate authorization host,
// but the token exchange -- authentication, not authorization -- must always
// stay on the identity host (see WithAuthorizationHost). They stand up two
// plain HTTP stub servers, never mTLS, and record which one receives which
// request. The cached client's TLS config (see getIdentityHTTPClient) only
// applies over https, so a plain http stub exercises the routing alone.

// endpointCertClient returns a fake k8s client carrying just the client-cert
// and ca-cert secrets createIdentityOptions/createCoreClientOptions expect,
// borrowed from a throwaway mTLS server purely for valid certificate
// material -- the stub servers these tests drive traffic against are plain
// HTTP and never see TLS.
func endpointCertClient(t *testing.T) client.Client {
	t.Helper()

	certs, err := mtlstest.NewMTLSServer(http.NotFoundHandler())
	require.NoError(t, err)
	t.Cleanup(certs.Close)

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	clientCertSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "client-cert"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certs.ClientCertPEM,
			corev1.TLSPrivateKeyKey: certs.ClientKeyPEM,
		},
	}

	caCertSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "ca-cert"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certs.CACertPEM,
			corev1.TLSPrivateKeyKey: certs.CAKeyPEM,
		},
	}

	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(clientCertSecret, caCertSecret).
		Build()
}

// pathRecorder stands up a plain HTTP stub that records the path of every
// request it receives and serves a canned empty JSON object, standing in for
// whichever of identity's endpoints a test points at it.
func pathRecorder(hits *[]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits = append(*hits, r.URL.Path)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
}

// driveAllThreeCalls exercises the token exchange (authentication), the ACL
// fetch and the decision call (authorization) once each against auth,
// ignoring their results -- these tests assert on which host received each
// request, not on call success, since the stub responses are not valid
// exchange/decision payloads.
func driveAllThreeCalls(t *testing.T, auth *authorizer.Authorizer, identityHost string) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, identityHost+"/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	_, _ = auth.Authorize(authInput(req))

	ctx := checkAuthContext(t, "any-token", false)

	_, _ = auth.GetACL(ctx, "")

	_, _ = auth.CheckMany(ctx, []authorizer.CheckRequest{
		{Resource: authorizer.Resource{Kind: "identity:groups", OrganizationID: "org-1"}, Action: identityapi.Read},
	})
}

// TestAuthorizationHostSplitsAuthzFromAuthn pins the separation an enclave
// needs. A consumer's identity host also serves the token exchange, quota
// allocations and lifecycle references, none of which an enclave serves, so
// only the ACL fetch and the decision call may move.
func TestAuthorizationHostSplitsAuthzFromAuthn(t *testing.T) {
	t.Parallel()

	var authzHits, identityHits []string

	authz := pathRecorder(&authzHits)
	defer authz.Close()

	identity := pathRecorder(&identityHits)
	defer identity.Close()

	k8sClient := endpointCertClient(t)
	auth := createRemoteAuthorizer(t, k8sClient, identity.URL, authorizer.WithAuthorizationHost(authz.URL))

	driveAllThreeCalls(t, auth, identity.URL)

	require.Contains(t, authzHits, "/api/v1/acl")
	require.Contains(t, authzHits, "/api/v1/authorization/check")
	require.NotContains(t, authzHits, "/oauth2/v2/token")

	require.Contains(t, identityHits, "/oauth2/v2/token")
	require.NotContains(t, identityHits, "/api/v1/acl")
	require.NotContains(t, identityHits, "/api/v1/authorization/check")
}

// TestAuthorizationHostDefaultsToIdentityHost pins the compatibility
// contract: an unset option leaves every existing deployment unchanged, so
// the token exchange, the ACL fetch and the decision call all land on the
// one identity host, exactly as today.
func TestAuthorizationHostDefaultsToIdentityHost(t *testing.T) {
	t.Parallel()

	var hits []string

	identity := pathRecorder(&hits)
	defer identity.Close()

	k8sClient := endpointCertClient(t)
	auth := createRemoteAuthorizer(t, k8sClient, identity.URL)

	driveAllThreeCalls(t, auth, identity.URL)

	require.Contains(t, hits, "/oauth2/v2/token")
	require.Contains(t, hits, "/api/v1/acl")
	require.Contains(t, hits, "/api/v1/authorization/check")
}

// TestAuthorizationHostRefusesPlaintext pins the credential rule on the new
// option. GetACL forwards the caller's passport to this host as a bearer and
// the decision call trusts the verdict it returns, so a plaintext host both
// discloses the passport and lets anything on the path forge an allow. The
// refusal happens at construction, not on the first request that would have
// leaked it. Loopback keeps http, which is what every test above relies on.
func TestAuthorizationHostRefusesPlaintext(t *testing.T) {
	t.Parallel()

	k8sClient := endpointCertClient(t)
	identityOptions := createIdentityOptions(t, "https://identity.unikorn-cloud.org")
	clientOptions := createCoreClientOptions(t)

	for _, host := range []string{
		"http://identity.unikorn-cloud.org",
		"http://10.0.0.1:6080",
		"identity.unikorn-cloud.org:6080",
		"ftp://identity.unikorn-cloud.org",
	} {
		auth, err := authorizer.NewAuthorizer(k8sClient, identityOptions, clientOptions,
			authorizer.WithAuthorizationHost(host))
		require.ErrorIs(t, err, authorizer.ErrAuthorizationHost, "host %q must be refused", host)
		require.Nil(t, auth)
	}

	for _, host := range []string{
		"https://enclave.unikorn-cloud.org",
		"http://localhost:6080",
		"http://127.0.0.1:6080",
		"",
	} {
		auth, err := authorizer.NewAuthorizer(k8sClient, identityOptions, clientOptions,
			authorizer.WithAuthorizationHost(host))
		require.NoError(t, err, "host %q must be accepted", host)
		require.NotNil(t, auth)
	}
}
