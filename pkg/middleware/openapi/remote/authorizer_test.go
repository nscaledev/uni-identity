/*
Copyright 2025 the Unikorn Authors.
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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	authorizer "github.com/unikorn-cloud/identity/pkg/middleware/openapi/remote"
	"github.com/unikorn-cloud/identity/pkg/mtlstest"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	oauth2errors "github.com/unikorn-cloud/identity/pkg/oauth2/errors"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace          = "test-namespace"
	testSubject            = "test@example.com"
	testOrgID              = "test-org"
	testUserID             = "test-user-id"
	testServiceID          = "test-service-id"
	certificateName        = "jose-tls"
	remoteTestCheckTimeout = 5 * time.Second
)

// TestRemoteFederatedTokenAuthentication tests authentication via remote identity service.
func TestRemoteFederatedTokenAuthentication(t *testing.T) {
	t.Parallel()

	k8sClient, server, accessToken := setupTestEnvironment(t)

	auth := createRemoteAuthorizer(t, k8sClient, server.URL())

	// Create test request
	req := httptest.NewRequest(http.MethodGet, server.URL()+"/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	info, err := auth.Authorize(authInput(req))

	require.NoError(t, err)
	require.NotNil(t, info)
	require.Equal(t, testSubject, info.Userinfo.Sub)
}

// TestRemoteTokenCaching tests that tokens are cached properly.
func TestRemoteTokenCaching(t *testing.T) {
	t.Parallel()

	k8sClient, server, accessToken := setupTestEnvironment(t)

	auth := createRemoteAuthorizer(t, k8sClient, server.URL())

	// First request
	req1 := httptest.NewRequest(http.MethodGet, server.URL()+"/api/v1/test", nil)
	req1.Header.Set("Authorization", "Bearer "+accessToken)

	info1, err := auth.Authorize(authInput(req1))

	require.NoError(t, err)
	require.NotNil(t, info1)

	// Second request with same token (should hit cache)
	req2 := httptest.NewRequest(http.MethodGet, server.URL()+"/api/v1/test", nil)
	req2.Header.Set("Authorization", "Bearer "+accessToken)

	info2, err := auth.Authorize(authInput(req2))

	require.NoError(t, err)
	require.NotNil(t, info2)
	require.Equal(t, info1.Userinfo.Sub, info2.Userinfo.Sub)
	require.Equal(t, int32(1), server.Called.Load())
	require.NotEmpty(t, info1.Passport, "a fresh exchange must return the raw passport")
	require.Equal(t, info1.Passport, info2.Passport, "a cache hit must return the same raw passport")
}

func TestRemotePassportGoesOnlyInTheCheckBody(t *testing.T) {
	t.Parallel()

	k8sClient, server, accessToken := setupTestEnvironment(t)

	auth := createRemoteAuthorizer(t, k8sClient, server.URL())

	var passport string

	// The first request exchanges the token. The second one is a cache hit, which serves most bearer requests.
	for range 2 {
		req := httptest.NewRequest(http.MethodGet, server.URL()+"/api/v1/test", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		info, err := auth.Authorize(authInput(req))
		require.NoError(t, err)
		require.NotEmpty(t, info.Passport)

		passport = info.Passport

		actor := &principal.Principal{Actor: testSubject, Type: identityapi.User}
		ctx := authorization.NewContext(principal.NewContext(t.Context(), actor), info)

		_, err = auth.GetACL(ctx, "")
		require.NoError(t, err)

		allowed, err := auth.RemoteDecisionEngine().AllowCoarseMany(ctx, []rbac.Resource{{Kind: "identity:groups"}}, identityapi.Read)
		require.NoError(t, err)
		require.Equal(t, []bool{true}, allowed)
	}

	require.Equal(t, int32(1), server.Called.Load(), "the second request must be a cache hit")

	paths := map[string]int{}

	for _, call := range server.recorded() {
		paths[call.path]++

		require.NotContains(t, call.query, passport, "the query of %s must not carry the passport", call.path)

		for name, values := range call.header {
			for _, value := range values {
				require.NotContains(t, value, passport, "header %s of %s must not carry the passport", name, call.path)

				for _, encoding := range headerEncodings() {
					if decoded, err := encoding.DecodeString(value); err == nil {
						require.NotContains(t, string(decoded), passport, "decoded header %s of %s must not carry the passport", name, call.path)
					}
				}
			}
		}

		if call.path == checkPath {
			require.Contains(t, string(call.body), passport, "the check body carries the passport")

			continue
		}

		require.NotContains(t, string(call.body), passport, "the body of %s must not carry the passport", call.path)
	}

	require.Equal(t, map[string]int{"/oauth2/v2/token": 1, "/api/v1/acl": 2, checkPath: 2}, paths, "the test must see the exchange, two ACL calls and two checks")
}

func TestRemoteExchangeRequestsAudienceOfClientCertificate(t *testing.T) {
	t.Parallel()

	k8sClient, server, accessToken := setupTestEnvironment(t)

	auth := createRemoteAuthorizer(t, k8sClient, server.URL())

	req := httptest.NewRequest(http.MethodGet, server.URL()+"/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	info, err := auth.Authorize(authInput(req))
	require.NoError(t, err)

	clientCN := certificateCN(t, server.ClientCertPEM)
	require.NotEmpty(t, clientCN)
	require.Equal(t, clientCN, server.Audience.Load(), "the exchange form must name the certificate CN as audience")

	token, err := jwt.ParseSigned(info.Passport, []gojose.SignatureAlgorithm{gojose.ES512})
	require.NoError(t, err)

	var claims jwt.Claims

	require.NoError(t, token.UnsafeClaimsWithoutVerification(&claims))
	require.Equal(t, jwt.Audience{clientCN}, claims.Audience)
}

func TestNewAuthorizerNeedsClientCertificateOnlyWhenRemoteIsOn(t *testing.T) {
	t.Parallel()

	k8sClient, server, _ := setupTestEnvironment(t)

	noCertificate := &coreclient.HTTPClientOptions{}
	noCertificate.AddFlags(pflag.NewFlagSet("test-no-certificate", pflag.PanicOnError))

	identityOptions := createIdentityOptions(t, server.URL())

	t.Run("off starts", func(t *testing.T) {
		t.Parallel()

		_, err := authorizer.NewAuthorizer(k8sClient, identityOptions, noCertificate)
		require.NoError(t, err)
	})

	for name, mode := range map[string]rbac.RemoteMode{"shadow": rbac.RemoteShadow, "enforce": rbac.RemoteEnforce} {
		t.Run(name+" refuses", func(t *testing.T) {
			t.Parallel()

			_, err := authorizer.NewAuthorizer(k8sClient, identityOptions, noCertificate, authorizer.WithRemoteEngineMode(mode))
			require.ErrorIs(t, err, authorizer.ErrClientCertificateMissing)
			require.ErrorContains(t, err, "client certificate")
		})
	}

	t.Run("a certificate with no common name refuses", func(t *testing.T) {
		t.Parallel()

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)}, &x509.Certificate{}, &key.PublicKey, key)
		require.NoError(t, err)

		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)

		scheme := runtime.NewScheme()
		require.NoError(t, corev1.AddToScheme(scheme))

		unnamed := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "client-cert"},
				Type:       corev1.SecretTypeTLS,
				Data: map[string][]byte{
					corev1.TLSCertKey:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
					corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
				},
			},
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "ca-cert"},
				Type:       corev1.SecretTypeTLS,
				Data:       map[string][]byte{corev1.TLSCertKey: server.CACertPEM, corev1.TLSPrivateKeyKey: server.CAKeyPEM},
			},
		).Build()

		_, err = authorizer.NewAuthorizer(unnamed, identityOptions, createCoreClientOptions(t), authorizer.WithRemoteEngineMode(rbac.RemoteShadow))
		require.ErrorIs(t, err, authorizer.ErrClientCertificateMissing)
		require.ErrorContains(t, err, "common name")
	})

	t.Run("shadow starts with a certificate", func(t *testing.T) {
		t.Parallel()

		_, err := authorizer.NewAuthorizer(k8sClient, identityOptions, createCoreClientOptions(t), authorizer.WithRemoteEngineMode(rbac.RemoteShadow))
		require.NoError(t, err)
	})
}

// TestRemoteInvalidToken tests authentication with an invalid token.
func TestRemoteInvalidRequest(t *testing.T) {
	t.Parallel()

	k8sClient, server, _ := setupTestEnvironment(t)

	auth := createRemoteAuthorizer(t, k8sClient, server.URL())

	requestMutators := map[string]func(*http.Request){
		"missing token": func(*http.Request) {},
		"invalid token": func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer invalid-token")
		},
		"unauthorized token": func(req *http.Request) {
			t := generatePlausibleToken(t, k8sClient)
			req.Header.Set("Authorization", "Bearer "+t)
		},
	}

	for name, fn := range requestMutators {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, server.URL()+"/api/v1/test", nil)
			fn(req)
			info, err := auth.Authorize(authInput(req))

			require.Error(t, err)
			require.Nil(t, info)
		})
	}
}

// TestRemoteUnsupportedScheme tests authentication with unsupported scheme.
func TestRemoteUnsupportedScheme(t *testing.T) {
	t.Parallel()

	k8sClient, server, accessToken := setupTestEnvironment(t)

	auth := createRemoteAuthorizer(t, k8sClient, server.URL())

	// Create test request
	req := httptest.NewRequest(http.MethodGet, server.URL()+"/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	// Test Authorize with unsupported scheme
	authInput := &openapi3filter.AuthenticationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request: req,
		},
		SecurityScheme: &openapi3.SecurityScheme{
			Type: "basic",
		},
	}

	info, err := auth.Authorize(authInput)

	require.Error(t, err)
	require.True(t, errors.IsBadRequest(err))
	require.Nil(t, info)
}

// ---- helpers

type server struct {
	*mtlstest.MTLSServer
	Called   *atomic.Int32 // used to check that cache is used rather than repeating calls
	Audience *atomic.Value
	calls    *callRecorder
}

const checkPath = "/api/v1/authorization/check"

// headerEncodings are every base64 form in which a header could hide the passport.
func headerEncodings() []*base64.Encoding {
	return []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding}
}

type recordedCall struct {
	path   string
	query  string
	header http.Header
	body   []byte
}

type callRecorder struct {
	mu    sync.Mutex
	calls []recordedCall
}

func (r *callRecorder) record(req *http.Request) error {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}

	req.Body = io.NopCloser(bytes.NewReader(body))

	r.mu.Lock()
	defer r.mu.Unlock()

	r.calls = append(r.calls, recordedCall{path: req.URL.Path, query: req.URL.RawQuery, header: req.Header.Clone(), body: body})

	return nil
}

func (s *server) recorded() []recordedCall {
	s.calls.mu.Lock()
	defer s.calls.mu.Unlock()

	return append([]recordedCall(nil), s.calls.calls...)
}

// setupTestEnvironment creates a test environment with necessary K8s resources and identity server.
func setupTestEnvironment(t *testing.T) (client.Client, *server, string) {
	t.Helper()

	// Create K8s scheme and client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	// We need to create the mTLS server early so we can use its certificates
	// in the K8s secrets. However, we need the authenticator to create the
	// handler, so we'll use a placeholder handler first.
	var authenticator *oauth2.Authenticator
	// Similarly, the handler needs the server URL, so declare first and assign after.
	var mtlsServer *mtlstest.MTLSServer

	var (
		called   atomic.Int32
		audience atomic.Value
		calls    callRecorder
	)

	// Create mTLS server with handler
	var err error
	mtlsServer, err = mtlstest.NewMTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := calls.record(r); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			u := mtlsServer.URL()
			// OIDC discovery endpoint
			config := map[string]interface{}{
				"issuer":                 u,
				"userinfo_endpoint":      u + "/oauth2/v2/userinfo",
				"jwks_uri":               u + "/.well-known/jwks.json",
				"token_endpoint":         u + "/oauth2/v2/token",
				"authorization_endpoint": u + "/oauth2/v2/authorization",
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(config)

		case "/oauth2/v2/token":
			called.Add(1)
			audience.Store(r.PostFormValue("audience"))

			result, err := authenticator.Token(w, r)
			if err != nil {
				oauth2errors.HandleError(w, r, err)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(result)

		case "/api/v1/acl":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(identityapi.Acl{})

		case checkPath:
			var request identityapi.AuthorizationCheckRequest

			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			subject := testSubject
			results := make([]identityapi.AuthorizationCheckResult, len(request.Checks))

			for i := range results {
				results[i].Allowed = true
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(identityapi.AuthorizationCheckResponse{Results: results, PassportSubject: &subject})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	require.NoError(t, err)
	t.Cleanup(mtlsServer.Close)

	// Create signing key secret (for JWT signing)
	signingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      certificateName,
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       mtlsServer.ServerCertPEM,
			corev1.TLSPrivateKeyKey: mtlsServer.ServerKeyPEM,
		},
	}

	// Create client certificate secret (for mTLS)
	clientCertSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      "client-cert",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       mtlsServer.ClientCertPEM,
			corev1.TLSPrivateKeyKey: mtlsServer.ClientKeyPEM,
		},
	}

	caCertSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      "ca-cert",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       mtlsServer.CACertPEM,
			corev1.TLSPrivateKeyKey: mtlsServer.CAKeyPEM,
		},
	}

	// Create signing key resource
	signingKey := &unikornv1.SigningKey{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      jose.SigningKeyName,
		},
		Spec: unikornv1.SigningKeySpec{
			PrivateKeys: []unikornv1.PrivateKey{
				{PEM: mtlsServer.ServerKeyPEM},
			},
		},
	}

	// Create test user
	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testUserID,
		},
		Spec: unikornv1.UserSpec{
			Subject: testSubject,
			State:   unikornv1.UserStateActive,
		},
	}

	// Create test service account
	serviceAccount := &unikornv1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace + "-org",
			Name:      testServiceID,
			Labels: map[string]string{
				"unikorn-cloud.org/organization": testOrgID,
			},
		},
		Spec: unikornv1.ServiceAccountSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(signingSecret, clientCertSecret, caCertSecret,
			signingKey, user, serviceAccount).
		Build()

	// Create JWT issuer
	issuer := jose.NewJWTIssuer(fakeClient, testNamespace, &jose.Options{
		IssuerSecretName: certificateName,
	})

	// Create RBAC
	rbacOptions := &rbac.Options{}
	rbacClient := rbac.New(fakeClient, testNamespace, rbacOptions)

	// Create oauth2 authenticator
	oauth2Options := &oauth2.Options{
		AccessTokenDuration: time.Hour,
		TokenCacheSize:      10,
		CodeCacheSize:       10,
	}

	u, _ := url.Parse(mtlsServer.URL())
	iss := handlercommon.IssuerValue{
		URL:      mtlsServer.URL(),
		Hostname: u.Host,
	}

	userdb := userdb.NewUserDatabase(fakeClient, testNamespace)

	authenticator, err = oauth2.New(oauth2Options, testNamespace, iss, fakeClient, fakeClient, issuer, userdb, rbacClient)
	require.NoError(t, err)

	// Issue a test token
	ctx := t.Context()
	issueInfo := &oauth2.IssueInfo{
		Issuer:   mtlsServer.URL(),
		Audience: u.Host, // the issuer is https://..., but the audience is the host.
		Subject:  testSubject,
		Type:     oauth2.TokenTypeFederated,
		Federated: &oauth2.FederatedClaims{
			ClientID: "test-client",
			UserID:   testUserID,
			Provider: "test-provider",
			Scope:    oauth2.NewScope("openid email"),
		},
	}

	tokens, err := authenticator.Issue(ctx, issueInfo)
	require.NoError(t, err)
	require.NotNil(t, tokens)
	accessToken := tokens.AccessToken

	return fakeClient, &server{mtlsServer, &called, &audience, &calls}, accessToken
}

func certificateCN(tb testing.TB, certPEM []byte) string {
	tb.Helper()

	block, _ := pem.Decode(certPEM)
	require.NotNil(tb, block)

	certificate, err := x509.ParseCertificate(block.Bytes)
	require.NoError(tb, err)

	return certificate.Subject.CommonName
}

// The fields are all unexported, and the only way to set them is with flags. So,
// flags we use.
func createIdentityOptions(tb testing.TB, host string) *identityclient.Options {
	tb.Helper()

	flags := pflag.NewFlagSet("test-identity-options", pflag.PanicOnError)
	options := identityclient.NewOptions()
	options.AddFlags(flags)
	// there is a brittle dependence here on the service name prefix ("identity") being correct
	require.NoError(tb, flags.Set("identity-host", host))
	require.NoError(tb, flags.Set("identity-ca-secret-namespace", testNamespace))
	require.NoError(tb, flags.Set("identity-ca-secret-name", "ca-cert"))

	return options
}

func createCoreClientOptions(tb testing.TB) *coreclient.HTTPClientOptions {
	tb.Helper()

	options := &coreclient.HTTPClientOptions{}
	flags := pflag.NewFlagSet("test-http-options", pflag.PanicOnError)
	options.AddFlags(flags)
	// Configure client certificate for mTLS; these flags are defined in uni-core/pkg/client
	require.NoError(tb, flags.Set("client-certificate-namespace", testNamespace))
	require.NoError(tb, flags.Set("client-certificate-name", "client-cert"))

	return options
}

func createRemoteAuthorizer(tb testing.TB, k8sClient client.Client, issuer string, opts ...authorizer.Option) *authorizer.Authorizer {
	tb.Helper()

	identityOptions := createIdentityOptions(tb, issuer)
	clientOptions := createCoreClientOptions(tb)

	// TLS setup can exceed the production 250ms decision deadline under the
	// race detector. Explicit test options follow this default and still win.
	opts = append([]authorizer.Option{authorizer.WithCheckTimeout(remoteTestCheckTimeout)}, opts...)

	a, err := authorizer.NewAuthorizer(k8sClient, identityOptions, clientOptions, opts...)
	require.NoError(tb, err)

	return a
}

func authInput(req *http.Request) *openapi3filter.AuthenticationInput {
	return &openapi3filter.AuthenticationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request: req,
		},
		SecurityScheme: &openapi3.SecurityScheme{
			Type: "oauth2",
		},
	}
}

func generatePlausibleToken(t *testing.T, k8sClient client.Client) string {
	t.Helper()

	_, _, serverCertPEM, serverKeyPEM, err := mtlstest.GenerateCACerts()
	require.NoError(t, err)

	unauthNamespace := "unauthorised"

	// Create a separate signing key secret with the unauthorized server's keys
	unauthorizedSigningSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: unauthNamespace,
			Name:      "unauthorized-jose-tls",
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       serverCertPEM,
			corev1.TLSPrivateKeyKey: serverKeyPEM,
		},
	}

	unauthorizedSigningKey := &unikornv1.SigningKey{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: unauthNamespace,
			Name:      jose.SigningKeyName,
		},
		Spec: unikornv1.SigningKeySpec{
			PrivateKeys: []unikornv1.PrivateKey{
				{PEM: serverKeyPEM},
			},
		},
	}

	// Create a separate k8s client with the unauthorized keys
	unauthorizedClient := fake.NewClientBuilder().
		WithScheme(k8sClient.Scheme()).
		WithObjects(unauthorizedSigningSecret, unauthorizedSigningKey).
		Build()

	// Create issuer with the separate key
	unauthorizedIssuer := jose.NewJWTIssuer(unauthorizedClient, unauthNamespace, &jose.Options{
		IssuerSecretName: unauthorizedSigningSecret.Name,
	})
	token, err := unauthorizedIssuer.EncodeJWT(t.Context(), map[string]any{"iss": "https://unknown.example.com"})
	require.NoError(t, err)

	return token
}
