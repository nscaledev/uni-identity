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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/jose"
	authorizer "github.com/unikorn-cloud/identity/pkg/middleware/openapi/remote"
	"github.com/unikorn-cloud/identity/pkg/mtlstest"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace   = "test-namespace"
	testSubject     = "test@example.com"
	testOrgID       = "test-org"
	testUserID      = "test-user-id"
	testServiceID   = "test-service-id"
	certificateName = "jose-tls"
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
	Called *atomic.Int32 // used to check that cache is used rather than repeating calls
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

	var called atomic.Int32

	// Create mTLS server with handler
	var err error
	mtlsServer, err = mtlstest.NewMTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		case "/oauth2/v2/userinfo":
			called.Add(1)

			// Userinfo endpoint. This part of the handler is copied from handlers/handler.go, because the
			// "full" handler has too many dependencies that are irrelevant here.
			header := r.Header.Get("Authorization")
			if header == "" {
				errors.HandleError(w, r, errors.OAuth2InvalidRequest("authorization header missing"))
				return
			}

			parts := strings.Split(header, " ")

			if len(parts) != 2 {
				errors.HandleError(w, r, errors.OAuth2InvalidRequest("authorization header malformed"))
				return
			}

			if !strings.EqualFold(parts[0], "bearer") {
				errors.HandleError(w, r, errors.OAuth2InvalidRequest("authorization scheme not allowed"))
				return
			}

			userinfo, _, err := authenticator.GetUserinfo(r.Context(), r, parts[1])
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(userinfo)

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
		AccessTokenDuration:      time.Hour,
		TokenCacheSize:           10,
		CodeCacheSize:            10,
		AccountCreationCacheSize: 10,
	}

	u, _ := url.Parse(mtlsServer.URL())
	iss := handlercommon.IssuerValue{
		URL:      mtlsServer.URL(),
		Hostname: u.Host,
	}

	userdb := userdb.NewUserDatabase(fakeClient, testNamespace)

	authenticator = oauth2.New(oauth2Options, testNamespace, iss, fakeClient, issuer, userdb, rbacClient)

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

	return fakeClient, &server{mtlsServer, &called}, accessToken
}

// The fields are all unexported, and the only way to set them is with flags. So,
// flags we use.
func createIdentityOptions(t *testing.T, host string) *identityclient.Options {
	t.Helper()

	flags := pflag.NewFlagSet("test-identity-options", pflag.PanicOnError)
	options := identityclient.NewOptions()
	options.AddFlags(flags)
	// there is a brittle dependence here on the service name prefix ("identity") being correct
	require.NoError(t, flags.Set("identity-host", host))
	require.NoError(t, flags.Set("identity-ca-secret-namespace", testNamespace))
	require.NoError(t, flags.Set("identity-ca-secret-name", "ca-cert"))

	return options
}

func createCoreClientOptions(t *testing.T) *coreclient.HTTPClientOptions {
	t.Helper()

	options := &coreclient.HTTPClientOptions{}
	flags := pflag.NewFlagSet("test-http-options", pflag.PanicOnError)
	options.AddFlags(flags)
	// Configure client certificate for mTLS; these flags are defined in uni-core/pkg/client
	require.NoError(t, flags.Set("client-certificate-namespace", testNamespace))
	require.NoError(t, flags.Set("client-certificate-name", "client-cert"))

	return options
}

func createRemoteAuthorizer(t *testing.T, k8sClient client.Client, issuer string) *authorizer.Authorizer {
	t.Helper()

	identityOptions := createIdentityOptions(t, issuer)
	clientOptions := createCoreClientOptions(t)

	a, err := authorizer.NewAuthorizer(k8sClient, identityOptions, clientOptions)
	require.NoError(t, err)

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
