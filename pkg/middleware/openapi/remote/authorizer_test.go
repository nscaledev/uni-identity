/*
Copyright 2025 the Unikorn Authors.

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	"github.com/unikorn-cloud/identity/pkg/jose"
	authorizer "github.com/unikorn-cloud/identity/pkg/middleware/openapi/remote"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/rbac"

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

// generateCA creates a self-signed CA certificate for testing.
func generateCA() (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	privDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	return cert, privateKey, certPEM, privPEM, nil
}

// generateCertificate creates a certificate signed by the given CA for testing.
func generateCertificate(cn string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	privDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	return certPEM, privPEM, nil
}

// setupTestEnvironment creates a test environment with necessary K8s resources and identity server.
func setupTestEnvironment(t *testing.T) (client.Client, *httptest.Server, string) {
	t.Helper()

	// Generate CA certificate
	caCert, caKey, caCertPEM, caPrivPEM, err := generateCA()
	require.NoError(t, err)

	// Generate server certificate signed by CA
	serverCertPEM, serverPrivPEM, err := generateCertificate("test-server", caCert, caKey)
	require.NoError(t, err)

	// Generate client certificate signed by CA
	clientCertPEM, clientPrivPEM, err := generateCertificate("test-client", caCert, caKey)
	require.NoError(t, err)

	// Create K8s scheme and client
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	// Create signing key secret (for JWT signing)
	signingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      certificateName,
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       serverCertPEM,
			corev1.TLSPrivateKeyKey: serverPrivPEM,
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
			corev1.TLSCertKey:       clientCertPEM,
			corev1.TLSPrivateKeyKey: clientPrivPEM,
		},
	}

	caCertSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      "ca-cert",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       caCertPEM,
			corev1.TLSPrivateKeyKey: caPrivPEM,
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
				{PEM: serverPrivPEM},
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
	authenticator := oauth2.New(oauth2Options, testNamespace, fakeClient, issuer, rbacClient)

	// Create CA pool for client certificate verification
	clientCAPool := x509.NewCertPool()
	clientCAPool.AppendCertsFromPEM(caCertPEM)

	// Create test HTTP server that simulates identity service
	var accessToken string

	var server *httptest.Server
	server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			// OIDC discovery endpoint
			config := map[string]interface{}{
				"issuer":                 server.URL,
				"userinfo_endpoint":      server.URL + "/oauth2/v2/userinfo",
				"jwks_uri":               server.URL + "/.well-known/jwks.json",
				"token_endpoint":         server.URL + "/oauth2/v2/token",
				"authorization_endpoint": server.URL + "/oauth2/v2/authorization",
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(config)

		case "/oauth2/v2/userinfo":
			// Userinfo endpoint. This part of the handler is copied from handlers/handler.go, because the
			// "full" handler has too many dependencies that are irrelevant here.
			header := r.Header.Get("Authorization")
			if header == "" {
				errors.HandleError(w, r, errors.OAuth2UnauthorizedClient("missing auth header"))
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

	// Load server certificate
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverPrivPEM)
	require.NoError(t, err)

	// Configure server TLS before starting
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	server.StartTLS()

	// Issue a test token
	ctx := t.Context()
	u, _ := url.Parse(server.URL)
	issueInfo := &oauth2.IssueInfo{
		Issuer:   server.URL,
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
	accessToken = tokens.AccessToken

	return fakeClient, server, accessToken
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

	return authorizer.NewAuthorizer(k8sClient, identityOptions, clientOptions)
}

// TestRemoteFederatedTokenAuthentication tests authentication via remote identity service.
func TestRemoteFederatedTokenAuthentication(t *testing.T) {
	t.Parallel()

	k8sClient, server, accessToken := setupTestEnvironment(t)
	defer server.Close()

	auth := createRemoteAuthorizer(t, k8sClient, server.URL)

	// Create test request
	req := httptest.NewRequest(http.MethodGet, server.URL+"/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	// Test Authorize
	authInput := &openapi3filter.AuthenticationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request: req,
		},
		SecurityScheme: &openapi3.SecurityScheme{
			Type: "oauth2",
		},
	}

	info, err := auth.Authorize(authInput)

	require.NoError(t, err)
	require.NotNil(t, info)
	require.Equal(t, testSubject, info.Userinfo.Sub)
}

// TestRemoteTokenCaching tests that tokens are cached properly.
func TestRemoteTokenCaching(t *testing.T) {
	t.Parallel()

	k8sClient, server, accessToken := setupTestEnvironment(t)
	defer server.Close()

	auth := createRemoteAuthorizer(t, k8sClient, server.URL)

	// First request
	req1 := httptest.NewRequest(http.MethodGet, server.URL+"/api/v1/test", nil)
	req1.Header.Set("Authorization", "Bearer "+accessToken)

	authInput1 := &openapi3filter.AuthenticationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request: req1,
		},
		SecurityScheme: &openapi3.SecurityScheme{
			Type: "oauth2",
		},
	}

	info1, err := auth.Authorize(authInput1)

	require.NoError(t, err)
	require.NotNil(t, info1)

	// Second request with same token (should hit cache)
	req2 := httptest.NewRequest(http.MethodGet, server.URL+"/api/v1/test", nil)
	req2.Header.Set("Authorization", "Bearer "+accessToken)

	authInput2 := &openapi3filter.AuthenticationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request: req2,
		},
		SecurityScheme: &openapi3.SecurityScheme{
			Type: "oauth2",
		},
	}

	info2, err := auth.Authorize(authInput2)

	require.NoError(t, err)
	require.NotNil(t, info2)
	require.Equal(t, info1.Userinfo.Sub, info2.Userinfo.Sub)
}

// TestRemoteInvalidToken tests authentication with an invalid token.
func TestRemoteInvalidToken(t *testing.T) {
	t.Parallel()

	k8sClient, server, _ := setupTestEnvironment(t)
	defer server.Close()

	auth := createRemoteAuthorizer(t, k8sClient, server.URL)

	// Create test request with invalid token
	req := httptest.NewRequest(http.MethodGet, server.URL+"/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	// Test Authorize
	authInput := &openapi3filter.AuthenticationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request: req,
		},
		SecurityScheme: &openapi3.SecurityScheme{
			Type: "oauth2",
		},
	}

	info, err := auth.Authorize(authInput)

	require.Error(t, err)
	require.Nil(t, info)
}

// TestRemoteMissingAuthorizationHeader tests authentication without Authorization header.
func TestRemoteMissingAuthorizationHeader(t *testing.T) {
	t.Parallel()

	k8sClient, server, _ := setupTestEnvironment(t)
	defer server.Close()

	auth := createRemoteAuthorizer(t, k8sClient, server.URL)

	// Create test request without Authorization header
	req := httptest.NewRequest(http.MethodGet, server.URL+"/api/v1/test", nil)

	// Test Authorize
	authInput := &openapi3filter.AuthenticationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request: req,
		},
		SecurityScheme: &openapi3.SecurityScheme{
			Type: "oauth2",
		},
	}

	info, err := auth.Authorize(authInput)

	require.Error(t, err)
	require.Nil(t, info)
}

// TestRemoteGetACLWithOrganization tests ACL retrieval with organization context.
func TestRemoteGetACLWithOrganization(t *testing.T) {
	t.Parallel()

	k8sClient, server, accessToken := setupTestEnvironment(t)
	defer server.Close()

	auth := createRemoteAuthorizer(t, k8sClient, server.URL)

	// Authenticate first
	req := httptest.NewRequest(http.MethodGet, server.URL+"/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	authInput := &openapi3filter.AuthenticationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request: req,
		},
		SecurityScheme: &openapi3.SecurityScheme{
			Type: "oauth2",
		},
	}

	info, err := auth.Authorize(authInput)

	require.NoError(t, err)
	require.NotNil(t, info)
}

// TestRemoteUnsupportedScheme tests authentication with unsupported scheme.
func TestRemoteUnsupportedScheme(t *testing.T) {
	t.Parallel()

	k8sClient, server, accessToken := setupTestEnvironment(t)
	defer server.Close()

	auth := createRemoteAuthorizer(t, k8sClient, server.URL)

	// Create test request
	req := httptest.NewRequest(http.MethodGet, server.URL+"/api/v1/test", nil)
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
	require.Nil(t, info)
	require.Contains(t, err.Error(), "unsupported")
}
