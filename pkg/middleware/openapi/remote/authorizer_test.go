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
	"crypto/rand"
	"crypto/rsa"
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
	openapimiddleware "github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/idp"
	authorizer "github.com/unikorn-cloud/identity/pkg/middleware/openapi/remote"
	"github.com/unikorn-cloud/identity/pkg/mtlstest"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	oauth2errors "github.com/unikorn-cloud/identity/pkg/oauth2/errors"
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

// TestRemoteFederatedTokenAuthentication tests that a Unikorn-issued token is
// authenticated by an introspection (userinfo) call to identity.
func TestRemoteFederatedTokenAuthentication(t *testing.T) {
	t.Parallel()

	k8sClient, server, accessToken := setupTestEnvironment(t)

	auth := createRemoteAuthorizer(t, k8sClient, server.URL(), nil)

	req := httptest.NewRequest(http.MethodGet, server.URL()+"/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	info, err := auth.Authorize(authInput(req))

	require.NoError(t, err)
	require.NotNil(t, info)
	require.Equal(t, testSubject, info.Userinfo.Sub)
	require.Equal(t, int32(1), server.Called.Load())
}

// TestRemoteTokenCaching tests that the userinfo introspection result is cached
// so a repeated token does not re-hit identity.
func TestRemoteTokenCaching(t *testing.T) {
	t.Parallel()

	k8sClient, server, accessToken := setupTestEnvironment(t)

	auth := createRemoteAuthorizer(t, k8sClient, server.URL(), nil)

	req1 := httptest.NewRequest(http.MethodGet, server.URL()+"/api/v1/test", nil)
	req1.Header.Set("Authorization", "Bearer "+accessToken)

	info1, err := auth.Authorize(authInput(req1))
	require.NoError(t, err)
	require.NotNil(t, info1)

	req2 := httptest.NewRequest(http.MethodGet, server.URL()+"/api/v1/test", nil)
	req2.Header.Set("Authorization", "Bearer "+accessToken)

	info2, err := auth.Authorize(authInput(req2))
	require.NoError(t, err)
	require.NotNil(t, info2)
	require.Equal(t, info1.Userinfo.Sub, info2.Userinfo.Sub)
	require.Equal(t, int32(1), server.Called.Load())
}

// TestRemoteThirdPartyTokenAuthenticatedLocally tests that a third-party (Auth0)
// JWS access token is validated fully locally against the issuer JWKS, with no
// call to the identity service — the core Phase 1 property for the third-party
// path.
func TestRemoteThirdPartyTokenAuthenticatedLocally(t *testing.T) {
	t.Parallel()

	k8sClient, server, _ := setupTestEnvironment(t)

	tpIssuer := newThirdPartyIssuer(t)

	auth := createRemoteAuthorizer(t, k8sClient, server.URL(), &idp.Options{
		Issuer:   tpIssuer.issuer(),
		Audience: thirdPartyAudience,
	})

	req := httptest.NewRequest(http.MethodGet, server.URL()+"/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+tpIssuer.token(t))

	info, err := auth.Authorize(authInput(req))

	require.NoError(t, err)
	require.NotNil(t, info)
	require.Equal(t, thirdPartyEmail, info.Userinfo.Sub)
	require.NotNil(t, info.Userinfo.HttpsunikornCloudOrgauthz)
	require.Equal(t, "user", string(info.Userinfo.HttpsunikornCloudOrgauthz.Acctype))
	// Authentication did not consult identity: the third-party path is local.
	require.Equal(t, int32(0), server.Called.Load())
}

// TestRemoteInvalidRequest tests authentication failures.
func TestRemoteInvalidRequest(t *testing.T) {
	t.Parallel()

	k8sClient, server, _ := setupTestEnvironment(t)

	auth := createRemoteAuthorizer(t, k8sClient, server.URL(), nil)

	requestMutators := map[string]func(*http.Request){
		"missing token": func(*http.Request) {},
		"unrecognized token": func(req *http.Request) {
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

	auth := createRemoteAuthorizer(t, k8sClient, server.URL(), nil)

	req := httptest.NewRequest(http.MethodGet, server.URL()+"/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

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
	Called *atomic.Int32 // counts identity userinfo introspection calls
}

// setupTestEnvironment creates a test environment with necessary K8s resources
// and an identity server that serves the userinfo introspection endpoint.
func setupTestEnvironment(t *testing.T) (client.Client, *server, string) {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	var authenticator *oauth2.Authenticator

	var mtlsServer *mtlstest.MTLSServer

	var called atomic.Int32

	var err error

	mtlsServer, err = mtlstest.NewMTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			u := mtlsServer.URL()
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

			_, token, err := splitBearer(r)
			if err != nil {
				oauth2errors.HandleError(w, r, oauth2errors.OAuth2AccessDenied("missing bearer"))
				return
			}

			userinfo, _, err := authenticator.GetUserinfo(r.Context(), r, token)
			if err != nil {
				oauth2errors.HandleError(w, r, err)
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

	issuer := jose.NewJWTIssuer(fakeClient, testNamespace, &jose.Options{
		IssuerSecretName: certificateName,
	})

	rbacOptions := &rbac.Options{}
	rbacClient := rbac.New(fakeClient, testNamespace, rbacOptions)

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

	authenticator, err = oauth2.New(oauth2Options, testNamespace, iss, fakeClient, issuer, userdb, rbacClient)
	require.NoError(t, err)

	ctx := t.Context()
	issueInfo := &oauth2.IssueInfo{
		Issuer:   mtlsServer.URL(),
		Audience: u.Host,
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

func splitBearer(r *http.Request) (string, string, error) {
	return authorizationSchemeParts(r.Header.Get("Authorization"))
}

func authorizationSchemeParts(header string) (string, string, error) {
	parts := strings.Split(header, " ")
	if len(parts) != 2 {
		return "", "", oauth2errors.OAuth2AccessDenied("malformed authorization header")
	}

	return parts[0], parts[1], nil
}

// The fields are all unexported, and the only way to set them is with flags. So,
// flags we use.
func createIdentityOptions(t *testing.T, host string) *identityclient.Options {
	t.Helper()

	flags := pflag.NewFlagSet("test-identity-options", pflag.PanicOnError)
	options := identityclient.NewOptions()
	options.AddFlags(flags)
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
	require.NoError(t, flags.Set("client-certificate-namespace", testNamespace))
	require.NoError(t, flags.Set("client-certificate-name", "client-cert"))

	return options
}

func createRemoteAuthorizer(t *testing.T, k8sClient client.Client, issuer string, oidc *idp.Options) *authorizer.Authorizer {
	t.Helper()

	identityOptions := createIdentityOptions(t, issuer)
	clientOptions := createCoreClientOptions(t)

	if oidc == nil {
		oidc = &idp.Options{}
	}

	auth, err := openapimiddleware.NewAuthenticationInfo(oidc)
	require.NoError(t, err)

	a, err := authorizer.NewAuthorizer(k8sClient, identityOptions, clientOptions, auth)
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

	unauthorizedClient := fake.NewClientBuilder().
		WithScheme(k8sClient.Scheme()).
		WithObjects(unauthorizedSigningSecret, unauthorizedSigningKey).
		Build()

	unauthorizedIssuer := jose.NewJWTIssuer(unauthorizedClient, unauthNamespace, &jose.Options{
		IssuerSecretName: unauthorizedSigningSecret.Name,
	})
	token, err := unauthorizedIssuer.EncodeJWT(t.Context(), map[string]any{"iss": "https://unknown.example.com"})
	require.NoError(t, err)

	return token
}

// ---- third-party (Auth0-style) JWKS issuer for local-validation tests

const (
	thirdPartyAudience = "https://identity.example.com"
	thirdPartyEmail    = "alice@customer.com"
)

type thirdPartyIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
}

func newThirdPartyIssuer(t *testing.T) *thirdPartyIssuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	idp := &thirdPartyIssuer{
		key: key,
		kid: "third-party-key",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		jwk := gojose.JSONWebKey{
			Key:       &key.PublicKey,
			KeyID:     idp.kid,
			Algorithm: string(gojose.RS256),
			Use:       "sig",
		}

		_ = json.NewEncoder(w).Encode(gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{jwk}})
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)

	return idp
}

func (i *thirdPartyIssuer) issuer() string {
	return i.server.URL + "/"
}

func (i *thirdPartyIssuer) token(t *testing.T) string {
	t.Helper()

	verified := true
	now := time.Now()

	//nolint:tagliatelle
	claims := struct {
		jwt.Claims

		Email         string `json:"https://unikorn-cloud.org/email"`
		EmailVerified *bool  `json:"https://unikorn-cloud.org/email_verified"`
	}{
		Claims: jwt.Claims{
			Issuer:   i.issuer(),
			Subject:  "auth0|alice",
			Audience: jwt.Audience{thirdPartyAudience},
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(time.Minute)),
		},
		Email:         thirdPartyEmail,
		EmailVerified: &verified,
	}

	signer, err := gojose.NewSigner(
		gojose.SigningKey{
			Algorithm: gojose.RS256,
			Key: gojose.JSONWebKey{
				Key:   i.key,
				KeyID: i.kid,
			},
		},
		(&gojose.SignerOptions{}).WithType("at+jwt"),
	)
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	return token
}
