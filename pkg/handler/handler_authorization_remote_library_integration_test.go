//go:build integration

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync"
	"testing"
	"time"

	chi "github.com/go-chi/chi/v5"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	corehelpers "github.com/unikorn-cloud/core/pkg/openapi/helpers"
	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	identityclient "github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/jose"
	openapimiddleware "github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	authorizer "github.com/unikorn-cloud/identity/pkg/middleware/openapi/remote"
	"github.com/unikorn-cloud/identity/pkg/mtlstest"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	libraryNamespace = "remote-library-ns"
	checkPath        = "/api/v1/authorization/check"
)

type libraryUser struct {
	subject string
	srcIss  string
	groups  []string
}

type libraryIngress struct {
	server *httptest.Server

	mu        sync.Mutex
	audiences []string
	exchanges int
	checks    []libraryCheckCall
	requests  []libraryRequest
	passports []string
}

type libraryRequest struct {
	path    string
	query   string
	headers http.Header
	body    []byte
}

type libraryCheckCall struct {
	passport    string
	impersonate string
	principal   string
	relayedCert string
	checks      int
}

type libraryRecord struct {
	audiences []string
	exchanges int
	checks    []libraryCheckCall
	requests  []libraryRequest
	passports []string
}

func (i *libraryIngress) recorded() libraryRecord {
	i.mu.Lock()
	defer i.mu.Unlock()

	return libraryRecord{
		audiences: append([]string(nil), i.audiences...),
		exchanges: i.exchanges,
		checks:    append([]libraryCheckCall(nil), i.checks...),
		requests:  append([]libraryRequest(nil), i.requests...),
		passports: append([]string(nil), i.passports...),
	}
}

type libraryCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
}

func newLibraryCA(tb testing.TB) *libraryCA {
	tb.Helper()

	cert, key, certPEM, keyPEM, err := mtlstest.GenerateCACerts()
	require.NoError(tb, err)

	return &libraryCA{cert: cert, key: key, certPEM: certPEM, keyPEM: keyPEM}
}

func (ca *libraryCA) issue(tb testing.TB, commonName string) ([]byte, []byte) {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(tb, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(tb, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(tb, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func newLibraryIngress(tb testing.TB, ca *libraryCA, upstreamURL string, issuer *jose.JWTIssuer, users map[string]libraryUser, dropPassport bool) *libraryIngress {
	tb.Helper()

	upstream, err := url.Parse(upstreamURL)
	require.NoError(tb, err)

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	ingress := &libraryIngress{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if ingressFailed(tb, w, err) {
			return
		}

		r.Body = io.NopCloser(bytes.NewReader(body))

		ingress.mu.Lock()
		ingress.requests = append(ingress.requests, libraryRequest{path: r.URL.Path, query: r.URL.RawQuery, headers: r.Header.Clone(), body: body})
		ingress.mu.Unlock()

		switch r.URL.Path {
		case "/oauth2/v2/token":
			ingress.serveToken(tb, w, r, issuer, users)

			return
		case "/api/v1/acl":
			w.Header().Set("Content-Type", "application/json")
			_ = ingressFailed(tb, w, json.NewEncoder(w).Encode(openapi.Acl{}))

			return
		}

		peer := r.TLS.PeerCertificates[0]
		r.Header.Set("Ssl-Client-Cert", url.QueryEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peer.Raw}))))
		r.Header.Set("Ssl-Client-Verify", "SUCCESS")

		var request map[string]any

		if ingressFailed(tb, w, json.Unmarshal(body, &request)) {
			return
		}

		call := libraryCheckCall{
			impersonate: r.Header.Get(principal.ImpersonateHeader),
			principal:   r.Header.Get(principal.Header),
			relayedCert: r.Header.Get("Unikorn-Client-Certificate"),
		}

		if passport, ok := request["passport"].(string); ok {
			call.passport = passport
		}

		if checks, ok := request["checks"].([]any); ok {
			call.checks = len(checks)
		}

		ingress.mu.Lock()
		ingress.checks = append(ingress.checks, call)
		ingress.mu.Unlock()

		if dropPassport {
			delete(request, "passport")

			body, err = json.Marshal(request)
			if ingressFailed(tb, w, err) {
				return
			}
		}

		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))

		proxy.ServeHTTP(w, r)
	})

	serverCertPEM, serverKeyPEM := ca.issue(tb, "ingress")

	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(tb, err)

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(ca.cert)

	ingress.server = httptest.NewUnstartedServer(handler)
	ingress.server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	ingress.server.StartTLS()
	tb.Cleanup(ingress.server.Close)

	return ingress
}

// require must not run in a handler goroutine, so this fails through tb.Errorf.
func ingressFailed(tb testing.TB, w http.ResponseWriter, err error) bool {
	tb.Helper()

	if err == nil {
		return false
	}

	tb.Errorf("test ingress: %v", err)
	w.WriteHeader(http.StatusInternalServerError)

	return true
}

func (i *libraryIngress) serveToken(tb testing.TB, w http.ResponseWriter, r *http.Request, issuer *jose.JWTIssuer, users map[string]libraryUser) {
	tb.Helper()

	if ingressFailed(tb, w, r.ParseForm()) {
		return
	}

	i.mu.Lock()
	i.audiences = append(i.audiences, r.PostForm.Get("audience"))
	i.exchanges++
	i.mu.Unlock()

	user, ok := users[r.PostForm.Get("subject_token")]
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	claims := testPassportClaims(user.subject, openapi.User, r.PostForm.Get("audience"))
	claims.SrcIss = user.srcIss
	claims.Groups = user.groups

	passport, err := issuer.EncodeJWT(r.Context(), claims)
	if ingressFailed(tb, w, err) {
		return
	}

	i.mu.Lock()
	i.passports = append(i.passports, passport)
	i.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = ingressFailed(tb, w, json.NewEncoder(w).Encode(map[string]any{
		"access_token": passport,
		"token_type":   "Bearer",
		"expires_in":   int(time.Minute.Seconds()),
	}))
}

func newLibraryAuthorizer(tb testing.TB, ca *libraryCA, ingress *libraryIngress) *authorizer.Authorizer {
	tb.Helper()

	clientCertPEM, clientKeyPEM := ca.issue(tb, itNarrowCN)

	scheme := runtime.NewScheme()
	require.NoError(tb, corev1.AddToScheme(scheme))

	secrets := []*corev1.Secret{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: libraryNamespace, Name: "client-cert"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{corev1.TLSCertKey: clientCertPEM, corev1.TLSPrivateKeyKey: clientKeyPEM},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: libraryNamespace, Name: "ca-cert"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{corev1.TLSCertKey: ca.certPEM, corev1.TLSPrivateKeyKey: ca.keyPEM},
		},
	}

	builder := fake.NewClientBuilder().WithScheme(scheme)
	for _, secret := range secrets {
		builder = builder.WithObjects(secret)
	}

	identityFlags := pflag.NewFlagSet("library-identity", pflag.PanicOnError)
	identityOptions := identityclient.NewOptions()
	identityOptions.AddFlags(identityFlags)
	require.NoError(tb, identityFlags.Set("identity-host", ingress.server.URL))
	require.NoError(tb, identityFlags.Set("identity-ca-secret-namespace", libraryNamespace))
	require.NoError(tb, identityFlags.Set("identity-ca-secret-name", "ca-cert"))

	clientFlags := pflag.NewFlagSet("library-client", pflag.PanicOnError)
	clientOptions := &coreclient.HTTPClientOptions{}
	clientOptions.AddFlags(clientFlags)
	require.NoError(tb, clientFlags.Set("client-certificate-namespace", libraryNamespace))
	require.NoError(tb, clientFlags.Set("client-certificate-name", "client-cert"))

	a, err := authorizer.NewAuthorizer(builder.Build(), identityOptions, clientOptions,
		authorizer.WithRemoteEngineMode(rbac.RemoteEnforce),
		authorizer.WithCheckTimeout(10*time.Second))
	require.NoError(tb, err)

	return a
}

func libraryBearerContext(tb testing.TB, a *authorizer.Authorizer, token string) context.Context {
	tb.Helper()

	schema, err := corehelpers.NewSchema(openapi.GetSwagger)
	require.NoError(tb, err)

	handled := make(chan context.Context, 1)

	router := chi.NewRouter()
	router.Use(routeresolver.New(schema).Middleware)
	router.Use(openapimiddleware.NewValidator(&openapimiddleware.Options{ACLCacheSize: 1, ACLCacheTimeout: time.Minute}, a).Middleware)
	router.Get("/api/v1/organizations", func(_ http.ResponseWriter, r *http.Request) {
		handled <- r.Context()
	})

	req := httptest.NewRequestWithContext(tb.Context(), http.MethodGet, "http://localhost/api/v1/organizations", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(tb, http.StatusOK, w.Code, w.Body.String())
	require.Len(tb, handled, 1, "the handler must run")

	return <-handled
}

// headerEncodings are every base64 form in which a header could hide the passport.
func headerEncodings() []*base64.Encoding {
	return []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding}
}

// requirePassportOnlyInCheckBody walks every request that reached the ingress. The passport
// is a bearer credential, so it may leave the process only in the body of a check.
// X-Principal is base64url JSON built by the real middleware, so it is decoded too.
func requirePassportOnlyInCheckBody(tb testing.TB, seen libraryRecord) {
	tb.Helper()

	require.NotEmpty(tb, seen.passports, "the exchange must have issued a passport")

	for _, request := range seen.requests {
		for _, passport := range seen.passports {
			require.NotContains(tb, request.query, passport, "%s: the query must not carry the passport", request.path)

			if request.path != checkPath {
				require.NotContains(tb, string(request.body), passport, "%s: the body must not carry the passport", request.path)
			}
		}

		for name, values := range request.headers {
			for _, value := range values {
				for _, passport := range seen.passports {
					require.NotContains(tb, value, passport, "%s %s: header %s must not carry the passport", request.path, name, name)

					for _, encoding := range headerEncodings() {
						if decoded, err := encoding.DecodeString(value); err == nil {
							require.NotContains(tb, string(decoded), passport, "%s %s: the decoded header must not carry the passport", request.path, name)
						}
					}
				}
			}
		}
	}

	for _, call := range seen.checks {
		require.Contains(tb, seen.passports, call.passport, "the check body carries the issued passport")
	}
}

func groupChecks(count int) []rbac.Resource {
	resources := make([]rbac.Resource, count)
	for i := range resources {
		resources[i] = rbac.Resource{Kind: "identity:groups", OrganizationID: itOrgID}
	}

	return resources
}

func TestRemoteLibraryAgainstIdentity(t *testing.T) {
	t.Parallel()

	baseURL, issuer := newRemoteAuthzServer(t)
	ca := newLibraryCA(t)

	alice := libraryUser{subject: itAliceSubject, srcIss: constants.UNISentinel}
	withGroup := libraryUser{subject: itExternalSubject, srcIss: itGroupIssuer, groups: []string{itIDPGroup}}
	withoutGroup := withGroup
	withoutGroup.groups = nil

	users := map[string]libraryUser{"token-alice": alice, "token-group": withGroup, "token-no-group": withoutGroup}

	t.Run("a bearer user gets the verdict of the user, not of the narrow service", func(t *testing.T) {
		t.Parallel()

		ingress := newLibraryIngress(t, ca, baseURL, issuer, users, false)
		auth := newLibraryAuthorizer(t, ca, ingress)

		ctx := libraryBearerContext(t, auth, "token-alice")

		check := func(action openapi.AclOperation) bool {
			allowed, err := auth.RemoteDecisionEngine().AllowCoarseMany(ctx, groupChecks(1), action)
			require.NoError(t, err)
			require.Len(t, allowed, 1)

			return allowed[0]
		}

		require.True(t, check(openapi.Read), "a read that only the user holds must be allowed: no service cap")
		require.True(t, check(openapi.Update))
		require.False(t, check(openapi.Create), "a write that the user lacks must be denied")

		seen := ingress.recorded()
		require.Equal(t, []string{itNarrowCN}, seen.audiences, "the exchange must ask for the service's own certificate CN as audience")
		require.Len(t, seen.checks, 3)

		for _, call := range seen.checks {
			require.NotEmpty(t, call.passport, "a bearer check must carry the passport")
			require.Empty(t, call.impersonate, "a bearer check must not be impersonated")
			require.Empty(t, call.relayedCert)
			require.NotEmpty(t, call.principal, "X-Principal rides on every check")
		}

		requirePassportOnlyInCheckBody(t, seen)
	})

	t.Run("a cached passport serves every later check", func(t *testing.T) {
		t.Parallel()

		ingress := newLibraryIngress(t, ca, baseURL, issuer, users, false)
		auth := newLibraryAuthorizer(t, ca, ingress)

		for range 2 {
			ctx := libraryBearerContext(t, auth, "token-alice")

			allowed, err := auth.RemoteDecisionEngine().AllowCoarseMany(ctx, groupChecks(1), openapi.Read)
			require.NoError(t, err)
			require.Equal(t, []bool{true}, allowed)
		}

		seen := ingress.recorded()
		require.Equal(t, 1, seen.exchanges, "the second request must use the cached passport")
		require.Len(t, seen.checks, 2)
		require.Equal(t, seen.checks[0].passport, seen.checks[1].passport)

		requirePassportOnlyInCheckBody(t, seen)
	})

	t.Run("groups come from the claim", func(t *testing.T) {
		t.Parallel()

		ingress := newLibraryIngress(t, ca, baseURL, issuer, users, false)
		auth := newLibraryAuthorizer(t, ca, ingress)
		resources := []rbac.Resource{{Kind: "identity:projects"}}

		check := func(token string) bool {
			ctx := libraryBearerContext(t, auth, token)

			allowed, err := auth.RemoteDecisionEngine().AllowCoarseMany(ctx, resources, openapi.Read)
			require.NoError(t, err)

			return allowed[0]
		}

		require.True(t, check("token-group"), "the bound group in the passport must grant the role")
		require.False(t, check("token-no-group"), "with no group in the passport, nothing grants the role")

		requirePassportOnlyInCheckBody(t, ingress.recorded())
	})

	t.Run("a batch over the wire cap sends the passport in every chunk and keeps the order", func(t *testing.T) {
		t.Parallel()

		ingress := newLibraryIngress(t, ca, baseURL, issuer, users, false)
		auth := newLibraryAuthorizer(t, ca, ingress)

		ctx := libraryBearerContext(t, auth, "token-alice")

		const total = 120

		resources := make([]rbac.Resource, total)
		for i := range resources {
			kind := "identity:groups"
			if i%3 == 0 {
				kind = "identity:roles"
			}

			resources[i] = rbac.Resource{Kind: kind, OrganizationID: itOrgID}
		}

		allowed, err := auth.RemoteDecisionEngine().AllowCoarseMany(ctx, resources, openapi.Read)
		require.NoError(t, err)
		require.Len(t, allowed, total)

		for i := range allowed {
			require.Equal(t, i%3 != 0, allowed[i], "verdict %d must keep its request position", i)
		}

		seen := ingress.recorded()
		require.Len(t, seen.checks, 3)

		for _, call := range seen.checks {
			require.NotEmpty(t, call.passport)
		}

		requirePassportOnlyInCheckBody(t, seen)
	})

	t.Run("an identity that ignores the passport field gives no verdict", func(t *testing.T) {
		t.Parallel()

		ingress := newLibraryIngress(t, ca, baseURL, issuer, users, true)
		auth := newLibraryAuthorizer(t, ca, ingress)

		ctx := libraryBearerContext(t, auth, "token-alice")

		allowed, err := auth.RemoteDecisionEngine().AllowCoarseMany(ctx, []rbac.Resource{{Kind: "identity:quotas", OrganizationID: itOrgID}}, openapi.Read)
		require.ErrorIs(t, err, rbac.ErrDecisionUnavailable)
		require.Nil(t, allowed)

		requirePassportOnlyInCheckBody(t, ingress.recorded())
	})
}
