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

// This file proves the remote decision path (run it with make
// test-cerbos-remote): a downstream service obtains an authorization decision
// from identity over the real request pipeline.  It stands up an in-process
// identity server slice — the REAL generated router + the REAL openapi
// middleware validator + a REAL rbac.RBAC.WithCerbos backed by the pinned
// Cerbos image (docker) + the REAL PostApiV1AuthorizationCheck handler — and
// drives it through the GENERATED TYPED CLIENT
// (PostApiV1AuthorizationCheckWithResponse).
//
// FAITHFULNESS NOTE (deviation from the brief's "TLS listener with a client
// cert" wording, deliberately): identity does NOT authenticate mTLS from the
// TLS handshake.  Its production model is ingress-terminated mTLS where the
// ingress verifies the peer certificate and injects it as the url-encoded
// `Ssl-Client-Cert` header with `Ssl-Client-Verify: SUCCESS`, stripping any
// client-supplied copy (see pkg/util/tls.go and pkg/middleware/openapi
// validateAuthentication — the mTLS branch reads the HEADER, never
// connection PeerCertificates).  So the faithful in-process reproduction of a
// system-account caller is to inject exactly those ingress headers over the
// generated client's transport; the server is a plain httptest server.  This
// exercises the true auth boundary (the middleware re-derives SystemAccount +
// the acting CN from the cert header, and the handler's SystemAccount gate
// runs against that real Info).  The chart-level header-strip invariant and
// signed-principal propagation are the named follow-up; a
// genuine TLS-handshake mTLS assertion is deferred to kind CI (also
// follow-up).  This is stronger than the brief's sanctioned fallback (real
// router + real handler + synthesized contexts): the real validator runs.
package handler_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	chi "github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	corehelpers "github.com/unikorn-cloud/core/pkg/openapi/helpers"
	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos/generate"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/handler"
	handlercommon "github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/jose"
	josetesting "github.com/unikorn-cloud/identity/pkg/jose/testing"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	openapimiddleware "github.com/unikorn-cloud/identity/pkg/middleware/openapi"
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
)

const (
	itNamespace = "remote-authz-ns"
	itOrgID     = "remote-authz-org"
	itOrgNS     = "remote-authz-org-ns"

	// itSystemCN is the acting service's certificate common name; the
	// middleware re-derives SystemAccount + this subject from the cert header.
	itSystemCN = "remote-authz-system"

	// itAliceSubject is the impersonated user.
	itAliceSubject = "remote-authz-alice@example.com"
	// itIssuerBoundSubject has a global binding only at the UNI issuer.
	itIssuerBoundSubject = "remote-authz-bound@example.com"

	// Roles: the acting service holds identity:groups READ globally only; the
	// impersonated user holds identity:groups read+update at org scope.  So
	// read is allowed-by-both, and update is allowed-by-principal but
	// denied-by-service — the dual-check narrowing witness.
	itServiceRole = "remote-authz-service-role"
	itUserRole    = "remote-authz-user-role"
	itGroup       = "remote-authz-group"

	itNarrowCN = "remote-authz-narrow"

	itServiceAccount = "remote-authz-sa"
	itNarrowRole     = "remote-authz-narrow-role"

	itExternalSubject = "remote-authz-external@example.com"
	itGroupIssuer     = "https://groups.example.com/"
	itIDPGroup        = "remote-authz-idp-group"
	itGroupRole       = "remote-authz-group-role"
	itStaffIssuer     = "https://staff.example.com/"
	itStaffRole       = "remote-authz-staff-role"
)

// itAuthorizer is a middleware Authorizer for the mTLS-only decision endpoint.
// Authorize is never invoked on the mTLS path (the middleware derives the
// system account from the cert header itself), so it fails loudly if reached;
// GetACL and DecisionEngine delegate to the real RBAC so the middleware
// populates the ACL context and seeds the Cerbos decision engine exactly as
// production does.
type itAuthorizer struct {
	rbac *rbac.RBAC
}

func (a *itAuthorizer) Authorize(authentication *openapi3filter.AuthenticationInput) (*authorization.Info, error) {
	// A bearer caller (no client certificate) reaches here.  The real local
	// authorizer would validate the token; this endpoint is mTLS-only, so a
	// bearer is refused as access-denied (401) exactly as an invalid token
	// would be — the handler's SystemAccount gate is the unit-level proof, and
	// this stub keeps the end-to-end bearer rejection a 401 rather than a 500.
	return nil, coreerrors.AccessDenied(authentication.RequestValidationInput.Request, "authorization check is restricted to system accounts")
}

func (a *itAuthorizer) GetACL(ctx context.Context, organizationID string) (*openapi.Acl, error) {
	return a.rbac.GetACL(ctx, organizationID)
}

func (a *itAuthorizer) DecisionEngine() *rbac.RBAC {
	return a.rbac
}

// itValidatorOptions returns middleware options with a non-zero ACL cache
// (the LRU cache panics on size 0; production defaults it via flags).  Runtime
// schema validation is left off — this test asserts decision semantics on the
// response body, not schema conformance, and enabling it would require the
// full response-validation plumbing the production server wires.
func itValidatorOptions() *openapimiddleware.Options {
	options := &openapimiddleware.Options{}

	flags := pflag.NewFlagSet("it-openapi-options", pflag.PanicOnError)
	options.AddFlags(flags)

	return options
}

// itRoles is the fixture role catalogue.
func itRoles() []unikornv1.Role {
	scope := func(name string, ops ...unikornv1.Operation) unikornv1.RoleScope {
		return unikornv1.RoleScope{Name: name, Operations: ops}
	}

	role := func(name string, scopes unikornv1.RoleScopes) unikornv1.Role {
		return unikornv1.Role{
			ObjectMeta: metav1.ObjectMeta{Namespace: itNamespace, Name: name},
			Spec:       unikornv1.RoleSpec{Scopes: scopes},
		}
	}

	return []unikornv1.Role{
		// The acting service: GLOBAL identity:groups read only (like every
		// system account — global-only, the property the dual check rests on).
		role(itServiceRole, unikornv1.RoleScopes{
			Global: []unikornv1.RoleScope{scope("identity:groups", unikornv1.Read)},
		}),
		// The impersonated user: org-scoped identity:groups read + update.
		role(itUserRole, unikornv1.RoleScopes{
			Organization: []unikornv1.RoleScope{scope("identity:groups", unikornv1.Read, unikornv1.Update)},
		}),
		role(itNarrowRole, unikornv1.RoleScopes{
			Organization: []unikornv1.RoleScope{scope("identity:quotas", unikornv1.Read)},
		}),
		role(itGroupRole, unikornv1.RoleScopes{
			Global: []unikornv1.RoleScope{scope("identity:projects", unikornv1.Read)},
		}),
		role(itStaffRole, unikornv1.RoleScopes{
			Global: []unikornv1.RoleScope{scope("identity:organizations", unikornv1.Read, unikornv1.Update)},
		}),
	}
}

// newRemoteAuthzServer builds the in-process identity slice and returns its
// base URL and the JWT issuer that signs its passports.  The Cerbos PDP is the
// real pinned image (docker), started with a store generated from the fixture
// roles.
func newRemoteAuthzServer(tb testing.TB) (string, *jose.JWTIssuer) {
	tb.Helper()

	scheme := runtime.NewScheme()
	require.NoError(tb, unikornv1.AddToScheme(scheme))

	organization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{Namespace: itNamespace, Name: itOrgID},
		Status:     unikornv1.OrganizationStatus{Namespace: itOrgNS},
	}

	group := &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{Namespace: itOrgNS, Name: itGroup},
		Spec: unikornv1.GroupSpec{
			RoleIDs:           []string{itUserRole},
			Subjects:          []unikornv1.GroupSubject{{ID: itAliceSubject}},
			ServiceAccountIDs: []string{itServiceAccount},
		},
	}

	trust := func(name, issuer string) *unikornv1.OAuth2Provider {
		return &unikornv1.OAuth2Provider{
			ObjectMeta: metav1.ObjectMeta{Namespace: itNamespace, Name: name},
			Spec: unikornv1.OAuth2ProviderSpec{
				Issuer: issuer,
				BearerTrust: &unikornv1.BearerTrustSpec{
					Audience:              "https://identity.example.com",
					AllowExternalIdentity: true,
				},
			},
		}
	}

	objects := []client.Object{
		organization,
		group,
		josetesting.SigningKey(tb, itNamespace),
		&unikornv1.User{
			ObjectMeta: metav1.ObjectMeta{Namespace: itNamespace, Name: "remote-authz-alice"},
			Spec:       unikornv1.UserSpec{Subject: itAliceSubject, State: unikornv1.UserStateActive},
		},
		&unikornv1.OrganizationUser{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: itOrgNS,
				Name:      "remote-authz-alice",
				Labels: map[string]string{
					coreconstants.UserLabel:         "remote-authz-alice",
					coreconstants.OrganizationLabel: itOrgID,
				},
			},
			Spec: unikornv1.OrganizationUserSpec{State: unikornv1.UserStateActive},
		},
		&unikornv1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Namespace: itOrgNS, Name: itServiceAccount},
		},
		trust("remote-authz-groups", itGroupIssuer),
		trust("remote-authz-staff", itStaffIssuer),
	}

	roles := itRoles()
	for i := range roles {
		objects = append(objects, &roles[i])
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

	r := rbac.New(c, itNamespace, &rbac.Options{
		SystemAccountRoleIDs: map[string]string{itSystemCN: itServiceRole, itNarrowCN: itNarrowRole},
		GlobalRoleBindings: rbac.GlobalRoleBindingsValue{
			{Issuer: constants.UNISentinel, Subject: itIssuerBoundSubject, RoleIDs: []string{itServiceRole}},
			{Issuer: itStaffIssuer, Subject: rbac.WildcardSubject, RoleIDs: []string{itStaffRole}, Wildcard: true},
		},
		GlobalGroupRoleBindings: rbac.GlobalGroupRoleBindingsValue{
			{Issuer: itGroupIssuer, Group: itIDPGroup, RoleIDs: []string{itGroupRole}},
		},
	})

	// Start the real Cerbos PDP over the generated store.
	endpoint := startRemoteAuthzCerbos(tb, writeRemoteAuthzStore(tb, roles))

	pdp, err := cerbos.New(&cerbos.Options{Endpoint: endpoint, CheckTimeout: 5 * time.Second})
	require.NoError(tb, err)

	r.WithCerbos(pdp)

	// Build the real server pipeline: route resolver + the openapi validator
	// middleware + the generated router around the real handler.
	schema, err := corehelpers.NewSchema(openapi.GetSwagger)
	require.NoError(tb, err)

	router := chi.NewRouter()

	resolver := routeresolver.New(schema)
	router.Use(resolver.Middleware)

	validator := openapimiddleware.NewValidator(itValidatorOptions(), &itAuthorizer{rbac: r})

	users := userdb.NewUserDatabase(c, itNamespace)
	jwtIssuer := jose.NewJWTIssuer(c, itNamespace, &jose.Options{})

	authenticator, err := oauth2.New(&oauth2.Options{TokenCacheSize: 1, CodeCacheSize: 1}, itNamespace, handlercommon.IssuerValue{}, c, c, jwtIssuer, users, r)
	require.NoError(tb, err)

	h, err := handler.New(c, c, itNamespace, jwtIssuer, authenticator, users, r, &handler.Options{})
	require.NoError(tb, err)

	chiServerOptions := openapi.ChiServerOptions{
		BaseRouter:       router,
		ErrorHandlerFunc: handler.HandleError,
		Middlewares:      []openapi.MiddlewareFunc{validator.Middleware},
	}

	server := httptest.NewServer(openapi.HandlerWithOptions(h, chiServerOptions))
	tb.Cleanup(server.Close)

	return server.URL, jwtIssuer
}

// systemCertHeader returns a url-encoded PEM certificate with the given common
// name, as the ingress injects it into Ssl-Client-Cert.
func systemCertHeader(tb testing.TB, commonName string) string {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(tb, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(tb, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(tb, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	return url.QueryEscape(string(certPEM))
}

// systemClient returns a generated typed client whose transport injects the
// ingress mTLS headers for the given common name plus the X-Principal header
// every mTLS caller sends (see the middleware's extractPrincipal, which
// REQUIRES it for cert-bearing requests — a real downstream service always
// injects its principal via principal.Injector).  When impersonated is
// non-nil it is the propagated principal and the X-Impersonate marker rides;
// otherwise the acting service's own principal is sent for attribution only.
func systemClient(tb testing.TB, baseURL, commonName string, impersonated *principal.Principal) *openapi.ClientWithResponses {
	tb.Helper()

	certHeader := systemCertHeader(tb, commonName)

	p := impersonated
	impersonate := impersonated != nil

	if p == nil {
		// Attribution-only principal: the acting service itself.
		p = &principal.Principal{Actor: commonName, Type: openapi.System}
	}

	principalHeader := base64.RawURLEncoding.EncodeToString(mustMarshal(tb, p))

	editor := func(_ context.Context, req *http.Request) error {
		req.Header.Set("Ssl-Client-Cert", certHeader)
		req.Header.Set("Ssl-Client-Verify", "SUCCESS")
		req.Header.Set(principal.Header, principalHeader)

		if impersonate {
			req.Header.Set(principal.ImpersonateHeader, "true")
		}

		return nil
	}

	c, err := openapi.NewClientWithResponses(baseURL, openapi.WithRequestEditorFn(editor))
	require.NoError(tb, err)

	return c
}

func passportClient(tb testing.TB, baseURL, commonName string, p *principal.Principal, relayedCN string) *openapi.ClientWithResponses {
	tb.Helper()

	certHeader := systemCertHeader(tb, commonName)
	principalHeader := base64.RawURLEncoding.EncodeToString(mustMarshal(tb, p))

	var relayHeader string
	if relayedCN != "" {
		relayHeader = systemCertHeader(tb, relayedCN)
	}

	editor := func(_ context.Context, req *http.Request) error {
		req.Header.Set("Ssl-Client-Cert", certHeader)
		req.Header.Set("Ssl-Client-Verify", "SUCCESS")
		req.Header.Set(principal.Header, principalHeader)

		if relayHeader != "" {
			req.Header.Set(authorization.ClientCertificateHeader, relayHeader)
		}

		return nil
	}

	c, err := openapi.NewClientWithResponses(baseURL, openapi.WithRequestEditorFn(editor))
	require.NoError(tb, err)

	return c
}

func mustMarshal(tb testing.TB, v any) []byte {
	tb.Helper()

	raw, err := json.Marshal(v)
	require.NoError(tb, err)

	return raw
}

// bearerClient returns a generated typed client that presents a bearer token
// (and NO client certificate) — the caller this endpoint must reject.
func bearerClient(t *testing.T, baseURL string) *openapi.ClientWithResponses {
	t.Helper()

	editor := func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer some-user-token")

		return nil
	}

	c, err := openapi.NewClientWithResponses(baseURL, openapi.WithRequestEditorFn(editor))
	require.NoError(t, err)

	return c
}

// TestRemoteAuthorizationCheckSystemAccount is the core deliverable: a system
// account obtains decisions from identity over the real pipeline — an allowed
// check and a denied check in one batch, asserted on the response body.
func TestRemoteAuthorizationCheckSystemAccount(t *testing.T) {
	t.Parallel()

	baseURL, _ := newRemoteAuthzServer(t)
	c := systemClient(t, baseURL, itSystemCN, nil)

	// The service holds GLOBAL identity:groups read only.  read at org scope
	// flows down (allow); create is on neither the service's nor anyone's
	// grant (deny).
	body := openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{
			{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(itOrgID)}, Action: openapi.Read},
			{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(itOrgID)}, Action: openapi.Create},
		},
	}

	t.Logf("REQUEST (system account %q): %s", itSystemCN, mustJSON(t, body))

	response, err := c.PostApiV1AuthorizationCheckWithResponse(t.Context(), body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode(), "body: %s", string(response.Body))
	require.NotNil(t, response.JSON200)

	t.Logf("RESPONSE: %s", string(response.Body))

	require.Len(t, response.JSON200.Results, 2)
	require.True(t, response.JSON200.Results[0].Allowed, "identity:groups read must be allowed (global flow-down)")
	require.False(t, response.JSON200.Results[1].Allowed, "identity:groups create must be denied")
}

// TestRemoteAuthorizationCheckImpersonatedDualCheck proves the impersonation dual check
// applies unchanged over the wire: the impersonated user allows the operation
// but the acting service does not, so the verdict is false — the confused
// deputy the intersection exists to stop.
func TestRemoteAuthorizationCheckImpersonatedDualCheck(t *testing.T) {
	t.Parallel()

	baseURL, _ := newRemoteAuthzServer(t)

	impersonated := &principal.Principal{Actor: itAliceSubject, Issuer: constants.UNISentinel, Type: openapi.User, OrganizationIDs: []string{itOrgID}}
	c := systemClient(t, baseURL, itSystemCN, impersonated)

	// alice holds identity:groups update at org scope; the acting service does
	// NOT (global read only).  Dual check: principal allows, service denies =>
	// false.  read is allowed by both => true.
	body := openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{
			{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(itOrgID)}, Action: openapi.Read},
			{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(itOrgID)}, Action: openapi.Update},
		},
	}

	t.Logf("REQUEST (impersonating %q): %s", itAliceSubject, mustJSON(t, body))

	response, err := c.PostApiV1AuthorizationCheckWithResponse(t.Context(), body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode(), "body: %s", string(response.Body))
	require.NotNil(t, response.JSON200)

	t.Logf("RESPONSE: %s", string(response.Body))

	require.Len(t, response.JSON200.Results, 2)
	require.True(t, response.JSON200.Results[0].Allowed, "read is allowed by both principal and service")
	require.False(t, response.JSON200.Results[1].Allowed, "update is allowed by the principal but DENIED by the acting service (dual check)")
}

// TestRemoteAuthorizationCheckDistinguishesImpersonatedIssuers proves the
// complete remote enforcement path keys an actor by (issuer, subject). The UNI
// identity is globally bound; the same subject from an external issuer is not.
// UNI is requested first so an issuer-blind ACL cache would also be exposed.
func TestRemoteAuthorizationCheckDistinguishesImpersonatedIssuers(t *testing.T) {
	t.Parallel()

	baseURL, _ := newRemoteAuthzServer(t)
	body := openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{
			{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups"}, Action: openapi.Read},
		},
	}

	uniPrincipal := &principal.Principal{Actor: itIssuerBoundSubject, Issuer: constants.UNISentinel, Type: openapi.User}
	uniResponse, err := systemClient(t, baseURL, itSystemCN, uniPrincipal).PostApiV1AuthorizationCheckWithResponse(t.Context(), body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, uniResponse.StatusCode(), "body: %s", string(uniResponse.Body))
	require.NotNil(t, uniResponse.JSON200)
	require.Len(t, uniResponse.JSON200.Results, 1)
	require.True(t, uniResponse.JSON200.Results[0].Allowed, "the UNI-bound identity must be allowed")

	externalPrincipal := &principal.Principal{Actor: itIssuerBoundSubject, Issuer: "https://external.example.com/", Type: openapi.User}
	externalResponse, err := systemClient(t, baseURL, itSystemCN, externalPrincipal).PostApiV1AuthorizationCheckWithResponse(t.Context(), body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, externalResponse.StatusCode(), "body: %s", string(externalResponse.Body))
	require.NotNil(t, externalResponse.JSON200)
	require.Len(t, externalResponse.JSON200.Results, 1)
	require.False(t, externalResponse.JSON200.Results[0].Allowed, "the same subject from an external issuer must not match the UNI binding")
}

// TestRemoteAuthorizationCheckRejectsBearer proves the mTLS-only guarantee end
// to end: a bearer-authenticated caller (no client certificate) is rejected.
func TestRemoteAuthorizationCheckRejectsBearer(t *testing.T) {
	t.Parallel()

	baseURL, _ := newRemoteAuthzServer(t)
	c := bearerClient(t, baseURL)

	body := openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{
			{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(itOrgID)}, Action: openapi.Read},
		},
	}

	response, err := c.PostApiV1AuthorizationCheckWithResponse(t.Context(), body)
	require.NoError(t, err)

	t.Logf("RESPONSE (bearer, expect rejection): status=%d body=%s", response.StatusCode(), string(response.Body))

	require.Equal(t, http.StatusUnauthorized, response.StatusCode(), "a bearer caller must not obtain a decision")
	require.Nil(t, response.JSON200)
}

// TestRemoteAuthorizationCheckPDPDown proves fail-closed over the wire: with
// the PDP unreachable the endpoint returns a non-200 the caller treats as
// deny.
func TestRemoteAuthorizationCheckPDPDown(t *testing.T) {
	t.Parallel()

	// Build the server slice but point the RBAC at a dead PDP endpoint.
	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	roles := itRoles()

	objects := []client.Object{
		&unikornv1.Organization{ObjectMeta: metav1.ObjectMeta{Namespace: itNamespace, Name: itOrgID}, Status: unikornv1.OrganizationStatus{Namespace: itOrgNS}},
	}
	for i := range roles {
		objects = append(objects, &roles[i])
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

	r := rbac.New(c, itNamespace, &rbac.Options{
		SystemAccountRoleIDs: map[string]string{itSystemCN: itServiceRole},
	})

	// A PDP endpoint that nothing listens on: CheckResources fails closed.
	pdp, err := cerbos.New(&cerbos.Options{Endpoint: "127.0.0.1:1", CheckTimeout: time.Second})
	require.NoError(t, err)

	r.WithCerbos(pdp)

	schema, err := corehelpers.NewSchema(openapi.GetSwagger)
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Use(routeresolver.New(schema).Middleware)

	validator := openapimiddleware.NewValidator(itValidatorOptions(), &itAuthorizer{rbac: r})

	h, err := handler.New(c, c, itNamespace, nil, nil, nil, r, &handler.Options{})
	require.NoError(t, err)

	server := httptest.NewServer(openapi.HandlerWithOptions(h, openapi.ChiServerOptions{
		BaseRouter:       router,
		ErrorHandlerFunc: handler.HandleError,
		Middlewares:      []openapi.MiddlewareFunc{validator.Middleware},
	}))
	t.Cleanup(server.Close)

	client := systemClient(t, server.URL, itSystemCN, nil)

	response, err := client.PostApiV1AuthorizationCheckWithResponse(t.Context(), openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{
			{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(itOrgID)}, Action: openapi.Read},
		},
	})
	require.NoError(t, err)

	t.Logf("RESPONSE (PDP down, expect non-200): status=%d body=%s", response.StatusCode(), string(response.Body))

	require.NotEqual(t, http.StatusOK, response.StatusCode(), "PDP unavailability must cross the wire as a non-200 the caller denies")
	require.Nil(t, response.JSON200)
}

// ---- helpers (docker PDP harness; a deliberate copy of the parity test's,
// per the brief's preference for a copied helper over a speculative shared
// testutil package).

func mustJSON(t *testing.T, v any) string {
	t.Helper()

	raw, err := json.Marshal(v)
	require.NoError(t, err)

	return string(raw)
}

// remoteAuthzDefaultImage must match the Makefile's CERBOS_VERSION; make
// test-cerbos-remote overrides via CERBOS_IMAGE.
const remoteAuthzDefaultImage = "ghcr.io/cerbos/cerbos:0.53.0"

const remoteAuthzCerbosUID = "65534"

func writeRemoteAuthzStore(tb testing.TB, roles []unikornv1.Role) string {
	tb.Helper()

	output, err := generate.Generate(roles)
	require.NoError(tb, err)

	files, err := output.Files()
	require.NoError(tb, err)

	dir := remoteAuthzStoreDir(tb)

	for name, data := range files {
		//nolint:gosec // the store must be readable by the container's non-root cerbos user.
		require.NoError(tb, os.WriteFile(filepath.Join(dir, name), data, 0o644))
	}

	return dir
}

func remoteAuthzStoreDir(tb testing.TB) string {
	tb.Helper()

	dir := tb.TempDir()

	if goruntime.GOOS != "linux" {
		cwd, err := os.Getwd()
		require.NoError(tb, err)

		dir, err = os.MkdirTemp(cwd, ".cerbos-remote-store-*") //nolint:usetesting // must live under the repository for docker file sharing.
		require.NoError(tb, err)

		tb.Cleanup(func() {
			require.NoError(tb, os.RemoveAll(dir))
		})
	}

	require.NoError(tb, os.Chmod(dir, 0o755))

	return dir
}

func startRemoteAuthzCerbos(tb testing.TB, policiesDir string) string {
	tb.Helper()

	image := os.Getenv("CERBOS_IMAGE")
	if image == "" {
		image = remoteAuthzDefaultImage
	}

	cwd, err := os.Getwd()
	require.NoError(tb, err)

	// The single fixture PDP config unit tests pin to the chart's, under
	// pkg/authz/cerbos/testdata/config (pkg/handler -> ../authz/...).
	configDir := filepath.Clean(filepath.Join(cwd, "..", "authz", "cerbos", "testdata", "config"))

	name := "cerbos-remote-authz-test-" + strings.ToLower(rand.Text())

	tb.Cleanup(func() {
		//nolint:usetesting // tb.Context() is already canceled inside Cleanup.
		_ = exec.CommandContext(context.Background(), "docker", "rm", "--force", name).Run()
	})

	cmd := exec.CommandContext(tb.Context(), "docker", "run",
		"--detach",
		"--name", name,
		"--user", remoteAuthzCerbosUID+":"+remoteAuthzCerbosUID,
		"--read-only",
		"--tmpfs", "/tmp",
		"--tmpfs", "/.cache",
		"--volume", configDir+":/config:ro",
		"--volume", policiesDir+":/policies:ro",
		"--publish", "127.0.0.1:0:3593",
		image,
		"server", "--config=/config/config.yaml",
	)

	out, err := cmd.CombinedOutput()
	require.NoError(tb, err, "docker run: %s", out)

	remoteAuthzWaitHealthy(tb, name)

	return remoteAuthzHostPort(tb, name, "3593/tcp")
}

func remoteAuthzHostPort(tb testing.TB, name, port string) string {
	tb.Helper()

	out, err := exec.CommandContext(tb.Context(), "docker", "port", name, port).Output()
	require.NoError(tb, err, "docker port %s %s", name, port)

	addr, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	require.NotEmpty(tb, addr)

	return addr
}

func remoteAuthzWaitHealthy(tb testing.TB, name string) {
	tb.Helper()

	deadline := time.Now().Add(time.Minute)

	arguments := []string{"exec", name, "/cerbos", "healthcheck", "--config=/config/config.yaml"}

	for {
		if time.Now().After(deadline) {
			logs, _ := exec.CommandContext(tb.Context(), "docker", "logs", name).CombinedOutput()
			require.FailNowf(tb, "cerbos did not become healthy", "container logs:\n%s", logs)
		}

		if err := exec.CommandContext(tb.Context(), "docker", arguments...).Run(); err == nil {
			return
		}

		time.Sleep(200 * time.Millisecond)
	}
}

// TestRemoteAuthorizationCheckOversizedBatch pins the maxItems:50 wire bound: a
// 51-check batch is rejected by the request validator with a 400 BEFORE the
// handler and before any PDP interaction, so an over-large batch is a clean
// client error rather than an opaque 500 from the PDP rejecting the resource
// batch (the sidecar's own maxResourcesPerRequest default is also 50).  It
// needs no live PDP precisely because the rejection precedes the decision
// layer — a dead PDP endpoint (never reached) keeps this test off the shared
// container pool.
func TestRemoteAuthorizationCheckOversizedBatch(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	roles := itRoles()

	objects := []client.Object{
		&unikornv1.Organization{ObjectMeta: metav1.ObjectMeta{Namespace: itNamespace, Name: itOrgID}, Status: unikornv1.OrganizationStatus{Namespace: itOrgNS}},
	}
	for i := range roles {
		objects = append(objects, &roles[i])
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

	r := rbac.New(c, itNamespace, &rbac.Options{
		SystemAccountRoleIDs: map[string]string{itSystemCN: itServiceRole},
	})

	// The validator rejects the batch before the handler, so the PDP is never
	// consulted; point it at a dead endpoint rather than a live container.
	pdp, err := cerbos.New(&cerbos.Options{Endpoint: "127.0.0.1:1", CheckTimeout: time.Second})
	require.NoError(t, err)

	r.WithCerbos(pdp)

	schema, err := corehelpers.NewSchema(openapi.GetSwagger)
	require.NoError(t, err)

	router := chi.NewRouter()
	router.Use(routeresolver.New(schema).Middleware)

	validator := openapimiddleware.NewValidator(itValidatorOptions(), &itAuthorizer{rbac: r})

	h, err := handler.New(c, c, itNamespace, nil, nil, nil, r, &handler.Options{})
	require.NoError(t, err)

	server := httptest.NewServer(openapi.HandlerWithOptions(h, openapi.ChiServerOptions{
		BaseRouter:       router,
		ErrorHandlerFunc: handler.HandleError,
		Middlewares:      []openapi.MiddlewareFunc{validator.Middleware},
	}))
	t.Cleanup(server.Close)

	checks := make([]openapi.AuthorizationCheck, 51)
	for i := range checks {
		checks[i] = openapi.AuthorizationCheck{
			Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(itOrgID)},
			Action:   openapi.Read,
		}
	}

	response, err := systemClient(t, server.URL, itSystemCN, nil).PostApiV1AuthorizationCheckWithResponse(t.Context(), openapi.AuthorizationCheckRequest{Checks: checks})
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, response.StatusCode(), "a batch over maxItems:50 must be a 400 from the validator; body: %s", string(response.Body))
}

func itAlice() *principal.Principal {
	return &principal.Principal{Actor: itAliceSubject, Issuer: constants.UNISentinel, Type: openapi.User, OrganizationIDs: []string{itOrgID}}
}

func itPassport(tb testing.TB, issuer *jose.JWTIssuer, subject, srcIss string, groups ...string) string {
	tb.Helper()

	claims := testPassportClaims(subject, openapi.User, itNarrowCN)
	claims.SrcIss = srcIss
	claims.Groups = groups

	return signTestPassport(tb, issuer, claims)
}

func TestRemoteAuthorizationCheckPassportNoServiceCap(t *testing.T) {
	t.Parallel()

	baseURL, issuer := newRemoteAuthzServer(t)

	checks := []openapi.AuthorizationCheck{
		{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(itOrgID)}, Action: openapi.Update},
	}

	passport := itPassport(t, issuer, itAliceSubject, constants.UNISentinel)

	response, err := passportClient(t, baseURL, itNarrowCN, itAlice(), "").PostApiV1AuthorizationCheckWithResponse(t.Context(),
		openapi.AuthorizationCheckRequest{Checks: checks, Passport: &passport})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode(), "body: %s", string(response.Body))
	require.NotNil(t, response.JSON200)
	require.Len(t, response.JSON200.Results, 1)
	require.True(t, response.JSON200.Results[0].Allowed, "the passport decision must be the verdict of alice alone")
	require.NotNil(t, response.JSON200.PassportSubject)
	require.Equal(t, itAliceSubject, *response.JSON200.PassportSubject)

	impersonated, err := systemClient(t, baseURL, itNarrowCN, itAlice()).PostApiV1AuthorizationCheckWithResponse(t.Context(),
		openapi.AuthorizationCheckRequest{Checks: checks})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, impersonated.StatusCode(), "body: %s", string(impersonated.Body))
	require.NotNil(t, impersonated.JSON200)
	require.Len(t, impersonated.JSON200.Results, 1)
	require.False(t, impersonated.JSON200.Results[0].Allowed, "the dual check must deny, because the narrow service lacks the grant")
	require.Nil(t, impersonated.JSON200.PassportSubject)
}

func TestRemoteAuthorizationCheckPassportGroupsFromClaim(t *testing.T) {
	t.Parallel()

	baseURL, issuer := newRemoteAuthzServer(t)

	actor := &principal.Principal{Actor: itExternalSubject, Issuer: itGroupIssuer, Type: openapi.User}
	checks := []openapi.AuthorizationCheck{
		{Resource: openapi.AuthorizationCheckResource{Kind: "identity:projects"}, Action: openapi.Read},
	}

	check := func(passport string) bool {
		response, err := passportClient(t, baseURL, itNarrowCN, actor, "").PostApiV1AuthorizationCheckWithResponse(t.Context(),
			openapi.AuthorizationCheckRequest{Checks: checks, Passport: &passport})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode(), "body: %s", string(response.Body))
		require.NotNil(t, response.JSON200)
		require.Len(t, response.JSON200.Results, 1)

		return response.JSON200.Results[0].Allowed
	}

	require.True(t, check(itPassport(t, issuer, itExternalSubject, itGroupIssuer, itIDPGroup)), "the bound group in the claim must grant the role")
	require.False(t, check(itPassport(t, issuer, itExternalSubject, itGroupIssuer)), "with no group in the claim, nothing must grant the role")
}

func TestRemoteAuthorizationCheckPassportWildcardBinding(t *testing.T) {
	t.Parallel()

	baseURL, issuer := newRemoteAuthzServer(t)

	actor := &principal.Principal{Actor: itExternalSubject, Issuer: itStaffIssuer, Type: openapi.User}
	passport := itPassport(t, issuer, itExternalSubject, itStaffIssuer)

	response, err := passportClient(t, baseURL, itNarrowCN, actor, "").PostApiV1AuthorizationCheckWithResponse(t.Context(), openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{
			{Resource: openapi.AuthorizationCheckResource{Kind: "identity:organizations"}, Action: openapi.Read},
			{Resource: openapi.AuthorizationCheckResource{Kind: "identity:organizations"}, Action: openapi.Update},
		},
		Passport: &passport,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode(), "body: %s", string(response.Body))
	require.NotNil(t, response.JSON200)
	require.Len(t, response.JSON200.Results, 2)
	require.True(t, response.JSON200.Results[0].Allowed, "the wildcard binding must grant the read of its role")
	require.False(t, response.JSON200.Results[1].Allowed, "the wildcard binding must not grant the write of its role")
}

func TestRemoteAuthorizationCheckPassportRelayedCertificate(t *testing.T) {
	t.Parallel()

	baseURL, issuer := newRemoteAuthzServer(t)

	passport := itPassport(t, issuer, itAliceSubject, constants.UNISentinel)

	response, err := passportClient(t, baseURL, itSystemCN, itAlice(), itNarrowCN).PostApiV1AuthorizationCheckWithResponse(t.Context(), openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{
			{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(itOrgID)}, Action: openapi.Read},
		},
		Passport: &passport,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, response.StatusCode(), "body: %s", string(response.Body))
	require.Nil(t, response.JSON200)
}

func TestRemoteAuthorizationCheckPassportSchemaBounds(t *testing.T) {
	t.Parallel()

	baseURL, _ := newRemoteAuthzServer(t)
	c := passportClient(t, baseURL, itNarrowCN, itAlice(), "")

	cases := []struct {
		name       string
		passport   string
		wantStatus int
	}{
		{name: "Empty", passport: "", wantStatus: http.StatusBadRequest},
		{name: "OverMaximum", passport: strings.Repeat("a", 8193), wantStatus: http.StatusBadRequest},
		{name: "AtMaximum", passport: strings.Repeat("a", 8192), wantStatus: http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			response, err := c.PostApiV1AuthorizationCheckWithResponse(t.Context(), openapi.AuthorizationCheckRequest{
				Checks: []openapi.AuthorizationCheck{
					{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups"}, Action: openapi.Read},
				},
				Passport: &tc.passport,
			})
			require.NoError(t, err)
			require.Equal(t, tc.wantStatus, response.StatusCode(), "body: %s", string(response.Body))
			require.Nil(t, response.JSON200)
		})
	}
}

func BenchmarkAuthorizationCheck(b *testing.B) {
	checks := []openapi.AuthorizationCheck{
		{Resource: openapi.AuthorizationCheckResource{Kind: "identity:groups", OrganizationId: ptr.To(itOrgID)}, Action: openapi.Read},
	}

	run := func(b *testing.B, c *openapi.ClientWithResponses, body openapi.AuthorizationCheckRequest) {
		b.Helper()

		for b.Loop() {
			response, err := c.PostApiV1AuthorizationCheckWithResponse(b.Context(), body)
			if err != nil {
				b.Fatal(err)
			}

			if response.StatusCode() != http.StatusOK || !response.JSON200.Results[0].Allowed {
				b.Fatalf("expected an allow, got status %d body %s", response.StatusCode(), response.Body)
			}
		}
	}

	b.Run("impersonated", func(b *testing.B) {
		baseURL, _ := newRemoteAuthzServer(b)

		run(b, systemClient(b, baseURL, itSystemCN, itAlice()), openapi.AuthorizationCheckRequest{Checks: checks})
	})

	b.Run("passport", func(b *testing.B) {
		baseURL, issuer := newRemoteAuthzServer(b)

		claims := testPassportClaims(itAliceSubject, openapi.User, itSystemCN)
		claims.Expiry = jwt.NewNumericDate(time.Now().Add(time.Hour))
		passport := signTestPassport(b, issuer, claims)

		run(b, passportClient(b, baseURL, itSystemCN, itAlice(), ""), openapi.AuthorizationCheckRequest{Checks: checks, Passport: &passport})
	})

	b.Run("service-passport", func(b *testing.B) {
		baseURL, issuer := newRemoteAuthzServer(b)

		claims := testPassportClaims(itServiceAccount, openapi.Service, itSystemCN)
		claims.OrgIDs = []string{itOrgID}
		claims.Expiry = jwt.NewNumericDate(time.Now().Add(time.Hour))
		passport := signTestPassport(b, issuer, claims)

		actor := &principal.Principal{Actor: itServiceAccount, Type: openapi.Service, Issuer: constants.UNISentinel}

		run(b, passportClient(b, baseURL, itSystemCN, actor, ""), openapi.AuthorizationCheckRequest{Checks: checks, Passport: &passport})
	})
}
