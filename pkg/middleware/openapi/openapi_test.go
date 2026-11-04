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

package openapi_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/go-chi/chi/v5"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/openapi/helpers"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/mock"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/util"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// userActor is used as a sentinel to track end user propagation.
	userActor = "joe@acme.com"
	// serviceActor is used as a sentinel to track service propagation.
	serviceActor = "my-service"
	// serviceActorURI is encoded in the certificate, just in case.
	// serviceActorURI = "spiffe://my-platform/my-service"
	// servicePrivateKey is the pkey of an invoking service, base64 encoded
	// to avoid GitHub being all clever.
	servicePrivateKey = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2d0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktrd2dnU2xBZ0VBQW9JQkFRRFJMWUVIbW9SWC90aGIKK0RHZEw0NVVJM3R0Y0NPTG15L3JvdFhxdEllcmNHZ3N1c2lUZW5sWERVL0hRQ0hjL2hBaGY1VTYxcFdVUS9vOQpBQlRoamtjSUVSMnZPRUpSSnlYTVNLSzFNbUdkTHZ0K0ZRK0xCbTJidjd4b1M0Y2pRSm9rVW9zeHlaZjFITEhBCng0d1pUT3hPRkFubjBYK1BmeklISllNL3k3Q1JVRjd4VlVjMlpvMS9hRkI5ZXE0Yk9JdjRld25xSzgycXV4Y24KYzRpTitvRjZEdjAyQmJTSVVTK3N1UDlpWlhZMURFOHhUaUtKYkU2ZjNTOWpZUjFMSEZndWpTSUg1TWhVemNXNgpGMk1FTkhhdVpZbFQ1dDlCQU9uS3hmTVNhdGxvVW5HdmxLb0VPbW40Y2xXdzkyamdzZ0hrM3VUWHRqZHNydUdOCm91L253MDUvQWdNQkFBRUNnZ0VBU2tpQUZWeXNtZmxCQ1d3YTVtaXdnVFcyaTljeWNFMzBseGdWSW92bzBCdVQKaXlycnR0L2IvbXVXUkxxRUxCQTNWMFlSRHp1TUZBS045Nkt6UjZSNG1pZEY1T2MwT2RDT3JqeXZOMnpFV0ljSwpQYXlwLytPUkFpbjFkUTQ1Vis0RnIxZDI0Zi9tekY5YnlvdXl0M3RuUVpVQkxZZHE1dUV6T1hGN2FpamlNNy8wCkU4UlRISmJhTlI2Vkszb29yR25VN0hwalJsL2RmbE5TZEJRVkpzSzB6K2VJY1M4R2l5YTB5ZTBqbk1PbHJOZXkKcWdDcnF5TlhGbkpJQnJnRkppcEdEQXFGVGpFWTlkSG1hUjBQSTRZcUpOMEF5OS9ubWNEZjJVcFhmWFZDY3A1Kwo4aVBmZVNwdHhzZ3R6d3hKUkUwN3p1V0Z3SzlPekRJL3NGWkIvaHhsRVFLQmdRRG9JWW5jUWtZZFdTUUV0MHRRCm0wZkNHV1ExcjcyUkZkOTBySDZUc2lsVW92YXp4R01FWGhIYS9aQjZzT0NDZ1dyZDRuWUVzc2tKNkxEUHVqVDkKU0NzS3gyekx6ZzduQllWZVNzbWVGRlJ0d3NpL1VlbUVNOHhLN2hydEJha2FHK1Fha0JLWUMvdk5HOWplMEQrZwpOTTVaUlF5TTVVajJPK1puRHExUkF4WnowUUtCZ1FEbXI4SmR6ZlB2a0dZcElyb1JxQS9LOW1aRC9oNDZES21aCmkxQWJvT3ZOOGZVcXI4QTBBcHpxbGZWNngwQnowSVhIU05BT3RIMURIM2ZDalpSTEJKMkpyV2hoY0EzQnI4aSsKeUdFUXZBMXg2c1QxUDZtVHhQdHk1bThERlFhYkkzcmhFdEVHT2lmTTFaVUtvTDQwUmo5R0FBbU4rQ3I4ejdCWApVQXFGbUhYQlR3S0JnUUNNUkIvYXNVMU8xSnQ0SWczbmdqMEZJM1N6SUNOck5RMVdvaGpHUklURytNWWI4RkpvCnhETUQ0ZTVZeE9LVTJZRHEzTG0xc3hiWjN2cGdPME5qdlNVTkdWNDdkS0w2cEJKbjNNY2h0MlVoQWU5dDlDQW4KMjJqWjZqRHBBbCtoUUROQWZjaE9pZ2M0ZEZoQ294R2ZTK2xZZGVuVWhZUG1EbUgxNmg5K2NXQXkwUUtCZ1FDcAphVkFEVlptY1NGNU9QVnVLVmZMcktkTG1nZnV1dzlmVmxCTExoMzFFckRsUkZPckJCMTQzaE5OWFRIYlAxc1k0CkdRZjZsS0FkS0VIcUZkRmUyay9iYVFicjc3K2FpejZRcFZWclZiOUY5cFNZU3gxOUVMOWNuVS9QWXFTTVVCMFEKcDZIcndjK3l4UE9FYjVIZmorc3R2QjlJTElWZFRpVUJxaDFnQ1J3SlR3S0JnUUNwSHZsRnF2RGlwbEx0VW5CZgpwdnkrMlVJQkU2cHhxL29RN2lhdkg3c2tqWml0clN3bWR1UVdTeVdqV2xGa3hHN0hEbCswVmd0dEFNUDJVTW1MCkMvN3BRcWlZZ3F3YjVVVjlPRUtDU0dQMWRtYlJmanc2b3RLSjkzRzNPd1VyWXNPSU0yUW0wS21uQmc3VXRIUTcKRlF0N3pwRFJ5dnd5dzQwQi8vbFhzT293NGc9PQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0t"
	// serviceCertificate is the matching self-signed certificate of the private key.
	serviceCertificate = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURxakNDQXBLZ0F3SUJBZ0lVRDNERm5jZDNjNG9MNEYwUVd1UkpRRlI0UGRNd0RRWUpLb1pJaHZjTkFRRUwKQlFBd1JURVRNQkVHQTFVRUF3d0tiWGt0YzJWeWRtbGpaVEVMTUFrR0ExVUVCaE1DUjBJeEVEQU9CZ05WQkFnTQpCMFZ1WjJ4aGJtUXhEekFOQmdOVkJBY01Ca3h2Ym1SdmJqQWVGdzB5TlRBM01UWXhNekF3TXpoYUZ3MHlOakEzCk1UWXhNekF3TXpoYU1FVXhFekFSQmdOVkJBTU1DbTE1TFhObGNuWnBZMlV4Q3pBSkJnTlZCQVlUQWtkQ01SQXcKRGdZRFZRUUlEQWRGYm1kc1lXNWtNUTh3RFFZRFZRUUhEQVpNYjI1a2IyNHdnZ0VpTUEwR0NTcUdTSWIzRFFFQgpBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRRFJMWUVIbW9SWC90aGIrREdkTDQ1VUkzdHRjQ09MbXkvcm90WHF0SWVyCmNHZ3N1c2lUZW5sWERVL0hRQ0hjL2hBaGY1VTYxcFdVUS9vOUFCVGhqa2NJRVIydk9FSlJKeVhNU0tLMU1tR2QKTHZ0K0ZRK0xCbTJidjd4b1M0Y2pRSm9rVW9zeHlaZjFITEhBeDR3WlRPeE9GQW5uMFgrUGZ6SUhKWU0veTdDUgpVRjd4VlVjMlpvMS9hRkI5ZXE0Yk9JdjRld25xSzgycXV4Y25jNGlOK29GNkR2MDJCYlNJVVMrc3VQOWlaWFkxCkRFOHhUaUtKYkU2ZjNTOWpZUjFMSEZndWpTSUg1TWhVemNXNkYyTUVOSGF1WllsVDV0OUJBT25LeGZNU2F0bG8KVW5HdmxLb0VPbW40Y2xXdzkyamdzZ0hrM3VUWHRqZHNydUdOb3UvbncwNS9BZ01CQUFHamdaRXdnWTR3SFFZRApWUjBPQkJZRUZEa2NUUjM4ZEZTbFVuSkZ1VlFid3B6UVRCOUtNQjhHQTFVZEl3UVlNQmFBRkRrY1RSMzhkRlNsClVuSkZ1VlFid3B6UVRCOUtNQXNHQTFVZER3UUVBd0lIZ0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREFqQXEKQmdOVkhSRUVJekFoaGg5emNHbG1abVU2THk5dGVTMXdiR0YwWm05eWJTOXRlUzF6WlhKMmFXTmxNQTBHQ1NxRwpTSWIzRFFFQkN3VUFBNElCQVFBVitTTmIzNktzNTIxSW9LSjlCUzRxZzcwUWxkOEthWERsZ2taV1BFRytpem9SCk5ISXo3c0tjWGdMTU5uN3dLNHdsNkQ4cE9VcFhEZitnTkhIcWpJNHRBTXIwdFY1cEtlbHBIU0RQWUZvTGd3U2gKVnJ3QzZwaW0zYzNndms4WmxGQ3AzWG1oSGdCQ1Rab2x2VFpSbXZPR0h6YzA0dHdxbDUwaVVWUjk3aU02RCtNaQpPZTlQUjBSVUNyakt3bERjTnpPNUpaVENuZHhWQysvVUJjeTVTZUwrakZWbW1Ra1N6dEJqMGtvdE5kVDNEaHUwCnkzbTVrNWFzR0hRY3I1QmcxQUd3QUFBZjNSOFJJUlFmRDJtOVFWT3BsLytPdzRpZHJsVU5kMDJiay9Xd3FjMEwKcFBqZ0JJOThjVzg2enB0c3JHdEhEUXFZeHVLa1ZLT1gwcnh3Z3QrVAotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t"
	// authenticatedURL is an unscoped URL that requires authentication.
	authenticatedURL = "https://localhost/protected"
	// validatedBodyURL is a URL whose request body is schema validated.
	validatedBodyURL = "https://localhost/token"
	// requiredParameterURL is a URL with a required query parameter.
	requiredParameterURL = "https://localhost/search"
	// secretToken is a sentinel to track credentials in the request body
	// leaking back out again.
	secretToken = "not-for-your-eyes"
)

//go:embed "testdata/toyschema.yaml"
var toySchema []byte

// validateError checks that the response body is an error and is as we expect.
func validateError(t *testing.T, w *httptest.ResponseRecorder, validator func(error) bool) {
	t.Helper()

	require.NotNil(t, w.Body)

	oauthError := &coreapi.Error{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), oauthError))

	err := errors.FromOpenAPIError(w.Code, w.Header(), oauthError)
	require.True(t, validator(err))
}

// addCertificateHeader adds a client certificate to the request, pretending to
// be ingress-nginx.
func addCertificateHeader(t *testing.T, r *http.Request, verified bool) {
	t.Helper()

	certPEM, err := base64.RawURLEncoding.DecodeString(serviceCertificate)
	require.NoError(t, err)

	r.Header.Set("Ssl-Client-Cert", url.QueryEscape(string(certPEM)))

	if verified {
		r.Header.Set("Ssl-Client-Verify", "SUCCESS")
	}
}

func addCertificateHeaderForCN(t *testing.T, r *http.Request, verified bool, commonName string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})

	r.Header.Set("Ssl-Client-Cert", url.QueryEscape(string(certPEM)))

	if verified {
		r.Header.Set("Ssl-Client-Verify", "SUCCESS")
	}
}

func addRelayedCertificateHeader(t *testing.T, r *http.Request) {
	t.Helper()

	certPEM, err := base64.RawURLEncoding.DecodeString(serviceCertificate)
	require.NoError(t, err)

	r.Header.Set("Unikorn-Client-Certificate", url.QueryEscape(string(certPEM)))
}

// addPrincipalHeaderLegacy digitally signs a principal and adds to the request.
func addPrincipalHeaderLegacy(t *testing.T, r *http.Request) {
	t.Helper()

	p := &principal.Principal{
		Actor: userActor,
	}

	// TODO: we may want to consider making the core function available
	// rather than reimplmenting it.
	dataJSON, err := json.Marshal(p)
	require.NoError(t, err)

	keyPEM, err := base64.RawURLEncoding.DecodeString(servicePrivateKey)
	require.NoError(t, err)

	certPEM, err := base64.RawURLEncoding.DecodeString(serviceCertificate)
	require.NoError(t, err)

	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	signingKey := jose.SigningKey{
		Algorithm: jose.PS512,
		Key:       certificate.PrivateKey,
	}

	signer, err := jose.NewSigner(signingKey, nil)
	require.NoError(t, err)

	signedData, err := signer.Sign(dataJSON)
	require.NoError(t, err)

	value, err := signedData.CompactSerialize()
	require.NoError(t, err)

	r.Header.Set(principal.Header, value)
}

// addPrincipalHeader encodes principal and adds to the request.
func addPrincipalHeader(t *testing.T, r *http.Request) {
	t.Helper()

	p := &principal.Principal{
		Type:  identityapi.User,
		Actor: userActor,
	}

	dataJSON, err := json.Marshal(p)
	require.NoError(t, err)

	r.Header.Set(principal.Header, base64.RawURLEncoding.EncodeToString(dataJSON))
}

func addPrincipalHeaderWithoutActor(t *testing.T, r *http.Request) {
	t.Helper()

	p := &principal.Principal{}

	dataJSON, err := json.Marshal(p)
	require.NoError(t, err)

	r.Header.Set(principal.Header, base64.RawURLEncoding.EncodeToString(dataJSON))
}

// addAuthorizationHeader adds a token to the request.
func addAuthorizationHeader(tb testing.TB, r *http.Request) {
	tb.Helper()

	r.Header.Set("Authorization", "bearer foo")
}

// authInfoFixture creates a fixture to be returned from the Authorizer interface
// on successful authentication.
func authInfoFixture(accountType identityapi.AuthClaimsAcctype) *authorization.Info {
	authz := &identityapi.AuthClaims{
		Acctype: accountType,
	}

	if accountType == "" {
		authz = nil
	}

	return &authorization.Info{
		Userinfo: &identityapi.Userinfo{
			Sub:                       userActor,
			HttpsunikornCloudOrgauthz: authz,
		},
	}
}

// handler is a HTTP handler that records expected things that should exist in
// hte request context and allows inspection of them.
type handler struct {
	authinfo  *authorization.Info
	acl       *identityapi.Acl
	principal *principal.Principal
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authinfo, err := authorization.FromContext(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusTeapot)
		return
	}

	h.authinfo = authinfo

	// TODO: no error checking... not that it's relevant.
	h.acl = rbac.FromContext(r.Context())

	principal, err := principal.FromContext(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusPaymentRequired)
		return
	}

	h.principal = principal

	w.WriteHeader(http.StatusOK)
}

// validate checks all the correct bits are set, and the actor and principal
// actors are correct.  The former is the parameter as that can change based
// on calling context.
func (h *handler) validate(t *testing.T, actor string, principalType identityapi.AuthClaimsAcctype) {
	t.Helper()

	// Check the authentication information is good for auditing.
	require.NotNil(t, h.authinfo)
	require.NotNil(t, h.authinfo.Userinfo)
	require.Equal(t, actor, h.authinfo.Userinfo.Sub)

	// Check the Acl is good for RBAC.
	require.NotNil(t, h.acl)

	// Check the principal information is good for further auditing and accounting.
	require.NotNil(t, h.principal)
	require.Equal(t, userActor, h.principal.Actor)

	if principalType != "" {
		require.Equal(t, principalType, h.principal.Type)
	}
}

// getSchema loads and validates the test schema that is defined for this
// test suite.
func getSchema(t *testing.T) *helpers.Schema {
	t.Helper()

	s, err := openapi3.NewLoader().LoadFromData(toySchema)
	require.NoError(t, err)

	getter := func() (*openapi3.T, error) {
		return s, nil
	}

	schema, err := helpers.NewSchema(getter)
	require.NoError(t, err)

	return schema
}

// getMux returns a HTTP handler that is compatible with the test schema that
// is defined for this test suite and installs the validation/authorization
// middleware and any prerequisite. middleware that it depends upon.  Accepts a
// hadnler that captures various things about the request if it makes it past
// the middlweare stage so that it can be validated for correctness.
func getMux(t *testing.T, authorizer openapi.Authorizer, handler *handler, opts ...openapi.ValidatorOption) http.Handler {
	t.Helper()

	options := &openapi.Options{
		ACLCacheSize:    1,
		ACLCacheTimeout: time.Minute,
	}

	routeresolver := routeresolver.New(getSchema(t))
	validator := openapi.NewValidator(options, authorizer, opts...)

	r := chi.NewRouter()
	r.Use(routeresolver.Middleware)
	r.Use(validator.Middleware)

	r.Group(func(r chi.Router) {
		r.Get("/protected", http.HandlerFunc(handler.ServeHTTP))
	})

	r.Group(func(r chi.Router) {
		r.Post("/upload", http.HandlerFunc(handler.ServeHTTP))
	})

	r.Group(func(r chi.Router) {
		r.Post("/token", http.HandlerFunc(handler.ServeHTTP))
	})

	r.Group(func(r chi.Router) {
		r.Get("/search", http.HandlerFunc(handler.ServeHTTP))
	})

	return r
}

// TestUserToServiceAuthenticationFailure tests we propagate the correct error when
// authentication fails.
func TestUserToServiceAuthenticationFailure(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().Authorize(gomock.Any()).Return(nil, errors.AccessDenied(r))

	h := &handler{}
	m := getMux(t, authorizer, h)

	w := httptest.NewRecorder()

	addAuthorizationHeader(t, r)

	m.ServeHTTP(w, r)

	require.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
	require.NotEmpty(t, w.Header().Get(errors.AuthenticateHeader))
}

// TestUserToServiceAuthenticationSuccess tests everything is in place when authentication
// succeeds.
func TestUserToServiceAuthenticationSuccess(t *testing.T) {
	t.Parallel()

	testUserToServiceAuthenticationSuccess(t, identityapi.User)
}

func TestUserToServiceAuthenticationSuccessServiceAccountPrincipal(t *testing.T) {
	t.Parallel()

	testUserToServiceAuthenticationSuccess(t, identityapi.Service)
}

func testUserToServiceAuthenticationSuccess(t *testing.T, principalType identityapi.AuthClaimsAcctype) {
	t.Helper()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().Authorize(gomock.Any()).Return(authInfoFixture(principalType), nil)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Return(&identityapi.Acl{}, nil)

	h := &handler{}
	m := getMux(t, authorizer, h)

	w := httptest.NewRecorder()

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)

	addAuthorizationHeader(t, r)

	m.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Result().StatusCode)
	h.validate(t, userActor, principalType)
}

// TestServiceToServiceMalformedCertificate tests the response when a client certificate is
// malformed.
func TestServiceToServiceMalformedCertificate(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)

	h := &handler{}
	m := getMux(t, authorizer, h)

	w := httptest.NewRecorder()

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)

	r.Header.Set("Ssl-Client-Cert", "cat")

	m.ServeHTTP(w, r)

	validateError(t, w, errors.IsBadRequest)
}

// TestServiceToServiceCertificateInvalid tests the response when a client certificate
// did not validate at the ingress.
func TestServiceToServiceCertificateInvalid(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)

	h := &handler{}
	m := getMux(t, authorizer, h)

	w := httptest.NewRecorder()

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)

	addCertificateHeader(t, r, false)

	m.ServeHTTP(w, r)

	validateError(t, w, errors.IsBadRequest)
}

// TestServiceToServiceAuthenticationDenyEscalation stops a case where a user can supply
// a relayed certificate, but do it without mTLS validation, thus allowing any system
// account to be trivially spoofed.
func TestServiceToServiceAuthenticationDenyEscalation(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)

	h := &handler{}
	m := getMux(t, authorizer, h)

	w := httptest.NewRecorder()

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)

	addRelayedCertificateHeader(t, r)

	m.ServeHTTP(w, r)

	require.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
}

// TestServiceToServicePrincipalMissing tests the response when a principal is missing.
func TestServiceToServicePrincipalMissing(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)

	h := &handler{}
	m := getMux(t, authorizer, h)

	w := httptest.NewRecorder()

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)

	addCertificateHeader(t, r, true)

	m.ServeHTTP(w, r)

	validateError(t, w, errors.IsBadRequest)
}

// TestServiceToServiceAuthenticationSuccessLegacy tests a full service to service authenticated
// API call.
func TestServiceToServiceAuthenticationSuccessLegacy(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Return(&identityapi.Acl{}, nil)

	h := &handler{}
	m := getMux(t, authorizer, h)

	w := httptest.NewRecorder()

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)

	addCertificateHeader(t, r, true)
	addPrincipalHeaderLegacy(t, r)

	m.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Result().StatusCode)
	h.validate(t, serviceActor, "")
}

func TestServiceToServiceAuthenticationSuccess(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Return(&identityapi.Acl{}, nil)

	h := &handler{}
	m := getMux(t, authorizer, h)

	w := httptest.NewRecorder()

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)

	addCertificateHeader(t, r, true)
	addPrincipalHeader(t, r)

	m.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Result().StatusCode)
	h.validate(t, serviceActor, "")
}

func TestServiceToServiceImpersonationRequiresActor(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)

	h := &handler{}
	m := getMux(t, authorizer, h)

	w := httptest.NewRecorder()

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)

	addCertificateHeader(t, r, true)
	addPrincipalHeaderWithoutActor(t, r)
	r.Header.Set(principal.ImpersonateHeader, "true")

	m.ServeHTTP(w, r)

	validateError(t, w, errors.IsBadRequest)
}

func TestServiceToServiceDirectAndImpersonatedACLsDoNotShareCacheEntries(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Times(2).Return(&identityapi.Acl{}, nil)

	h := &handler{}
	m := getMux(t, authorizer, h)

	r1, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)
	addCertificateHeader(t, r1, true)
	addPrincipalHeader(t, r1)

	w1 := httptest.NewRecorder()
	m.ServeHTTP(w1, r1)
	require.Equal(t, http.StatusOK, w1.Result().StatusCode)

	r2, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)
	addCertificateHeader(t, r2, true)
	addPrincipalHeader(t, r2)
	r2.Header.Set(principal.ImpersonateHeader, "true")

	w2 := httptest.NewRecorder()
	m.ServeHTTP(w2, r2)
	require.Equal(t, http.StatusOK, w2.Result().StatusCode)
}

func TestServiceToServiceDirectACLsReuseCacheEntries(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Times(1).Return(&identityapi.Acl{}, nil)

	h := &handler{}
	m := getMux(t, authorizer, h)

	r1, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)
	addCertificateHeader(t, r1, true)
	addPrincipalHeader(t, r1)

	w1 := httptest.NewRecorder()
	m.ServeHTTP(w1, r1)
	require.Equal(t, http.StatusOK, w1.Result().StatusCode)

	r2, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)
	addCertificateHeader(t, r2, true)
	addPrincipalHeader(t, r2)

	w2 := httptest.NewRecorder()
	m.ServeHTTP(w2, r2)
	require.Equal(t, http.StatusOK, w2.Result().StatusCode)
}

func TestServiceToServiceImpersonatedACLsReuseCacheEntries(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Times(1).Return(&identityapi.Acl{}, nil)

	h := &handler{}
	m := getMux(t, authorizer, h)

	r1, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)
	addCertificateHeader(t, r1, true)
	addPrincipalHeader(t, r1)
	r1.Header.Set(principal.ImpersonateHeader, "true")

	w1 := httptest.NewRecorder()
	m.ServeHTTP(w1, r1)
	require.Equal(t, http.StatusOK, w1.Result().StatusCode)

	r2, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)
	addCertificateHeader(t, r2, true)
	addPrincipalHeader(t, r2)
	r2.Header.Set(principal.ImpersonateHeader, "true")

	w2 := httptest.NewRecorder()
	m.ServeHTTP(w2, r2)
	require.Equal(t, http.StatusOK, w2.Result().StatusCode)
}

func TestServiceToServiceImpersonatedACLsDoNotShareCacheEntriesAcrossServices(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Times(2).Return(&identityapi.Acl{}, nil)

	h := &handler{}
	m := getMux(t, authorizer, h)

	r1, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)
	addCertificateHeaderForCN(t, r1, true, "compute-service")
	addPrincipalHeader(t, r1)
	r1.Header.Set(principal.ImpersonateHeader, "true")

	w1 := httptest.NewRecorder()
	m.ServeHTTP(w1, r1)
	require.Equal(t, http.StatusOK, w1.Result().StatusCode)

	r2, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)
	addCertificateHeaderForCN(t, r2, true, "region-service")
	addPrincipalHeader(t, r2)
	r2.Header.Set(principal.ImpersonateHeader, "true")

	w2 := httptest.NewRecorder()
	m.ServeHTTP(w2, r2)
	require.Equal(t, http.StatusOK, w2.Result().StatusCode)
}

type poisonReader struct{}

var _ io.ReadCloser = poisonReader{}

func (r poisonReader) Read([]byte) (int, error) {
	return 0, errors.HTTPUnprocessableContent()
}

func (r poisonReader) Close() error {
	return nil
}

// TestValidateBodyBypass checks that you can tell the middleware to skip trying to validate the
// request body, by putting a tag in the OpenAPI schema. It would fail without the bypass, because
// the request body is defined in the schema, and the reader supplied here will throw an error when
// it's invoked by validation.
func TestValidateBodyBypass(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Return(&identityapi.Acl{}, nil)

	h := &handler{}
	m := getMux(t, authorizer, h)

	w := httptest.NewRecorder()

	requestBody := poisonReader{}
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "/upload", requestBody)
	require.NoError(t, err)

	// The validator would read the request even absent a reason to do so, but I'm going
	// to provoke it further by saying this is a form, for which it has a specific schema.
	r.Header.Set("Content-Type", "multipart/form-data")

	addCertificateHeader(t, r, true)
	addPrincipalHeader(t, r)

	m.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Result().StatusCode)
}

// TestRequestValidationErrorDoesNotEchoTheRequest tests that a schema validation
// failure tells the client which property is at fault, but hands back neither the
// schema nor the request body, as the latter carries credentials.
func TestRequestValidationErrorDoesNotEchoTheRequest(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().Authorize(gomock.Any()).Return(authInfoFixture(identityapi.User), nil)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Return(&identityapi.Acl{}, nil)

	h := &handler{}
	m := getMux(t, authorizer, h)

	w := httptest.NewRecorder()

	// The body is missing the required grant_type, so validation fails with the
	// subject token in hand.
	form := url.Values{
		"subject_token": {secretToken},
	}

	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, validatedBodyURL, strings.NewReader(form.Encode()))
	require.NoError(t, err)

	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	addAuthorizationHeader(t, r)

	m.ServeHTTP(w, r)

	require.Equal(t, http.StatusBadRequest, w.Result().StatusCode)

	body := w.Body.String()

	// The client is told what to fix...
	require.Contains(t, body, "grant_type")

	// ... but gets neither its own credentials nor our schema back.
	require.NotContains(t, body, secretToken)
	require.NotContains(t, body, "Schema:")
}

// validationErrorDescription returns the description the client was given, having
// checked the response is a well formed error in the first place.
func validationErrorDescription(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()

	oauthError := &coreapi.Error{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), oauthError))
	require.Equal(t, coreapi.InvalidRequest, oauthError.Error)

	// A description that is empty, or that trails off after the subject, tells the
	// caller nothing they can act on.
	require.NotEmpty(t, oauthError.ErrorDescription)
	require.False(t, strings.HasSuffix(oauthError.ErrorDescription, ": "))

	return oauthError.ErrorDescription
}

// TestRequestValidationErrorMalformedBody tests that an undecodable request body
// says so, rather than returning an empty description or the body itself.
func TestRequestValidationErrorMalformedBody(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().Authorize(gomock.Any()).Return(authInfoFixture(identityapi.User), nil)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Return(&identityapi.Acl{}, nil)

	h := &handler{}
	m := getMux(t, authorizer, h)

	w := httptest.NewRecorder()

	body := `{"subject_token": "` + secretToken + `", `

	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, validatedBodyURL, strings.NewReader(body))
	require.NoError(t, err)

	r.Header.Set("Content-Type", "application/json")

	addAuthorizationHeader(t, r)

	m.ServeHTTP(w, r)

	require.Equal(t, http.StatusBadRequest, w.Result().StatusCode)

	description := validationErrorDescription(t, w)

	require.Contains(t, description, "failed to decode request body")
	require.NotContains(t, description, secretToken)
}

// TestRequestValidationErrorMissingParameter tests that a missing required
// parameter names the parameter and says what is wrong with it.
func TestRequestValidationErrorMissingParameter(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().Authorize(gomock.Any()).Return(authInfoFixture(identityapi.User), nil)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Return(&identityapi.Acl{}, nil)

	h := &handler{}
	m := getMux(t, authorizer, h)

	w := httptest.NewRecorder()

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, requiredParameterURL, nil)
	require.NoError(t, err)

	addAuthorizationHeader(t, r)

	m.ServeHTTP(w, r)

	require.Equal(t, http.StatusBadRequest, w.Result().StatusCode)

	description := validationErrorDescription(t, w)

	require.Contains(t, description, "needed")
	require.Contains(t, description, "value is required but missing")
}

const (
	// relayerID is a registered SPIFFE ID on the relay list.
	relayerID = "spiffe://example.org/ns/region/sa/region"
	// unlistedID is a registered SPIFFE ID that is not on the relay list.
	unlistedID = "spiffe://example.org/ns/compute/sa/compute"
	// unregisteredID is a SPIFFE ID that is not registered.
	unregisteredID = "spiffe://example.org/ns/other/sa/other"
	// unregisteredCN is a common name that is not registered.
	unregisteredCN = "unikorn-unknown"
	// otherCN is a registered common name of another account.
	otherCN = "compute-service"
	// principalActor differs from the token subject, so that a test can tell a
	// principal read from X-Principal from a generated one.
	principalActor = "jane@acme.com"
)

// recorder keeps the authentication events of a validator.
type recorder struct {
	events []openapi.AuthenticationEvent
}

func (r *recorder) record(_ context.Context, event openapi.AuthenticationEvent) {
	r.events = append(r.events, event)
}

// getIdentityMux returns the mux with the validator options that identity sets.
func getIdentityMux(t *testing.T, authorizer openapi.Authorizer, h *handler) (http.Handler, *recorder) {
	t.Helper()

	rec := &recorder{}

	systemAccounts := map[string]string{
		serviceActor: "service",
		otherCN:      "service",
		relayerID:    "service",
		unlistedID:   "service",
	}

	m := getMux(t, authorizer, h,
		openapi.WithSystemAccounts(systemAccounts),
		openapi.WithRelayers([]string{relayerID}),
		openapi.WithAuthenticationRecorder(rec.record),
	)

	return m, rec
}

// newCertificate issues a self-signed certificate with an optional common name
// and optional URI SANs.
func newCertificate(t *testing.T, commonName string, notAfter time.Time, uris ...string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  notAfter,
	}

	for _, uri := range uris {
		u, err := url.Parse(uri)
		require.NoError(t, err)

		template.URIs = append(template.URIs, u)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return certificate
}

func escapedPEM(certificate *x509.Certificate) string {
	return url.QueryEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})))
}

// setPeer makes the request look as if it arrived on the SPIFFE listener, with a
// verified peer.
func setPeer(t *testing.T, r *http.Request, id string) {
	t.Helper()

	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{newCertificate(t, "", time.Now().Add(time.Hour), id)},
	}
}

func addIngressCertificate(r *http.Request, certificate *x509.Certificate) {
	r.Header.Set("Ssl-Client-Cert", escapedPEM(certificate))
	r.Header.Set("Ssl-Client-Verify", "SUCCESS")
}

func addPrincipalHeaderForActor(t *testing.T, r *http.Request, actor string) {
	t.Helper()

	dataJSON, err := json.Marshal(&principal.Principal{Type: identityapi.User, Actor: actor})
	require.NoError(t, err)

	r.Header.Set(principal.Header, base64.RawURLEncoding.EncodeToString(dataJSON))
}

func newRequest(t *testing.T) *http.Request {
	t.Helper()

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)

	return r
}

// requireGenericRefusal checks for the 401 that names no reason, and returns the body.
func requireGenericRefusal(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()

	require.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)

	oauthError := &coreapi.Error{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), oauthError))
	require.Equal(t, coreapi.AccessDenied, oauthError.Error)
	require.Equal(t, util.AccessDeniedDescription, oauthError.ErrorDescription)

	return w.Body.String()
}

func requireRefusal(t *testing.T, rec *recorder, listener, reason, peer string) {
	t.Helper()

	require.Equal(t, []openapi.AuthenticationEvent{
		{Listener: listener, Result: "refused", Reason: reason, Peer: peer},
	}, rec.events)
}

// TestRelayFromListedRelayer checks that a listed relayer gets the ACL of the
// account that it relays, not its own.
func TestRelayFromListedRelayer(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, _ string) (*identityapi.Acl, error) {
		info, err := authorization.FromContext(ctx)
		require.NoError(t, err)
		require.Equal(t, otherCN, info.Userinfo.Sub)

		return &identityapi.Acl{}, nil
	})

	h := &handler{}
	m, rec := getIdentityMux(t, authorizer, h)

	r := newRequest(t)
	setPeer(t, r, relayerID)
	r.Header.Set("Unikorn-Client-Certificate", escapedPEM(newCertificate(t, otherCN, time.Now().Add(time.Hour))))
	addPrincipalHeader(t, r)

	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Result().StatusCode)
	h.validate(t, otherCN, "")
	require.Equal(t, []openapi.AuthenticationEvent{
		{Listener: "spiffe", Result: "ok", Peer: relayerID, Subject: otherCN},
	}, rec.events)
}

// TestRelayFromUnlistedPeerRefused checks that a registered peer that is not on
// the relay list cannot act as the account in the relay header.
func TestRelayFromUnlistedPeerRefused(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)

	m, rec := getIdentityMux(t, authorizer, &handler{})

	r := newRequest(t)
	setPeer(t, r, unlistedID)
	addRelayedCertificateHeader(t, r)
	addPrincipalHeader(t, r)

	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)

	requireGenericRefusal(t, w)
	requireRefusal(t, rec, "spiffe", "relay_not_permitted", unlistedID)
}

// TestBadCertificateSubjectRefused checks that a subject that is empty, malformed
// or not registered gets the generic 401 before any ACL lookup, so no cache entry
// exists for it.  A common name equal to a registered SPIFFE ID is malformed, so it
// never reads the ACL of that SPIFFE ID.
func TestBadCertificateSubjectRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		cn     string
		uris   []string
		reason string
	}{
		{
			name:   "an empty subject",
			reason: "subject_empty",
		},
		{
			name:   "two SPIFFE IDs",
			uris:   []string{relayerID, unlistedID},
			reason: "subject_malformed",
		},
		{
			name:   "an unregistered common name",
			cn:     unregisteredCN,
			reason: "not_registered",
		},
		{
			name:   "a common name equal to a registered SPIFFE ID",
			cn:     relayerID,
			reason: "subject_malformed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			c := gomock.NewController(t)
			defer c.Finish()

			authorizer := mock.NewMockAuthorizer(c)

			m, rec := getIdentityMux(t, authorizer, &handler{})

			r := newRequest(t)
			addIngressCertificate(r, newCertificate(t, test.cn, time.Now().Add(time.Hour), test.uris...))
			addPrincipalHeader(t, r)

			w := httptest.NewRecorder()
			m.ServeHTTP(w, r)

			requireGenericRefusal(t, w)
			requireRefusal(t, rec, "legacy", test.reason, "")
		})
	}
}

// TestNotRegisteredFromACLLookupRefused checks that an unregistered subject that
// the ACL lookup finds gets the generic 401 in place of a server error.
func TestNotRegisteredFromACLLookupRefused(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("%w: system account '%s' not registered", rbac.ErrSystemAccountNotRegistered, serviceActor))

	m := getMux(t, authorizer, &handler{})

	r := newRequest(t)
	addCertificateHeader(t, r, true)
	addPrincipalHeader(t, r)

	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)

	requireGenericRefusal(t, w)
}

// TestUnregisteredSPIFFEPeerRefused checks the registry on the SPIFFE listener.
func TestUnregisteredSPIFFEPeerRefused(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)

	m, rec := getIdentityMux(t, authorizer, &handler{})

	r := newRequest(t)
	setPeer(t, r, unregisteredID)
	addPrincipalHeader(t, r)

	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)

	requireGenericRefusal(t, w)
	requireRefusal(t, rec, "spiffe", "not_registered", unregisteredID)
}

// TestUnparseableRelayedCertificateRefused checks that a relayed certificate that
// does not parse gets the generic 401, not a 500.
func TestUnparseableRelayedCertificateRefused(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)

	m, rec := getIdentityMux(t, authorizer, &handler{})

	r := newRequest(t)
	setPeer(t, r, relayerID)
	r.Header.Set("Unikorn-Client-Certificate", "cat")
	addPrincipalHeader(t, r)

	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)

	requireGenericRefusal(t, w)
	requireRefusal(t, rec, "spiffe", "certificate_invalid", relayerID)
}

// TestImpersonationOnSPIFFEListener checks that a verified peer reads X-Principal
// and X-Impersonate, and that a direct and an impersonated call do not share an
// ACL cache entry.
func TestImpersonationOnSPIFFEListener(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	var impersonated []bool

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Times(2).DoAndReturn(func(ctx context.Context, _ string) (*identityapi.Acl, error) {
		p, err := principal.FromContext(ctx)
		require.NoError(t, err)
		require.Equal(t, principalActor, p.Actor)

		impersonated = append(impersonated, principal.ImpersonateFromContext(ctx))

		return &identityapi.Acl{}, nil
	})

	m, _ := getIdentityMux(t, authorizer, &handler{})

	for _, impersonate := range []bool{false, true} {
		r := newRequest(t)
		setPeer(t, r, relayerID)
		addPrincipalHeaderForActor(t, r, principalActor)

		if impersonate {
			r.Header.Set(principal.ImpersonateHeader, "true")
		}

		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)

		require.Equal(t, http.StatusOK, w.Result().StatusCode)
	}

	require.Equal(t, []bool{false, true}, impersonated)
}

// TestBoundTokenThroughListedRelayer checks that the bound token check sees the
// relayed certificate when a listed relayer passes it on.
func TestBoundTokenThroughListedRelayer(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	relayed := escapedPEM(newCertificate(t, otherCN, time.Now().Add(time.Hour)))

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().Authorize(gomock.Any()).DoAndReturn(func(input *openapi3filter.AuthenticationInput) (*authorization.Info, error) {
		certificate, err := authorization.ClientCertFromContext(input.RequestValidationInput.Request.Context())
		require.NoError(t, err)
		require.Equal(t, relayed, certificate)

		return authInfoFixture(identityapi.User), nil
	})
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Return(&identityapi.Acl{}, nil)

	m, _ := getIdentityMux(t, authorizer, &handler{})

	r := newRequest(t)
	setPeer(t, r, relayerID)
	r.Header.Set("Unikorn-Client-Certificate", relayed)
	addAuthorizationHeader(t, r)
	addPrincipalHeader(t, r)

	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Result().StatusCode)
}

// TestBoundTokenThroughUnlistedPeerRefused checks that the relay rule also covers
// the bearer branch.
func TestBoundTokenThroughUnlistedPeerRefused(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)

	m, _ := getIdentityMux(t, authorizer, &handler{})

	r := newRequest(t)
	setPeer(t, r, unlistedID)
	r.Header.Set("Unikorn-Client-Certificate", escapedPEM(newCertificate(t, otherCN, time.Now().Add(time.Hour))))
	addAuthorizationHeader(t, r)
	addPrincipalHeader(t, r)

	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)

	requireGenericRefusal(t, w)
}

// TestIngressHeadersIgnoredOnSPIFFEListener checks that a verified peer cannot
// name another account with the ingress headers.
func TestIngressHeadersIgnoredOnSPIFFEListener(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Return(&identityapi.Acl{}, nil)

	h := &handler{}
	m, _ := getIdentityMux(t, authorizer, h)

	r := newRequest(t)
	setPeer(t, r, relayerID)
	addIngressCertificate(r, newCertificate(t, otherCN, time.Now().Add(time.Hour)))
	addPrincipalHeader(t, r)

	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Result().StatusCode)
	h.validate(t, relayerID, "")
}

// TestRefusalNamesNoReason checks that the response to a refusal names neither the
// subject nor the reason, and that the reason goes to one log line of the request
// logger, which carries the trace ID.
func TestRefusalNamesNoReason(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		setup  func(t *testing.T, r *http.Request)
		reason string
	}{
		{
			name: "an unregistered subject",
			setup: func(t *testing.T, r *http.Request) {
				t.Helper()
				addIngressCertificate(r, newCertificate(t, unregisteredCN, time.Now().Add(time.Hour)))
			},
			reason: "not_registered",
		},
		{
			name: "an unlisted peer that relays",
			setup: func(t *testing.T, r *http.Request) {
				t.Helper()
				setPeer(t, r, unlistedID)
				addRelayedCertificateHeader(t, r)
			},
			reason: "relay_not_permitted",
		},
	}

	bodies := make([]string, 0, len(tests))

	for _, test := range tests {
		c := gomock.NewController(t)

		authorizer := mock.NewMockAuthorizer(c)

		m, _ := getIdentityMux(t, authorizer, &handler{})

		var lines []map[string]any

		logger := funcr.NewJSON(func(obj string) {
			line := map[string]any{}
			require.NoError(t, json.Unmarshal([]byte(obj), &line))

			if line["msg"] == "error detail" {
				lines = append(lines, line)
			}
		}, funcr.Options{}).WithValues("traceID", "trace-1")

		r := newRequest(t)
		r = r.WithContext(log.IntoContext(r.Context(), logger))
		test.setup(t, r)
		addPrincipalHeader(t, r)

		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)

		body := requireGenericRefusal(t, w)
		require.NotContains(t, body, unregisteredCN, test.name)
		require.NotContains(t, body, "spiffe", test.name)
		require.NotContains(t, body, test.reason, test.name)

		require.Len(t, lines, 1, test.name)
		require.Equal(t, test.reason, lines[0]["reason"], test.name)
		require.Equal(t, "trace-1", lines[0]["traceID"], test.name)

		bodies = append(bodies, body)

		c.Finish()
	}

	require.Equal(t, bodies[0], bodies[1])
}

// TestRelayOfUnregisteredSubjectLabels checks that a refused relay records the
// verified peer but not the relayed subject, so the counter labels stay bounded.
// On the legacy listener the peer comes from a header, so it is not recorded.
func TestRelayOfUnregisteredSubjectLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		setPeer  func(t *testing.T, r *http.Request)
		listener string
		peer     string
	}{
		{
			name: "spiffe listener",
			setPeer: func(t *testing.T, r *http.Request) {
				t.Helper()
				setPeer(t, r, relayerID)
			},
			listener: "spiffe",
			peer:     relayerID,
		},
		{
			name: "legacy listener",
			setPeer: func(t *testing.T, r *http.Request) {
				t.Helper()
				addCertificateHeader(t, r, true)
			},
			listener: "legacy",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			c := gomock.NewController(t)
			defer c.Finish()

			authorizer := mock.NewMockAuthorizer(c)

			m, rec := getIdentityMux(t, authorizer, &handler{})

			r := newRequest(t)
			test.setPeer(t, r)
			r.Header.Set("Unikorn-Client-Certificate", escapedPEM(newCertificate(t, unregisteredCN, time.Now().Add(time.Hour))))
			addPrincipalHeader(t, r)

			w := httptest.NewRecorder()
			m.ServeHTTP(w, r)

			requireGenericRefusal(t, w)
			requireRefusal(t, rec, test.listener, "not_registered", test.peer)
		})
	}
}

// TestVerifiedPeerWithCommonNameRefused checks that a verified peer with a common
// name is refused, also when that common name is registered.
func TestVerifiedPeerWithCommonNameRefused(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)

	m, rec := getIdentityMux(t, authorizer, &handler{})

	r := newRequest(t)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{newCertificate(t, serviceActor, time.Now().Add(time.Hour), relayerID)},
	}
	addPrincipalHeader(t, r)

	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)

	requireGenericRefusal(t, w)
	requireRefusal(t, rec, "spiffe", "peer_has_common_name", "")
}

// TestExpiredPeerRefused checks that a request on a connection that outlives the
// peer certificate is refused.
func TestExpiredPeerRefused(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)

	m, rec := getIdentityMux(t, authorizer, &handler{})

	r := newRequest(t)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{newCertificate(t, "", time.Now().Add(-time.Minute), relayerID)},
	}
	addPrincipalHeader(t, r)

	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)

	requireGenericRefusal(t, w)
	requireRefusal(t, rec, "spiffe", "peer_expired", "")
}

// TestBearerTokenWithUnregisteredCertificate checks that a bearer token caller
// with an unregistered certificate cannot set X-Principal.  Without X-Principal
// or X-Impersonate the registry is not checked, so that caller keeps the result
// that it gets with no registry.
func TestBearerTokenWithUnregisteredCertificate(t *testing.T) {
	t.Parallel()

	t.Run("with X-Principal", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		defer c.Finish()

		authorizer := mock.NewMockAuthorizer(c)
		authorizer.EXPECT().Authorize(gomock.Any()).Return(authInfoFixture(identityapi.User), nil)

		m, _ := getIdentityMux(t, authorizer, &handler{})

		r := newRequest(t)
		addAuthorizationHeader(t, r)
		addIngressCertificate(r, newCertificate(t, unregisteredCN, time.Now().Add(time.Hour)))
		addPrincipalHeaderForActor(t, r, principalActor)

		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)

		requireGenericRefusal(t, w)
	})

	t.Run("without X-Principal or X-Impersonate", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		defer c.Finish()

		authorizer := mock.NewMockAuthorizer(c)
		authorizer.EXPECT().Authorize(gomock.Any()).Times(2).Return(authInfoFixture(identityapi.User), nil)

		certificate := newCertificate(t, unregisteredCN, time.Now().Add(time.Hour))

		responses := make([]*httptest.ResponseRecorder, 0, 2)

		identityMux, _ := getIdentityMux(t, authorizer, &handler{})

		for _, m := range []http.Handler{identityMux, getMux(t, authorizer, &handler{})} {
			r := newRequest(t)
			addAuthorizationHeader(t, r)
			addIngressCertificate(r, certificate)

			w := httptest.NewRecorder()
			m.ServeHTTP(w, r)

			responses = append(responses, w)
		}

		require.Equal(t, http.StatusBadRequest, responses[0].Code)
		require.Equal(t, responses[1].Code, responses[0].Code)
		require.Equal(t, responses[1].Body.String(), responses[0].Body.String())
	})

	t.Run("on the SPIFFE listener without X-Principal", func(t *testing.T) {
		t.Parallel()

		c := gomock.NewController(t)
		defer c.Finish()

		authorizer := mock.NewMockAuthorizer(c)
		authorizer.EXPECT().Authorize(gomock.Any()).Return(authInfoFixture(identityapi.User), nil)

		m, _ := getIdentityMux(t, authorizer, &handler{})

		r := newRequest(t)
		addAuthorizationHeader(t, r)
		setPeer(t, r, unregisteredID)

		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)

		requireGenericRefusal(t, w)
	})
}

// TestLegacyRegisteredAndUnregisteredCommonName checks the legacy listener: a
// registered common name keeps working, and an unregistered one gets the generic
// 401 in place of a server error.
func TestLegacyRegisteredAndUnregisteredCommonName(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Return(&identityapi.Acl{}, nil)

	h := &handler{}
	m, rec := getIdentityMux(t, authorizer, h)

	r := newRequest(t)
	addCertificateHeader(t, r, true)
	addPrincipalHeader(t, r)

	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Result().StatusCode)
	h.validate(t, serviceActor, "")
	require.Equal(t, []openapi.AuthenticationEvent{
		{Listener: "legacy", Result: "ok", Subject: serviceActor},
	}, rec.events)

	r = newRequest(t)
	addIngressCertificate(r, newCertificate(t, unregisteredCN, time.Now().Add(time.Hour)))
	addPrincipalHeader(t, r)

	w = httptest.NewRecorder()
	m.ServeHTTP(w, r)

	requireGenericRefusal(t, w)
}

// TestRegisteredCertificateWithBearerTokenReadsPrincipal checks the user ACL
// lookup of region: a user token, the certificate of region and X-Principal.
func TestRegisteredCertificateWithBearerTokenReadsPrincipal(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().Authorize(gomock.Any()).Return(authInfoFixture(identityapi.User), nil)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, _ string) (*identityapi.Acl, error) {
		p, err := principal.FromContext(ctx)
		require.NoError(t, err)
		require.Equal(t, principalActor, p.Actor)

		return &identityapi.Acl{}, nil
	})

	m, rec := getIdentityMux(t, authorizer, &handler{})

	r := newRequest(t)
	addAuthorizationHeader(t, r)
	addCertificateHeader(t, r, true)
	addPrincipalHeaderForActor(t, r, principalActor)

	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Result().StatusCode)
	require.Empty(t, rec.events)
}

// TestUnregisteredSubjectRefusedBeforePrincipal checks that an unregistered
// subject gets the same generic 401 whatever it sends in X-Principal and
// X-Impersonate, and that no ACL lookup runs.
func TestUnregisteredSubjectRefusedBeforePrincipal(t *testing.T) {
	t.Parallel()

	callers := map[string]func(t *testing.T, r *http.Request){
		"legacy": func(t *testing.T, r *http.Request) {
			t.Helper()
			addIngressCertificate(r, newCertificate(t, unregisteredCN, time.Now().Add(time.Hour)))
		},
		"spiffe": func(t *testing.T, r *http.Request) {
			t.Helper()
			setPeer(t, r, unregisteredID)
		},
	}

	headers := map[string]func(t *testing.T, r *http.Request){
		"principal and impersonate": func(t *testing.T, r *http.Request) {
			t.Helper()
			addPrincipalHeader(t, r)
			r.Header.Set(principal.ImpersonateHeader, "true")
		},
		"bad principal": func(t *testing.T, r *http.Request) {
			t.Helper()
			r.Header.Set(principal.Header, "!!")
		},
		"impersonate without principal": func(t *testing.T, r *http.Request) {
			t.Helper()
			r.Header.Set(principal.ImpersonateHeader, "true")
		},
		"neither": func(t *testing.T, r *http.Request) {
			t.Helper()
		},
	}

	bodies := make([]string, 0, len(callers)*len(headers))

	for callerName, caller := range callers {
		for headerName, header := range headers {
			c := gomock.NewController(t)

			authorizer := mock.NewMockAuthorizer(c)

			m, _ := getIdentityMux(t, authorizer, &handler{})

			r := newRequest(t)
			caller(t, r)
			header(t, r)

			w := httptest.NewRecorder()
			m.ServeHTTP(w, r)

			require.Equal(t, http.StatusUnauthorized, w.Result().StatusCode, callerName+", "+headerName)

			bodies = append(bodies, requireGenericRefusal(t, w))

			c.Finish()
		}
	}

	for _, body := range bodies {
		require.Equal(t, bodies[0], body)
	}
}
