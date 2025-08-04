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

package openapi_test

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"
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
	authenticatedURL = "https://localhost/api/v1/organizations"
)

// responseWriter is a mock http.ResponseWriter fixture that stores
// all details about any write calls.
type responseWriter struct {
	header     http.Header
	body       []byte
	statusCode int
}

func newResponseWriter() *responseWriter {
	return &responseWriter{
		header: http.Header{},
	}
}

func (w *responseWriter) Header() http.Header {
	return w.header
}

func (w *responseWriter) Write(body []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}

	w.body = body

	return len(body), nil
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

// validateError checks that the response body is an error and is as we expect.
func (w *responseWriter) validateError(t *testing.T, errorType coreapi.ErrorError, errorDescription string) {
	t.Helper()

	require.NotNil(t, w.body)

	oauthError := &coreapi.Error{}
	require.NoError(t, json.Unmarshal(w.body, oauthError))

	require.Equal(t, errorType, oauthError.Error)
	require.Equal(t, errorDescription, oauthError.ErrorDescription)
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

// addPrincipalHeader digitally signs a principal and adds to the request.
func addPrincipalHeader(t *testing.T, r *http.Request) {
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
func (h *handler) validate(t *testing.T, actor string) {
	t.Helper()

	// Check the authentication information is good for auditing.
	require.NotNil(t, h.authinfo)
	require.Equal(t, actor, h.authinfo.Actor)

	// Check the Acl is good for RBAC.
	require.NotNil(t, h.acl)

	// Check the principal information is good for further auditing and accounting.
	require.NotNil(t, h.principal)
	require.Equal(t, userActor, h.principal.Actor)
}

// mustNewValidator creates an OpanAPI validator middleware, the thing we are testing.
func mustNewValidator(t *testing.T, handler http.Handler) *openapi.Validator {
	t.Helper()

	schema, err := coreapi.NewSchema(identityapi.GetSwagger)
	require.NoError(t, err)

	return openapi.NewValidator(handler, schema)
}

// TestUserToServiceAuthenticationFailure tests we propagate the correct error when
// authentication fails.
func TestUserToServiceAuthenticationFailure(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	h := &handler{}
	v := mustNewValidator(t, h)

	w := newResponseWriter()

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)

	v.ServeHTTP(w, r)

	require.Equal(t, http.StatusUnauthorized, w.statusCode)
}

// TestUserToServiceAuthenticationSuccess tests everything is in place when authentication
// succeeds.
func TestUserToServiceAuthenticationSuccess(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	h := &handler{}
	v := mustNewValidator(t, h)

	w := newResponseWriter()

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)

	v.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.statusCode)
	h.validate(t, userActor)
}

// TestServiceToServiceMalformedCertificate tests the response when a client certificate is
// malformed.
func TestServiceToServiceMalformedCertificate(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	h := &handler{}
	v := mustNewValidator(t, h)

	w := newResponseWriter()

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)

	r.Header.Set("Ssl-Client-Cert", "cat")

	v.ServeHTTP(w, r)

	require.Equal(t, http.StatusInternalServerError, w.statusCode)
	w.validateError(t, coreapi.ServerError, "certificate propagation failure")
}

// TestServiceToServiceCertificateInvalid tests the response when a client certificate
// did not validate at the ingress.
func TestServiceToServiceCertificateInvalid(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	h := &handler{}
	v := mustNewValidator(t, h)

	w := newResponseWriter()

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)

	addCertificateHeader(t, r, false)

	v.ServeHTTP(w, r)

	require.Equal(t, http.StatusInternalServerError, w.statusCode)
	w.validateError(t, coreapi.ServerError, "certificate propagation failure")
}

// TestServiceToServiceAuthenticationFailure tests the response when authentication fails.
func TestServiceToServiceAuthenticationFailure(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	h := &handler{}
	v := mustNewValidator(t, h)

	w := newResponseWriter()

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)

	addCertificateHeader(t, r, true)

	v.ServeHTTP(w, r)

	require.Equal(t, http.StatusUnauthorized, w.statusCode)
}

// TestServiceToServicePrincipalMissing tests the response when a principal is missing.
func TestServiceToServicePrincipalMissing(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	h := &handler{}
	v := mustNewValidator(t, h)

	w := newResponseWriter()

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)

	addCertificateHeader(t, r, true)

	v.ServeHTTP(w, r)

	require.Equal(t, http.StatusBadRequest, w.statusCode)
	w.validateError(t, coreapi.InvalidRequest, "principal propagation failure for authentication")
}

// TestServiceToServiceAuthenticationSuccess tests a full service to service authenticated
// API call.
func TestServiceToServiceAuthenticationSuccess(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	h := &handler{}
	v := mustNewValidator(t, h)

	w := newResponseWriter()

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)

	addCertificateHeader(t, r, true)
	addPrincipalHeader(t, r)

	v.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.statusCode)
	h.validate(t, serviceActor)
}
