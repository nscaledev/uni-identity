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

//nolint:revive,testpackage // dot imports and package naming standard for Ginkgo
package suites

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// This suite is the A18 genuine-mTLS assertion for the internal decision
// endpoint POST /api/v1/authorization/check.  The A8 in-process handler tests
// reproduce the ingress trust model by INJECTING verified-cert headers; this
// drives a REAL TLS handshake through the ingress to prove the endpoint enforces
// mTLS at the transport, not merely trusts injected headers.
//
// It uses its own mTLS-configured generated client (test/api.APIClient is
// bearer-only), modelled on hack/ci/fixtures.newAPIClient, and reuses the
// ci-fixtures client certificate (CN ci-fixtures → platform-administrator) that
// hack/ci/fixtures issues off the unikorn-client-issuer and exports into
// test/.env.

// injectCIPrincipal sets the X-Principal header identity requires on every mTLS
// call, exactly as the fixtures client does (actor ci-fixtures →
// platform-administrator).
func injectCIPrincipal(_ context.Context, req *http.Request) error {
	principalJSON, err := json.Marshal(map[string]string{"actor": "ci-fixtures"})
	if err != nil {
		return err
	}

	req.Header.Set("X-Principal", base64.RawURLEncoding.EncodeToString(principalJSON))

	return nil
}

// newAuthzMTLSClient builds a generated typed client that reaches identity over a
// GENUINE mTLS handshake.  With withClientCert it presents the ci-fixtures client
// certificate (so nginx sets Ssl-Client-Verify: SUCCESS and identity resolves a
// system account) and injects X-Principal; without it, no client certificate is
// presented, so the endpoint has no verified mTLS peer to trust.  It Skips when
// hack/ci/fixtures did not export mTLS credentials (e.g. a focused local run).
func newAuthzMTLSClient(withClientCert bool) *openapi.ClientWithResponses {
	GinkgoHelper()

	caCertPath := os.Getenv("IDENTITY_CA_CERT")
	if config.BaseURL == "" || caCertPath == "" || config.MTLSClientCert == "" || config.MTLSClientKey == "" {
		Skip("mTLS client credentials unavailable (run via `make integration-fixtures`)")
	}

	caBytes, err := os.ReadFile(caCertPath)
	Expect(err).NotTo(HaveOccurred(), "reading CA bundle %s", caCertPath)

	caPool := x509.NewCertPool()
	Expect(caPool.AppendCertsFromPEM(caBytes)).To(BeTrue(), "appending CA bundle to pool")

	// RootCAs trusts the ingress server certificate so TLS to the server always
	// succeeds; whether a CLIENT certificate is presented is the variable under
	// test.
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: caPool}

	var editors []openapi.ClientOption

	if withClientCert {
		certPEM, err := base64.StdEncoding.DecodeString(config.MTLSClientCert)
		Expect(err).NotTo(HaveOccurred(), "decoding mTLS client certificate")

		keyPEM, err := base64.StdEncoding.DecodeString(config.MTLSClientKey)
		Expect(err).NotTo(HaveOccurred(), "decoding mTLS client key")

		clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
		Expect(err).NotTo(HaveOccurred(), "parsing mTLS key pair")

		tlsConfig.Certificates = []tls.Certificate{clientCert}

		editors = append(editors, openapi.WithRequestEditorFn(injectCIPrincipal))
	}

	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   30 * time.Second,
	}

	options := append([]openapi.ClientOption{openapi.WithHTTPClient(httpClient)}, editors...)

	client, err := openapi.NewClientWithResponses(config.BaseURL, options...)
	Expect(err).NotTo(HaveOccurred(), "building mTLS identity client")

	return client
}

// authzCheckBody is a single global check the mTLS-authenticated
// platform-administrator system account is granted, so a successful decision is a
// deterministic allow.
func authzCheckBody() openapi.AuthorizationCheckRequest {
	return openapi.AuthorizationCheckRequest{
		Checks: []openapi.AuthorizationCheck{{
			Resource: openapi.AuthorizationCheckResource{Kind: "identity:organizations"},
			Action:   openapi.Read,
		}},
	}
}

var _ = Describe("Authorization check decision endpoint", func() {
	Context("When reached over a genuine mTLS connection", func() {
		Describe("Given a valid, trusted client certificate", func() {
			It("returns a per-check authorization decision", func() {
				client := newAuthzMTLSClient(true)

				resp, err := client.PostApiV1AuthorizationCheckWithResponse(ctx, authzCheckBody())
				Expect(err).NotTo(HaveOccurred(), "genuine mTLS authorization check")
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(resp.JSON200).NotTo(BeNil(), "a decision body must be returned over mTLS")
				Expect(resp.JSON200.Results).To(HaveLen(1), "one result per requested check, in order")

				// platform-administrator holds identity:organizations read at global
				// scope, so a real Cerbos decision for the mTLS-authenticated system
				// account is an allow.  Asserting the verdict (not just the shape)
				// proves the pipeline ran end to end — mTLS resolved the system
				// account and Cerbos evaluated policy — rather than a default body.
				Expect(resp.JSON200.Results[0].Allowed).To(BeTrue(),
					"the mTLS-authenticated platform-administrator must be allowed identity:organizations read")
			})
		})

		Describe("Given no client certificate", func() {
			It("rejects the request at the mTLS/authorization layer", func() {
				client := newAuthzMTLSClient(false)

				resp, err := client.PostApiV1AuthorizationCheckWithResponse(ctx, authzCheckBody())
				if err != nil {
					// A transport/handshake rejection is itself a valid "mTLS
					// required" outcome (e.g. were the ingress tightened to require
					// client certificates).
					return
				}

				// The ingress runs auth-tls-verify-client: optional, so the handshake
				// succeeds without a client certificate and identity refuses at the
				// authorization layer.  Either way, no decision is served to a caller
				// without a verified mTLS peer.
				Expect(resp.StatusCode()).NotTo(Equal(http.StatusOK),
					"a caller without a trusted client certificate must not obtain a decision")
				Expect(resp.JSON200).To(BeNil(), "no decision body may be returned to an unverified caller")
				Expect(resp.StatusCode()).To(SatisfyAny(
					Equal(http.StatusUnauthorized),
					Equal(http.StatusForbidden),
				), "an unverified caller must be refused with 401/403")
			})
		})
	})
})
