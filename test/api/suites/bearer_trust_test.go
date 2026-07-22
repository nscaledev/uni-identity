//go:build integration
// +build integration

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

// Package suites contains integration tests for the Identity API.
//
// # Coverage boundary for the bearerTrust feature
//
// A full multi-issuer dispatch test requires a live external IdP serving JWKS
// that the KinD harness cannot easily stand up. In-process signature and dispatch
// behaviour is therefore covered by unit tests (Tasks 3–9), which mint tokens
// and serve JWKS in-process via auth0TestIssuer.
//
// This integration test covers the CRD + API surface that KinD CAN exercise:
//
//   - An OAuth2Provider with a standard issuer is accepted and persisted via the
//     typed APIClient; response body fields (Metadata.Id, Spec.Issuer) are asserted.
//
//   - A malformed or unknown-issuer JWS bearer presented to /oauth2/v2/userinfo is
//     rejected with 401 (pure-authz assertion, acceptable per testing standards).
//
// Limitation: the bearerTrust block (BearerTrustSpec) is a CRD-only field and is
// not exposed in the OpenAPI Oauth2ProviderSpec. It cannot therefore be set or
// verified via the typed APIClient. Full end-to-end bearerTrust dispatch (trusted
// external issuer accepted at /oauth2/v2/userinfo) is deferred to a future test
// phase that can inject a live JWKS-serving issuer into the KinD cluster.

//nolint:revive,testpackage // dot imports and package naming standard for Ginkgo
package suites

import (
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	"github.com/unikorn-cloud/identity/test/api"
)

var _ = Describe("OAuth2Provider bearerTrust", func() {
	Context("When an operator creates a provider with a bearerTrust-relevant issuer", func() {
		Describe("the persisted resource", func() {
			It("retains the canonical issuer and is accepted", func() {
				// bearerTrust is CRD-only and not settable via the OpenAPI surface;
				// we create a standard OAuth2Provider and assert that the issuer and
				// ID round-trip correctly, confirming the provider CRD path works.
				canonicalIssuer := "https://login.example.com"

				payload := api.NewOauth2ProviderPayload().
					WithIssuer(canonicalIssuer).
					Build()

				created, providerID := api.CreateOauth2ProviderWithCleanup(client, ctx, config, payload)

				Expect(providerID).NotTo(BeEmpty(),
					"Metadata.Id must be set on the created OAuth2Provider")

				Expect(created.Metadata.Id).To(Equal(providerID),
					"Metadata.Id in the response body must match the returned provider ID")

				Expect(created.Spec.Issuer).To(Equal(canonicalIssuer),
					"Spec.Issuer must be persisted exactly as supplied")

				GinkgoWriter.Printf("OAuth2Provider created: ID=%s issuer=%s\n",
					providerID, created.Spec.Issuer)
			})
		})
	})

	Context("When a malformed or unknown-issuer bearer is presented to /oauth2/v2/userinfo", func() {
		Describe("the response", func() {
			It("is rejected with 401", func() {
				// Send a syntactically malformed JWS (not a real JWT) as the bearer
				// token. The server must reject it before any provider lookup because
				// the token cannot be decoded, let alone matched to a trusted issuer.
				// Pure-authz status assertion: typed APIClient cannot supply an arbitrary
				// bearer; coreclient.NewAPIClient used directly (RBAC exception clause).
				malformedBearer := "this.is.not.a.valid.jws"

				rawClient := coreclient.NewAPIClient(
					config.BaseURL,
					malformedBearer,
					config.RequestTimeout,
					&api.GinkgoLogger{},
				)

				resp, _, err := rawClient.DoRequest(
					ctx,
					http.MethodGet,
					api.NewEndpoints().GetUserinfo(),
					nil,
					http.StatusUnauthorized,
				)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized),
					"malformed JWS bearer must be rejected with 401")

				GinkgoWriter.Printf("Malformed bearer rejected with %d\n", resp.StatusCode)
			})

			It("is rejected with 401 for a well-formed JWT from an untrusted issuer", func() {
				// A syntactically valid but unsigned/self-signed JWT whose iss does
				// not match any registered OAuth2Provider should be rejected. We use
				// a compact JWT header.payload.signature where the signature is
				// replaced with zeros; the server must reject it before or after
				// key-lookup because the issuer is unknown.
				//
				// eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9 = {"alg":"RS256","typ":"JWT"}
				// eyJpc3MiOiJodHRwczovL3VudHJ1c3RlZC5leGFtcGxlLmNvbSIsInN1YiI6InRlc3R1c2VyIn0
				//   = {"iss":"https://untrusted.example.com","sub":"testuser"}
				// Pure-authz status assertion: typed APIClient cannot supply an arbitrary
				// bearer; coreclient.NewAPIClient used directly (RBAC exception clause).
				untrustedJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" +
					".eyJpc3MiOiJodHRwczovL3VudHJ1c3RlZC5leGFtcGxlLmNvbSIsInN1YiI6InRlc3R1c2VyIn0" +
					".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
					"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
					"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

				rawClient := coreclient.NewAPIClient(
					config.BaseURL,
					untrustedJWT,
					config.RequestTimeout,
					&api.GinkgoLogger{},
				)

				resp, _, err := rawClient.DoRequest(
					ctx,
					http.MethodGet,
					api.NewEndpoints().GetUserinfo(),
					nil,
					http.StatusUnauthorized,
				)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized),
					"unknown-issuer JWT bearer must be rejected with 401")

				GinkgoWriter.Printf("Unknown-issuer JWT rejected with %d\n", resp.StatusCode)
			})
		})
	})
})
