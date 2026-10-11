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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/test/api"
)

const narrowCN = "ci-narrow"

type passportCaller struct {
	certificate        string
	key                string
	relayedCertificate string
	impersonate        bool
}

func requirePassportCredentials() {
	GinkgoHelper()

	if config.BaseURL == "" || os.Getenv("IDENTITY_CA_CERT") == "" ||
		config.MTLSClientCert == "" || config.MTLSClientKey == "" ||
		config.MTLSNarrowClientCert == "" || config.MTLSNarrowClientKey == "" ||
		config.ServiceAccountToken == "" || config.UserSAID == "" {
		Skip("passport credentials unavailable (run via `make integration-fixtures`)")
	}
}

func decodeBase64PEM(encoded, what string) []byte {
	GinkgoHelper()

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	Expect(err).NotTo(HaveOccurred(), "decoding %s", what)

	return decoded
}

func newPassportMTLSClient(caller passportCaller, actor string) *identityopenapi.ClientWithResponses {
	GinkgoHelper()

	// A service account principal carries its home organization, as the
	// downstream middleware sets it.  Impersonation resolves the account there.
	principalJSON, err := json.Marshal(&principal.Principal{
		Actor:           actor,
		Type:            identityopenapi.Service,
		Issuer:          constants.UNISentinel,
		OrganizationIDs: []string{config.OrgID},
	})
	Expect(err).NotTo(HaveOccurred())

	principalHeader := base64.RawURLEncoding.EncodeToString(principalJSON)

	var relayHeader string
	if caller.relayedCertificate != "" {
		relayHeader = url.QueryEscape(string(decodeBase64PEM(caller.relayedCertificate, "relayed client certificate")))
	}

	editor := func(_ context.Context, req *http.Request) error {
		req.Header.Set(principal.Header, principalHeader)

		if caller.impersonate {
			req.Header.Set(principal.ImpersonateHeader, "true")
		}

		if relayHeader != "" {
			req.Header.Set(authorization.ClientCertificateHeader, relayHeader)
		}

		return nil
	}

	return newAuthzMTLSClient(caller.certificate, caller.key, editor)
}

func narrowCaller() passportCaller {
	return passportCaller{certificate: config.MTLSNarrowClientCert, key: config.MTLSNarrowClientKey}
}

func exchangeServicePassport(token, audience string) string {
	GinkgoHelper()

	serviceConfig := *config
	serviceConfig.AuthToken = token

	result, err := api.NewAPIClientWithConfig(&serviceConfig).ExchangePassport(ctx, &identityopenapi.TokenRequestOptions{
		Audience:        &audience,
		XOrganizationId: &config.OrgID,
	})
	Expect(err).NotTo(HaveOccurred(), "exchanging the service account token for a passport")
	Expect(result.AccessToken).NotTo(BeEmpty())

	return result.AccessToken
}

func projectReadCheck(passport *string) identityopenapi.AuthorizationCheckRequest {
	return identityopenapi.AuthorizationCheckRequest{
		Checks: []identityopenapi.AuthorizationCheck{{
			Resource: identityopenapi.AuthorizationCheckResource{
				Kind:           "identity:projects",
				OrganizationId: &config.OrgID,
				ProjectId:      &config.ProjectID,
			},
			Action: identityopenapi.Read,
		}},
		Passport: passport,
	}
}

var _ = Describe("Authorization check decision endpoint", func() {
	Context("When a service presents a passport", func() {
		BeforeEach(func() {
			requirePassportCredentials()
		})

		Describe("Given a passport whose audience is the presenting service", func() {
			It("decides for the passport subject with no cap from the presenting service", func() {
				passport := exchangeServicePassport(config.ServiceAccountToken, narrowCN)

				resp, err := newPassportMTLSClient(narrowCaller(), config.UserSAID).PostApiV1AuthorizationCheckWithResponse(ctx, projectReadCheck(&passport))
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK), "body: %s", string(resp.Body))
				Expect(resp.JSON200).NotTo(BeNil())
				Expect(resp.JSON200.Results).To(HaveLen(1))
				Expect(resp.JSON200.Results[0].Allowed).To(BeTrue(),
					"ci-user-sa can read the fixture project, and the role of ci-narrow must not cap that")
				Expect(resp.JSON200.PassportSubject).NotTo(BeNil(), "the caller must be able to make sure that identity decided for its subject")
				Expect(*resp.JSON200.PassportSubject).To(Equal(config.UserSAID))
			})

			It("denies the same check through impersonation with no passport", func() {
				caller := narrowCaller()
				caller.impersonate = true

				resp, err := newPassportMTLSClient(caller, config.UserSAID).PostApiV1AuthorizationCheckWithResponse(ctx, projectReadCheck(nil))
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK), "body: %s", string(resp.Body))
				Expect(resp.JSON200).NotTo(BeNil())
				Expect(resp.JSON200.Results).To(HaveLen(1))
				Expect(resp.JSON200.Results[0].Allowed).To(BeFalse(),
					"the dual check must deny, because ci-narrow does not hold the grant")
				Expect(resp.JSON200.PassportSubject).To(BeNil(), "an impersonated decision must not name a passport subject")
			})
		})

		Describe("Given a passport whose audience is another service", func() {
			It("refuses the passport", func() {
				passport := exchangeServicePassport(config.ServiceAccountToken, "ci-fixtures")

				resp, err := newPassportMTLSClient(narrowCaller(), config.UserSAID).PostApiV1AuthorizationCheckWithResponse(ctx, projectReadCheck(&passport))
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusUnauthorized), "body: %s", string(resp.Body))
				Expect(resp.JSON200).To(BeNil(), "a refused passport must return no decision")
			})
		})

		Describe("Given a passport together with impersonation", func() {
			It("rejects the request", func() {
				passport := exchangeServicePassport(config.ServiceAccountToken, narrowCN)

				caller := narrowCaller()
				caller.impersonate = true

				resp, err := newPassportMTLSClient(caller, config.UserSAID).PostApiV1AuthorizationCheckWithResponse(ctx, projectReadCheck(&passport))
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusBadRequest), "body: %s", string(resp.Body))
				Expect(resp.JSON200).To(BeNil())
			})
		})

		Describe("Given a caller that relays the certificate of the passport audience", func() {
			It("rejects the request, because the audience binds to the TLS peer", func() {
				passport := exchangeServicePassport(config.ServiceAccountToken, narrowCN)

				caller := passportCaller{
					certificate:        config.MTLSClientCert,
					key:                config.MTLSClientKey,
					relayedCertificate: config.MTLSNarrowClientCert,
				}

				resp, err := newPassportMTLSClient(caller, config.UserSAID).PostApiV1AuthorizationCheckWithResponse(ctx, projectReadCheck(&passport))
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusBadRequest), "body: %s", string(resp.Body))
				Expect(resp.JSON200).To(BeNil())
			})
		})

		Describe("Given a passport for a service account that was deleted", func() {
			It("refuses the passport", func() {
				created, saID := api.CreateServiceAccountWithCleanup(client, ctx, config, api.NewServiceAccountPayload().Build())
				Expect(created.Status.AccessToken).NotTo(BeNil(), "the create response must return the one-time token")

				passport := exchangeServicePassport(*created.Status.AccessToken, narrowCN)
				expiry := decodePassportClaims(passport).Expiry.Time()
				narrowClient := newPassportMTLSClient(narrowCaller(), saID)

				live, err := narrowClient.PostApiV1AuthorizationCheckWithResponse(ctx, projectReadCheck(&passport))
				Expect(err).NotTo(HaveOccurred())
				Expect(live.StatusCode()).To(Equal(http.StatusOK), "the passport must be accepted while its subject exists; body: %s", string(live.Body))
				Expect(live.JSON200).NotTo(BeNil())
				Expect(live.JSON200.PassportSubject).NotTo(BeNil())
				Expect(*live.JSON200.PassportSubject).To(Equal(saID))

				Expect(client.DeleteServiceAccount(ctx, config.OrgID, saID)).To(Succeed())

				Eventually(func(g Gomega) {
					resp, err := narrowClient.PostApiV1AuthorizationCheckWithResponse(ctx, projectReadCheck(&passport))
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(resp.StatusCode()).To(Equal(http.StatusUnauthorized),
						"a passport must not outlive its subject; body: %s", string(resp.Body))
					g.Expect(resp.JSON200).To(BeNil())
				}).WithTimeout(30 * time.Second).WithPolling(time.Second).Should(Succeed())

				Expect(time.Now()).To(BeTemporally("<", expiry), "the 401 must come from the deleted subject, not from the expiry of the passport")
			})
		})
	})
})
