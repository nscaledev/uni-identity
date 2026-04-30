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

//nolint:revive,testpackage // dot imports and package naming standard for Ginkgo
package suites

import (
	"encoding/json"
	goerrors "errors"
	"net/http"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	oauth2errors "github.com/unikorn-cloud/identity/pkg/oauth2/errors"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/test/api"
)

type actorClaim struct {
	Subject string      `json:"sub"`
	Act     *actorClaim `json:"act,omitempty"`
}

type passportClaims struct {
	jwt.Claims `json:",inline"`

	Type      string                            `json:"typ"`
	Acctype   identityopenapi.AuthClaimsAcctype `json:"acctype"`
	Source    string                            `json:"source"`
	Email     string                            `json:"email,omitempty"`
	OrgIDs    []string                          `json:"org_ids"`
	OrgID     string                            `json:"org_id,omitempty"`
	ProjectID string                            `json:"project_id,omitempty"`
	Actor     *actorClaim                       `json:"act,omitempty"`
}

func passportIssuedTokenType() string {
	return "urn:nscale:params:oauth:token-type:passport"
}

func decodePassportClaims(passport string) passportClaims {
	parsed, err := jwt.ParseSigned(passport, []gojose.SignatureAlgorithm{gojose.ES512})
	Expect(err).NotTo(HaveOccurred(), "Passport should be a valid ES512 JWS")
	Expect(parsed.Headers).To(HaveLen(1))
	Expect(parsed.Headers[0].Algorithm).To(Equal(string(gojose.ES512)))

	var claims passportClaims

	Expect(parsed.UnsafeClaimsWithoutVerification(&claims)).To(Succeed())

	return claims
}

func decodeExchangeOAuth2Error(respBody []byte) identityopenapi.Oauth2Error {
	var oauthErr identityopenapi.Oauth2Error

	Expect(json.Unmarshal(respBody, &oauthErr)).To(Succeed())

	return oauthErr
}

var _ = Describe("Passport Token Exchange", func() {
	Context("When exchanging an access token for a passport", func() {
		Describe("Given valid authentication without scope", func() {
			It("should return a signed passport with correct metadata", func() {
				result, err := client.ExchangePassport(ctx, nil)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.AccessToken).NotTo(BeEmpty(), "Passport JWT should not be empty")
				Expect(result.ExpiresIn).To(Equal(120), "Passport TTL should be 120 seconds")
				Expect(result.TokenType).To(Equal("Bearer"))
				Expect(result.IssuedTokenType).NotTo(BeNil())
				Expect(*result.IssuedTokenType).To(Equal(passportIssuedTokenType()))

				claims := decodePassportClaims(result.AccessToken)
				Expect(claims.Type).To(Equal("passport"))
				Expect(claims.Source).To(Equal("uni"))
				Expect(claims.Subject).NotTo(BeEmpty())
				Expect(claims.Actor).To(BeNil(), "act claim must be omitted when subject is the acting party")

				GinkgoWriter.Printf("Passport exchanged successfully, expires_in: %d\n", result.ExpiresIn)
			})
		})

		Describe("Given valid authentication with organization scope", func() {
			It("should return a passport scoped to the organization", func() {
				options := &identityopenapi.TokenRequestOptions{
					XOrganizationId: &config.OrgID,
				}

				result, err := client.ExchangePassport(ctx, options)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.AccessToken).NotTo(BeEmpty(), "Passport JWT should not be empty")
				Expect(result.ExpiresIn).To(Equal(120), "Passport TTL should be 120 seconds")

				claims := decodePassportClaims(result.AccessToken)
				Expect(claims.OrgID).To(Equal(config.OrgID))
				Expect(claims.ProjectID).To(BeEmpty())

				GinkgoWriter.Printf("Org-scoped passport exchanged for org %s\n", config.OrgID)
			})
		})

		Describe("Given valid authentication with organization and project scope", func() {
			It("should return a passport scoped to the organization and project", func() {
				options := &identityopenapi.TokenRequestOptions{
					XOrganizationId: &config.OrgID,
					XProjectId:      &config.ProjectID,
				}

				result, err := client.ExchangePassport(ctx, options)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.AccessToken).NotTo(BeEmpty(), "Passport JWT should not be empty")
				Expect(result.ExpiresIn).To(Equal(120), "Passport TTL should be 120 seconds")

				claims := decodePassportClaims(result.AccessToken)
				Expect(claims.OrgID).To(Equal(config.OrgID))
				Expect(claims.ProjectID).To(Equal(config.ProjectID))

				GinkgoWriter.Printf("Org+project-scoped passport exchanged for org %s, project %s\n",
					config.OrgID, config.ProjectID)
			})
		})

		Describe("Given an out-of-scope organization", func() {
			It("should reject the exchange with an OAuth2 invalid_target response", func() {
				invalidOrgID := "00000000-0000-0000-0000-000000000000"
				options := &identityopenapi.TokenRequestOptions{
					XOrganizationId: &invalidOrgID,
				}

				resp, respBody, err := client.ExchangePassportRaw(ctx, 0, options)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))

				oauthErr := decodeExchangeOAuth2Error(respBody)
				Expect(oauthErr.Error).To(Equal(oauth2errors.InvalidTargetCode))
				Expect(oauthErr.ErrorDescription).To(ContainSubstring("organization not in scope"))
			})
		})

		Describe("Given an invalid project scope", func() {
			It("should reject the exchange with an OAuth2 invalid_target response", func() {
				invalidProjectID := "00000000-0000-0000-0000-000000000000"
				options := &identityopenapi.TokenRequestOptions{
					XOrganizationId: &config.OrgID,
					XProjectId:      &invalidProjectID,
				}

				resp, respBody, err := client.ExchangePassportRaw(ctx, 0, options)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))

				oauthErr := decodeExchangeOAuth2Error(respBody)
				Expect(oauthErr.Error).To(Equal(oauth2errors.InvalidTargetCode))
				Expect(oauthErr.ErrorDescription).To(ContainSubstring("project not in scope"))
			})
		})

		Describe("Given no authentication", func() {
			It("should reject the exchange request", func() {
				unauthConfig := *config
				unauthConfig.AuthToken = ""
				unauthClient := api.NewAPIClientWithConfig(&unauthConfig)

				_, respBody, err := unauthClient.ExchangePassportRaw(ctx, 200, nil)

				Expect(err).To(HaveOccurred())
				Expect(goerrors.Is(err, coreclient.ErrUnexpectedStatusCode)).To(BeTrue(),
					"Should return unexpected status code error for missing auth")

				oauthErr := decodeExchangeOAuth2Error(respBody)
				Expect(oauthErr.Error).To(Equal(identityopenapi.InvalidRequest))
				Expect(oauthErr.ErrorDescription).To(ContainSubstring("subject_token must be specified"))

				GinkgoWriter.Printf("Expected error for missing authentication: %v\n", err)
			})
		})
	})

	Context("When exchanging a service account access token for a passport", func() {
		Describe("Given a service account in the organization", func() {
			It("should return a signed service passport with the expected claims", func() {
				created, _ := api.CreateServiceAccountWithCleanup(client, ctx, config,
					api.NewServiceAccountPayload().Build())

				Expect(created.Status.AccessToken).NotTo(BeNil(), "Service account create should return a token")

				serviceConfig := *config
				serviceConfig.AuthToken = *created.Status.AccessToken
				serviceClient := api.NewAPIClientWithConfig(&serviceConfig)

				result, err := serviceClient.ExchangePassport(ctx, &identityopenapi.TokenRequestOptions{
					XOrganizationId: &config.OrgID,
				})

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.AccessToken).NotTo(BeEmpty())
				Expect(result.ExpiresIn).To(Equal(120))
				Expect(result.TokenType).To(Equal("Bearer"))
				Expect(result.IssuedTokenType).NotTo(BeNil())
				Expect(*result.IssuedTokenType).To(Equal(passportIssuedTokenType()))

				claims := decodePassportClaims(result.AccessToken)
				Expect(claims.Type).To(Equal("passport"))
				Expect(claims.Acctype).To(Equal(identityopenapi.Service))
				Expect(claims.Source).To(Equal("uni"))
				Expect(claims.Subject).NotTo(BeEmpty())
				Expect(claims.Actor).To(BeNil(), "act claim must be omitted when subject is the acting party")
				Expect(claims.OrgIDs).To(ContainElement(config.OrgID))
				Expect(claims.OrgID).To(Equal(config.OrgID))
				Expect(claims.ProjectID).To(BeEmpty())
			})
		})
	})
})
