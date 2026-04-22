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

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/test/api"
)

type passportClaims struct {
	jwt.Claims `json:",inline"`

	Type      string                            `json:"typ"`
	Acctype   identityopenapi.AuthClaimsAcctype `json:"acctype"`
	Source    string                            `json:"source"`
	Email     string                            `json:"email,omitempty"`
	OrgIDs    []string                          `json:"org_ids"`
	OrgID     string                            `json:"org_id,omitempty"`
	ProjectID string                            `json:"project_id,omitempty"`
	Actor     string                            `json:"actor"`
	ACL       *identityopenapi.Acl              `json:"acl"`
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

var _ = Describe("Passport Token Exchange", func() {
	Context("When exchanging an access token for a passport", func() {
		Describe("Given valid authentication without scope", func() {
			It("should return a signed passport with correct metadata", func() {
				result, err := client.ExchangePassport(ctx, nil)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.Passport).NotTo(BeEmpty(), "Passport JWT should not be empty")
				Expect(result.ExpiresIn).To(Equal(120), "Passport TTL should be 120 seconds")

				claims := decodePassportClaims(result.Passport)
				Expect(claims.Type).To(Equal("passport"))
				Expect(claims.Source).To(Equal("uni"))
				Expect(claims.Subject).NotTo(BeEmpty())
				Expect(claims.Actor).To(Equal(claims.Subject))
				Expect(claims.ACL).NotTo(BeNil())

				GinkgoWriter.Printf("Passport exchanged successfully, expires_in: %d\n", result.ExpiresIn)
			})
		})

		Describe("Given valid authentication with organization scope", func() {
			It("should return a passport scoped to the organization", func() {
				options := &identityopenapi.ExchangeRequestOptions{
					OrganizationId: &config.OrgID,
				}

				result, err := client.ExchangePassport(ctx, options)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.Passport).NotTo(BeEmpty(), "Passport JWT should not be empty")
				Expect(result.ExpiresIn).To(Equal(120), "Passport TTL should be 120 seconds")

				claims := decodePassportClaims(result.Passport)
				Expect(claims.OrgID).To(Equal(config.OrgID))
				Expect(claims.ProjectID).To(BeEmpty())
				Expect(claims.ACL).NotTo(BeNil())

				GinkgoWriter.Printf("Org-scoped passport exchanged for org %s\n", config.OrgID)
			})
		})

		Describe("Given valid authentication with organization and project scope", func() {
			It("should return a passport scoped to the organization and project", func() {
				options := &identityopenapi.ExchangeRequestOptions{
					OrganizationId: &config.OrgID,
					ProjectId:      &config.ProjectID,
				}

				result, err := client.ExchangePassport(ctx, options)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.Passport).NotTo(BeEmpty(), "Passport JWT should not be empty")
				Expect(result.ExpiresIn).To(Equal(120), "Passport TTL should be 120 seconds")

				claims := decodePassportClaims(result.Passport)
				Expect(claims.OrgID).To(Equal(config.OrgID))
				Expect(claims.ProjectID).To(Equal(config.ProjectID))
				Expect(claims.ACL).NotTo(BeNil())

				GinkgoWriter.Printf("Org+project-scoped passport exchanged for org %s, project %s\n",
					config.OrgID, config.ProjectID)
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

				var oauthErr identityopenapi.Oauth2Error

				Expect(json.Unmarshal(respBody, &oauthErr)).To(Succeed())
				Expect(oauthErr.Error).To(Equal(identityopenapi.AccessDenied))
				Expect(oauthErr.ErrorDescription).To(ContainSubstring("authorization header not set"))

				GinkgoWriter.Printf("Expected error for missing authentication: %v\n", err)
			})
		})
	})
})
