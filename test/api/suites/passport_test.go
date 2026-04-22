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
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/test/api"
)

// decodePassportClaims parses a passport JWT's payload without verifying the
// signature. Integration tests only care about the claim shape, and the signing
// key would require fetching the JWKS.
func decodePassportClaims(passport string) (*oauth2.PassportClaims, error) {
	parts := strings.Split(passport, ".")
	if len(parts) != 3 {
		return nil, errors.New("passport is not a JWT")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	claims := &oauth2.PassportClaims{}
	if err := json.Unmarshal(payload, claims); err != nil {
		return nil, err
	}

	return claims, nil
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

				GinkgoWriter.Printf("Org+project-scoped passport exchanged for org %s, project %s\n",
					config.OrgID, config.ProjectID)
			})
		})

		Describe("Given no authentication", func() {
			It("should reject the exchange request", func() {
				unauthClient := coreclient.NewAPIClient(config.BaseURL, "", config.RequestTimeout, &api.GinkgoLogger{})
				path := client.GetEndpoints().Exchange()

				_, respBody, err := unauthClient.DoRequest(ctx, http.MethodPost, path, nil, http.StatusOK)

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrUnexpectedStatusCode)).To(BeTrue(),
					"Should return unexpected status code error for missing auth")
				Expect(string(respBody)).To(ContainSubstring("access_denied"),
					"Response body should contain access_denied error")

				GinkgoWriter.Printf("Expected error for missing authentication: %v\n", err)
			})
		})
	})

	Context("When a service impersonates a user via mTLS", func() {
		var (
			mtlsClient *api.MTLSClient
			actingAs   *principal.Principal
		)

		BeforeEach(func() {
			if config.ImpersonationCertPath == "" || config.ImpersonationKeyPath == "" {
				Skip("impersonation fixtures not configured; run `make integration-fixtures` to provision them")
			}

			if config.ImpersonationUserSubject == "" {
				Skip("TEST_IMPERSONATION_USER_SUBJECT not set; run `make integration-fixtures`")
			}

			var err error
			mtlsClient, err = api.NewMTLSClient(api.MTLSClientOptions{
				BaseURL:    config.BaseURL,
				CertPath:   config.ImpersonationCertPath,
				KeyPath:    config.ImpersonationKeyPath,
				CACertPath: config.CACertPath,
				Timeout:    config.RequestTimeout,
			})
			Expect(err).NotTo(HaveOccurred())

			actingAs = &principal.Principal{
				Actor:           config.ImpersonationUserSubject,
				OrganizationIDs: []string{config.OrgID},
				OrganizationID:  config.OrgID,
			}
		})

		Describe("Given a valid principal and X-Impersonate: true", func() {
			It("should return a passport whose actor matches the impersonated user", func() {
				result, err := mtlsClient.ExchangePassport(ctx, api.ImpersonatedExchangeOptions{
					Principal:    actingAs,
					Impersonate:  true,
					Organization: &config.OrgID,
				})

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.Passport).NotTo(BeEmpty())
				Expect(result.ExpiresIn).To(Equal(120))

				claims, err := decodePassportClaims(result.Passport)
				Expect(err).NotTo(HaveOccurred())
				Expect(claims.Actor).To(Equal(config.ImpersonationUserSubject),
					"Passport actor should be the impersonated user, not the calling service")
				Expect(string(claims.Acctype)).To(Equal("user"),
					"Passport acctype must mark this as user-sourced, not service/system")
				Expect(claims.OrgID).To(Equal(config.OrgID))

				GinkgoWriter.Printf("Impersonated passport minted for %s in org %s\n",
					claims.Actor, claims.OrgID)
			})
		})

		Describe("Given a valid principal but the X-Impersonate header is missing", func() {
			It("should refuse with OAuth2 invalid_request (400)", func() {
				// Autonomous service-to-service mTLS calls must NOT be issued a
				// passport: missing the impersonate header is a programming error
				// that has to surface, not silently upgrade to system creds.
				resp, body, err := mtlsClient.ExchangePassportRaw(ctx, api.ImpersonatedExchangeOptions{
					Principal:             actingAs,
					OmitImpersonateHeader: true,
					Organization:          &config.OrgID,
				})

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest),
					"mTLS without X-Impersonate must fail closed")
				Expect(string(body)).To(ContainSubstring("invalid_request"))
			})
		})

		Describe("Given X-Impersonate: false", func() {
			It("should refuse with OAuth2 invalid_request (400)", func() {
				resp, body, err := mtlsClient.ExchangePassportRaw(ctx, api.ImpersonatedExchangeOptions{
					Principal:              actingAs,
					ImpersonateHeaderValue: "false",
					Organization:           &config.OrgID,
				})

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))
				Expect(string(body)).To(ContainSubstring("invalid_request"))
			})
		})

		Describe("Given a malformed X-Principal header", func() {
			It("should refuse with OAuth2 access_denied (401)", func() {
				garbage := "!!not-base64!!"
				resp, body, err := mtlsClient.ExchangePassportRaw(ctx, api.ImpersonatedExchangeOptions{
					Impersonate:             true,
					Organization:            &config.OrgID,
					PrincipalHeaderOverride: &garbage,
				})

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized),
					"invalid principal header must fail closed with 401")
				Expect(string(body)).To(ContainSubstring("access_denied"))
			})
		})

		Describe("Given a principal scoped to an organization the caller is not a member of", func() {
			It("should refuse with OAuth2 access_denied (401)", func() {
				// The principal lists an org the impersonated user doesn't
				// belong to. The handler must reject this even with a valid
				// cert + impersonate flag.
				otherOrg := "org-does-not-exist"
				otherOrgPrincipal := &principal.Principal{
					Actor:           config.ImpersonationUserSubject,
					OrganizationIDs: []string{otherOrg},
					OrganizationID:  otherOrg,
				}

				resp, _, err := mtlsClient.ExchangePassportRaw(ctx, api.ImpersonatedExchangeOptions{
					Principal:    otherOrgPrincipal,
					Impersonate:  true,
					Organization: &otherOrg,
				})

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized),
					"out-of-scope org in principal must be rejected")
			})
		})
	})
})
