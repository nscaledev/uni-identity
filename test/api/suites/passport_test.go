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
	"errors"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/test/api"
)

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
})
