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

var _ = Describe("Access Control Discovery", func() {
	Context("When getting global ACL", func() {
		Describe("Given valid authentication", func() {
			It("should return global ACL with organization permissions", func() {
				acl, err := client.GetGlobalACL(ctx)

				Expect(err).NotTo(HaveOccurred())
				Expect(acl).NotTo(BeNil())
				Expect(acl.Organizations).NotTo(BeNil(), "Organizations ACL should be present")
				Expect(*acl.Organizations).NotTo(BeEmpty(), "At least one organization should be present in ACL")

				for _, org := range *acl.Organizations {
					Expect(org.Id).NotTo(BeEmpty(), "Organization ID should not be empty")

					if org.Endpoints != nil {
						Expect(*org.Endpoints).NotTo(BeEmpty(), "Organization should have at least one endpoint permission")

						for _, endpoint := range *org.Endpoints {
							Expect(endpoint.Name).NotTo(BeEmpty(), "Endpoint name should not be empty")
							Expect(endpoint.Operations).NotTo(BeEmpty(), "Endpoint should have at least one operation")

							for _, op := range endpoint.Operations {
								Expect(op).To(BeElementOf(
									identityopenapi.Create,
									identityopenapi.Read,
									identityopenapi.Update,
									identityopenapi.Delete),
									"Operation should be a valid CRUD operation")
							}

							GinkgoWriter.Printf("  Endpoint: %s (operations: %v)\n",
								endpoint.Name, endpoint.Operations)
						}
					}
				}

				found := false
				for _, org := range *acl.Organizations {
					if org.Id == config.OrgID {
						found = true
						GinkgoWriter.Printf("Found test organization in ACL: %s\n", config.OrgID)
						break
					}
				}
				Expect(found).To(BeTrue(), "Test organization %s should be in global ACL", config.OrgID)

				GinkgoWriter.Printf("Global ACL retrieved with %d organizations\n", len(*acl.Organizations))
			})
		})

		Describe("Given invalid authentication", func() {
			It("should reject requests without valid token", func() {
				unauthClient := coreclient.NewAPIClient(config.BaseURL, "", config.RequestTimeout, &api.GinkgoLogger{})
				_, _, err := unauthClient.DoRequest(ctx, http.MethodGet, "/api/v1/acl", nil, http.StatusOK)

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrUnexpectedStatusCode)).To(BeTrue(),
					"Should return unexpected status code error for missing auth")

				GinkgoWriter.Printf("Expected error for missing authentication: %v\n", err)
			})
		})
	})

	Context("When getting organization ACL", func() {
		Describe("Given valid organization", func() {
			It("should return organization-scoped ACL with detailed permissions", func() {
				acl, err := client.GetOrganizationACL(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(acl).NotTo(BeNil())
				Expect(acl.Organization).NotTo(BeNil(), "Organization field should be present in org ACL")
				Expect(acl.Organization.Id).To(Equal(config.OrgID), "Organization ID should match request")

				if acl.Organization.Endpoints != nil {
					Expect(*acl.Organization.Endpoints).NotTo(BeEmpty(),
						"Organization should have at least one endpoint permission")

					endpointsByService := make(map[string]int)
					for _, endpoint := range *acl.Organization.Endpoints {
						Expect(endpoint.Name).NotTo(BeEmpty())
						Expect(endpoint.Operations).NotTo(BeEmpty())

						serviceName := endpoint.Name
						for idx := 0; idx < len(serviceName); idx++ {
							if serviceName[idx] == ':' {
								serviceName = serviceName[:idx]
								break
							}
						}
						endpointsByService[serviceName]++
					}

					GinkgoWriter.Printf("Organization ACL for %s retrieved\n", config.OrgID)
					GinkgoWriter.Printf("  Total endpoints: %d\n", len(*acl.Organization.Endpoints))
					for service, count := range endpointsByService {
						GinkgoWriter.Printf("  Service '%s': %d endpoints\n", service, count)
					}
				}
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return empty ACL for non-existent organization", func() {
				acl, err := client.GetOrganizationACL(ctx, "00000000-0000-0000-0000-000000000000")

				Expect(err).NotTo(HaveOccurred())
				Expect(acl).NotTo(BeNil())

				if acl.Organization != nil {
					Expect(acl.Organization.Id).To(Equal("00000000-0000-0000-0000-000000000000"))
					if acl.Organization.Endpoints != nil {
						GinkgoWriter.Printf("Non-existent org ACL has %d endpoints\n", len(*acl.Organization.Endpoints))
					}
				}

				GinkgoWriter.Printf("Non-existent organization returns valid (but likely empty) ACL\n")
			})
		})
	})
})
