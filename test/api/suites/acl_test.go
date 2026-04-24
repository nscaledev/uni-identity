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
		// The user role (not administrator) has project-scoped endpoint permissions,
		// so only the user token produces ACL entries under Organization.Projects.
		Describe("Given the caller is a member of groups assigned to projects", func() {
			BeforeEach(func() {
				if userClient == nil {
					Skip("USER_AUTH_TOKEN is required for ACL projection testing")
				}
			})

			It("should no longer include a project in the ACL after it is deleted", func() {
				if config.UserGroupID == "" {
					Skip("TEST_USER_GROUP_ID is not configured")
				}

				_, projectID := api.CreateProjectWithCleanup(adminClient, ctx, config,
					api.NewProjectPayload().
						WithGroupIDs([]string{config.UserGroupID}).
						Build())

				api.WaitForProjectProvisioned(adminClient, ctx, config, projectID)

				api.WaitForProjectInACL(userClient, ctx, config, projectID)

				Expect(adminClient.DeleteProject(ctx, config.OrgID, projectID)).To(Succeed())

				api.WaitForProjectRemovedFromACL(userClient, ctx, config, projectID)

				GinkgoWriter.Printf("Verified project %s no longer appears in ACL after deletion\n", projectID)
			})

		})

		Describe("Given the caller belongs to an organization", func() {
			It("should include ACL content for the caller's organization", func() {
				acl, err := adminClient.GetGlobalACL(ctx)

				Expect(err).NotTo(HaveOccurred())
				Expect(acl).NotTo(BeNil())
				Expect(acl.Organizations).NotTo(BeNil(), "Organizations field should be present in ACL")

				var organization *identityopenapi.AclOrganization
				unrelatedFound := false
				for i := range *acl.Organizations {
					if (*acl.Organizations)[i].Id == "00000000-0000-0000-0000-000000000000" {
						unrelatedFound = true
					}

					if (*acl.Organizations)[i].Id == config.OrgID {
						organization = &(*acl.Organizations)[i]
					}
				}
				Expect(organization).NotTo(BeNil(), "Organization ID should be present in ACL")
				Expect(unrelatedFound).To(BeFalse(),
					"ACL should not include organizations the caller is not a member of")

				if organization.Endpoints != nil {
					Expect(*organization.Endpoints).NotTo(BeEmpty(),
						"Organization should have at least one endpoint permission")
					endpointsByService := make(map[string]int)
					for _, endpoint := range *organization.Endpoints {
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
					GinkgoWriter.Printf("  Total endpoints: %d\n", len(*organization.Endpoints))
					for service, count := range endpointsByService {
						GinkgoWriter.Printf("  Service '%s': %d endpoints\n", service, count)
					}
				}
			})
		})
	})
})
