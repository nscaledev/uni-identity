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
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/test/api"
)

func expectAuditRequestForbidden(method, path string, payload any) {
	GinkgoHelper()

	var body io.Reader
	if payload != nil {
		bodyBytes, err := json.Marshal(payload)
		Expect(err).NotTo(HaveOccurred())

		body = bytes.NewReader(bodyBytes)
	}

	resp, _, err := auditClient.DoRequest(ctx, method, path, body, http.StatusForbidden)
	Expect(err).NotTo(HaveOccurred(),
		"audit %s %s should return 403 Forbidden", method, path)
	Expect(resp).NotTo(BeNil())
	Expect(resp.StatusCode).To(Equal(http.StatusForbidden))
}

var _ = Describe("Console Audit View Permissions", func() {
	Context("When reading console-visible resources", func() {
		BeforeEach(func() {
			if auditClient == nil {
				Skip("AUDIT_AUTH_TOKEN is not configured — skipping audit read-access tests")
			}
		})

		Describe("Given a request to list organizations", func() {
			It("audit token should succeed and return at least one organization", func() {
				orgs, err := auditClient.ListOrganizations(ctx)

				Expect(err).NotTo(HaveOccurred())
				Expect(orgs).NotTo(BeEmpty())

				var orgIDs []string
				for _, org := range orgs {
					orgIDs = append(orgIDs, org.Metadata.Id)
				}

				Expect(orgIDs).To(ContainElement(config.OrgID))

				GinkgoWriter.Printf("Audit: listed %d organizations\n", len(orgs))
			})
		})

		Describe("Given a request to view organization details", func() {
			It("audit token should return organization with matching ID", func() {
				org, err := auditClient.GetOrganization(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(org).NotTo(BeNil())
				Expect(org.Metadata.Id).To(Equal(config.OrgID))

				GinkgoWriter.Printf("Audit: fetched org %s\n", config.OrgID)
			})
		})

		Describe("Given a request to list users", func() {
			It("audit token should succeed and return a list", func() {
				users, err := auditClient.ListUsers(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				if config.UserID != "" {
					var userIDs []string
					for _, user := range users {
						userIDs = append(userIDs, user.Metadata.Id)
					}

					Expect(userIDs).To(ContainElement(config.UserID))
				}

				GinkgoWriter.Printf("Audit: listed %d users\n", len(users))
			})
		})

		Describe("Given a request to list roles", func() {
			It("audit token should succeed and return at least one role", func() {
				roles, err := auditClient.ListRoles(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(roles).NotTo(BeEmpty())

				GinkgoWriter.Printf("Audit: listed %d roles\n", len(roles))
			})
		})

		Describe("Given a request to list groups", func() {
			It("audit token should succeed and return a list", func() {
				groups, err := auditClient.ListGroups(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(groups).NotTo(BeEmpty())
				GinkgoWriter.Printf("Audit: listed %d groups\n", len(groups))
			})
		})

		Describe("Given a request to list projects", func() {
			It("audit token should succeed and return a list", func() {
				projects, err := auditClient.ListProjects(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				var projectIDs []string
				for _, project := range projects {
					projectIDs = append(projectIDs, project.Metadata.Id)
				}

				Expect(projectIDs).To(ContainElement(config.ProjectID))
				GinkgoWriter.Printf("Audit: listed %d projects\n", len(projects))
			})
		})

		Describe("Given a request to list service accounts", func() {
			It("audit token should succeed and return a list", func() {
				sas, err := auditClient.ListServiceAccounts(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				if config.UserSAID != "" {
					var serviceAccountIDs []string
					for _, sa := range sas {
						serviceAccountIDs = append(serviceAccountIDs, sa.Metadata.Id)
					}

					Expect(serviceAccountIDs).To(ContainElement(config.UserSAID))
				}

				GinkgoWriter.Printf("Audit: listed %d service accounts\n", len(sas))
			})
		})

		Describe("Given a request to read quotas", func() {
			It("audit token should succeed and return a quotas object", func() {
				quotas, err := auditClient.GetQuotas(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(quotas).NotTo(BeNil())

				GinkgoWriter.Printf("Audit: read quotas (%d entries)\n", len(quotas.Quotas))
			})
		})
	})

	Context("When mutating console-managed resources", func() {
		BeforeEach(func() {
			if auditClient == nil {
				Skip("AUDIT_AUTH_TOKEN is not configured — skipping audit write-denied tests")
			}
		})

		Describe("Given a POST to create a group", func() {
			It("audit token should be denied with a forbidden response", func() {
				expectAuditRequestForbidden(http.MethodPost,
					api.NewEndpoints().ListGroups(config.OrgID),
					api.NewGroupPayload().Build())

				GinkgoWriter.Printf("Audit group create correctly denied with 403\n")
			})
		})

		Describe("Given a PUT to update a group", func() {
			It("audit token should be denied with a forbidden response", func() {
				_, groupID := api.CreateGroupWithCleanup(adminClient, ctx, config,
					api.NewGroupPayload().Build())

				expectAuditRequestForbidden(http.MethodPut,
					api.NewEndpoints().GetGroup(config.OrgID, groupID),
					api.NewGroupPayload().Build())

				GinkgoWriter.Printf("Audit group update correctly denied with 403\n")
			})
		})

		Describe("Given a DELETE to remove a group", func() {
			It("audit token should be denied with a forbidden response", func() {
				_, groupID := api.CreateGroupWithCleanup(adminClient, ctx, config,
					api.NewGroupPayload().Build())

				expectAuditRequestForbidden(http.MethodDelete,
					api.NewEndpoints().GetGroup(config.OrgID, groupID), nil)

				GinkgoWriter.Printf("Audit group delete correctly denied with 403\n")
			})
		})

		Describe("Given a PUT to update the organization", func() {
			It("audit token should be denied with a forbidden response", func() {
				original, err := adminClient.GetOrganization(ctx, config.OrgID)
				Expect(err).NotTo(HaveOccurred())

				expectAuditRequestForbidden(http.MethodPut,
					api.NewEndpoints().GetOrganization(config.OrgID),
					api.NewOrganizationPayload().FromRead(*original).Build())

				GinkgoWriter.Printf("Audit org update correctly denied with 403\n")
			})
		})

		Describe("Given a PUT to update quotas", func() {
			It("audit token should be denied with a forbidden response", func() {
				expectAuditRequestForbidden(http.MethodPut,
					api.NewEndpoints().GetQuotas(config.OrgID),
					identityopenapi.QuotasWrite{})

				GinkgoWriter.Printf("Audit quota update correctly denied with 403\n")
			})
		})
	})
})
