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
			Expect(auditClient).NotTo(BeNil(), "AUDIT_AUTH_TOKEN must be set by integration fixtures")
		})

		Describe("Given a request to list organizations", func() {
			It("audit token should succeed and return at least one organization", func() {
				Expect(config.UnauthorisedOrgID).NotTo(BeEmpty(),
					"UNAUTHORISED_ORG_ID must be set by integration fixtures")

				orgs, err := auditClient.ListOrganizations(ctx)

				Expect(err).NotTo(HaveOccurred())
				Expect(orgs).NotTo(BeEmpty())

				var orgIDs []string
				for _, org := range orgs {
					Expect(org.Metadata.Id).NotTo(BeEmpty())
					orgIDs = append(orgIDs, org.Metadata.Id)
				}

				Expect(orgIDs).To(ContainElement(config.OrgID))
				Expect(orgIDs).NotTo(ContainElement(config.UnauthorisedOrgID),
					"audit token must not list organizations outside its scope")

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
				Expect(config.UserID).NotTo(BeEmpty(), "TEST_USER_ID must be set by integration fixtures")
				Expect(config.UserSubjectEmail).NotTo(BeEmpty(),
					"TEST_USER_SUBJECT_EMAIL must be set by integration fixtures")

				users, err := auditClient.ListUsers(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				found := false
				for _, user := range users {
					Expect(user.Metadata.OrganizationId).To(Equal(config.OrgID))

					if user.Metadata.Id == config.UserID {
						found = true
						Expect(user.Spec.Subject).To(Equal(config.UserSubjectEmail))

						break
					}
				}

				Expect(found).To(BeTrue(),
					"audit token should see fixture user %s in organization %s", config.UserID, config.OrgID)
				GinkgoWriter.Printf("Audit: listed %d users\n", len(users))
			})
		})

		Describe("Given a request to list roles", func() {
			It("audit token should succeed and return the auditor role", func() {
				roles, err := auditClient.ListRoles(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(roles).NotTo(BeEmpty())

				roleNames := make(map[string]bool)
				for _, role := range roles {
					Expect(role.Metadata.Id).NotTo(BeEmpty())
					Expect(role.Metadata.Name).NotTo(BeEmpty())

					roleNames[role.Metadata.Name] = true
				}

				Expect(roleNames).To(HaveKey("auditor"))
				Expect(roleNames).NotTo(HaveKey("administrator"),
					"audit token must not see administrator as a grantable role")
				Expect(roleNames).NotTo(HaveKey("user"),
					"audit token must not see user as a grantable role")

				GinkgoWriter.Printf("Audit: listed %d roles\n", len(roles))
			})
		})

		Describe("Given a request to list groups", func() {
			It("audit token should succeed and return a list", func() {
				Expect(config.AdminGroupID).NotTo(BeEmpty(),
					"TEST_ADMIN_GROUP_ID must be set by integration fixtures")
				Expect(config.UserGroupID).NotTo(BeEmpty(),
					"TEST_USER_GROUP_ID must be set by integration fixtures")

				groups, err := auditClient.ListGroups(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(groups).NotTo(BeEmpty())

				var groupIDs []string
				for _, group := range groups {
					Expect(group.Metadata.Id).NotTo(BeEmpty())
					Expect(group.Metadata.OrganizationId).To(Equal(config.OrgID))

					groupIDs = append(groupIDs, group.Metadata.Id)
				}

				Expect(groupIDs).To(ContainElements(config.AdminGroupID, config.UserGroupID))
				GinkgoWriter.Printf("Audit: listed %d groups\n", len(groups))
			})
		})

		Describe("Given a request to list projects", func() {
			It("audit token should succeed and return a list", func() {
				projects, err := auditClient.ListProjects(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				var projectIDs []string
				for _, project := range projects {
					Expect(project.Metadata.OrganizationId).To(Equal(config.OrgID))

					projectIDs = append(projectIDs, project.Metadata.Id)
				}

				Expect(projectIDs).To(ContainElement(config.ProjectID))
				GinkgoWriter.Printf("Audit: listed %d projects\n", len(projects))
			})
		})

		Describe("Given a request to list service accounts", func() {
			It("audit token should succeed and return a list", func() {
				Expect(config.UserSAID).NotTo(BeEmpty(), "TEST_USER_SA_ID must be set by integration fixtures")
				Expect(config.UserGroupID).NotTo(BeEmpty(),
					"TEST_USER_GROUP_ID must be set by integration fixtures")

				sas, err := auditClient.ListServiceAccounts(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				found := false
				for _, sa := range sas {
					Expect(sa.Metadata.Id).NotTo(BeEmpty())
					Expect(sa.Metadata.OrganizationId).To(Equal(config.OrgID))

					if sa.Metadata.Id == config.UserSAID {
						found = true
						Expect(sa.Spec.GroupIDs).To(ContainElement(config.UserGroupID))

						break
					}
				}

				Expect(found).To(BeTrue(),
					"audit token should see fixture service account %s", config.UserSAID)
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
			Expect(auditClient).NotTo(BeNil(), "AUDIT_AUTH_TOKEN must be set by integration fixtures")
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
				current, err := adminClient.GetQuotas(ctx, config.OrgID)
				Expect(err).NotTo(HaveOccurred())
				Expect(current.Quotas).NotTo(BeEmpty())

				writes := make(identityopenapi.QuotaWriteList, len(current.Quotas))
				for i, quota := range current.Quotas {
					writes[i] = identityopenapi.QuotaWrite{Kind: quota.Kind, Quantity: quota.Quantity}
				}

				expectAuditRequestForbidden(http.MethodPut,
					api.NewEndpoints().GetQuotas(config.OrgID),
					identityopenapi.QuotasWrite{Quotas: writes})

				GinkgoWriter.Printf("Audit quota update correctly denied with 403\n")
			})
		})
	})
})
