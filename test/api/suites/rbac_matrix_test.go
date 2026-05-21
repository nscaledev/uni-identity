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

func expectUserRequestForbidden(method, path string, payload any) {
	GinkgoHelper()

	var body io.Reader
	if payload != nil {
		bodyBytes, err := json.Marshal(payload)
		Expect(err).NotTo(HaveOccurred())

		body = bytes.NewReader(bodyBytes)
	}

	resp, _, err := userClient.DoRequest(ctx, method, path, body, http.StatusForbidden)
	Expect(err).NotTo(HaveOccurred(),
		"user %s %s should return 403 Forbidden", method, path)
	Expect(resp).NotTo(BeNil())
	Expect(resp.StatusCode).To(Equal(http.StatusForbidden))
}

var _ = Describe("RBAC Enforcement", func() {
	BeforeEach(func() {
		Expect(config.AdminToken).NotTo(BeEmpty(),
			"ADMIN_AUTH_TOKEN must be set by integration fixtures")
		Expect(adminClient).NotTo(BeNil(),
			"ADMIN_AUTH_TOKEN must create an administrator API client")
		Expect(config.UserToken).NotTo(BeEmpty(),
			"USER_AUTH_TOKEN must be set by integration fixtures")
		Expect(userClient).NotTo(BeNil(),
			"USER_AUTH_TOKEN must create a user API client")
	})

	Context("When authenticated as an administrator", func() {
		Describe("Given a request to list groups", func() {
			It("should return all groups in the organization with complete metadata", func() {
				Expect(config.AdminGroupID).NotTo(BeEmpty(),
					"TEST_ADMIN_GROUP_ID must be set by integration fixtures")
				Expect(config.UserGroupID).NotTo(BeEmpty(),
					"TEST_USER_GROUP_ID must be set by integration fixtures")

				groups, err := adminClient.ListGroups(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(groups).NotTo(BeEmpty())

				var groupIDs []string
				for _, group := range groups {
					Expect(group.Metadata.Id).NotTo(BeEmpty())
					Expect(group.Metadata.OrganizationId).To(Equal(config.OrgID))

					groupIDs = append(groupIDs, group.Metadata.Id)
				}

				Expect(groupIDs).To(ContainElements(config.AdminGroupID, config.UserGroupID))
			})
		})

		Describe("Given a request to list groups in a non-member organization", func() {
			It("should be denied with a forbidden response", func() {
				Expect(config.UnauthorisedOrgID).NotTo(BeEmpty(),
					"UNAUTHORISED_ORG_ID must be set by integration fixtures")

				resp, _, err := adminClient.DoRequest(ctx, http.MethodGet,
					api.NewEndpoints().ListGroups(config.UnauthorisedOrgID), nil, http.StatusForbidden)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusForbidden))
			})
		})

		Describe("Given a request to list roles", func() {
			It("should return all roles in the organization with complete metadata", func() {
				roles, err := adminClient.ListRoles(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(roles).NotTo(BeEmpty())

				roleNames := make(map[string]bool)
				for _, role := range roles {
					// RoleRead uses the base ResourceReadMetadata which does not carry
					// OrganizationId; only Id is guaranteed on this resource type.
					Expect(role.Metadata.Id).NotTo(BeEmpty())
					Expect(role.Metadata.Name).NotTo(BeEmpty())

					roleNames[role.Metadata.Name] = true
				}

				Expect(roleNames).To(HaveKey("administrator"))
				Expect(roleNames).To(HaveKey("auditor"))
			})
		})

		Describe("Given a request to list service accounts", func() {
			It("should return all service accounts in the organization with complete metadata", func() {
				serviceAccounts, err := adminClient.ListServiceAccounts(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(serviceAccounts).NotTo(BeEmpty())

				for _, sa := range serviceAccounts {
					Expect(sa.Metadata.Id).NotTo(BeEmpty())
					Expect(sa.Metadata.OrganizationId).To(Equal(config.OrgID))
				}
			})

			Describe("Given TEST_USER_SA_ID is configured", func() {
				BeforeEach(func() {
					Expect(config.UserSAID).NotTo(BeEmpty(),
						"TEST_USER_SA_ID must be set by integration fixtures")
				})

				It("should include service accounts belonging to other principals", func() {
					serviceAccounts, err := adminClient.ListServiceAccounts(ctx, config.OrgID)

					Expect(err).NotTo(HaveOccurred())

					var found bool

					for _, sa := range serviceAccounts {
						if sa.Metadata.Id == config.UserSAID {
							found = true

							break
						}
					}

					Expect(found).To(BeTrue(),
						"admin should see user service account %s in the full list", config.UserSAID)
				})
			})
		})

		Describe("Given a request to list users", func() {
			It("should be permitted to list users", func() {
				api.CreateUserWithCleanup(adminClient, ctx, config, api.NewUserPayload().Build())

				users, err := adminClient.ListUsers(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(users).NotTo(BeEmpty())

				for _, u := range users {
					Expect(u.Metadata.Id).NotTo(BeEmpty())
					Expect(u.Metadata.OrganizationId).To(Equal(config.OrgID))
				}
			})

			Describe("Given TEST_USER_ID is configured", func() {
				It("should include the fixture user in the organization users list", func() {
					Expect(config.UserID).NotTo(BeEmpty(), "TEST_USER_ID must be set by integration fixtures")
					Expect(config.UserSubjectEmail).NotTo(BeEmpty(),
						"TEST_USER_SUBJECT_EMAIL must be set by integration fixtures")

					users, err := adminClient.ListUsers(ctx, config.OrgID)

					Expect(err).NotTo(HaveOccurred())

					var found bool

					for _, user := range users {
						if user.Metadata.Id == config.UserID {
							found = true
							Expect(user.Metadata.OrganizationId).To(Equal(config.OrgID))
							Expect(user.Spec.Subject).To(Equal(config.UserSubjectEmail))

							break
						}
					}

					Expect(found).To(BeTrue(),
						"admin should see fixture user %s in organization %s", config.UserID, config.OrgID)
				})
			})
		})

		Describe("Given a request to list projects", func() {
			It("should be permitted to list all projects in the organization", func() {
				projects, err := adminClient.ListProjects(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(projects).NotTo(BeEmpty())

				var projectIDs []string

				for _, p := range projects {
					projectIDs = append(projectIDs, p.Metadata.Id)
				}

				Expect(projectIDs).To(ContainElement(config.ProjectID))
			})
		})

	})

	Context("When authenticated as a user", func() {
		BeforeEach(func() {
			Expect(userClient).NotTo(BeNil(), "USER_AUTH_TOKEN must be set by integration fixtures")
		})

		Describe("Given a request to list groups", func() {
			It("should be denied with a forbidden response", func() {
				expectUserRequestForbidden(http.MethodGet,
					api.NewEndpoints().ListGroups(config.OrgID), nil)
			})
		})

		Describe("Given a request to list roles", func() {
			It("should be denied with a forbidden response", func() {
				expectUserRequestForbidden(http.MethodGet,
					api.NewEndpoints().ListRoles(config.OrgID), nil)
			})
		})

		Describe("Given a request to list service accounts", func() {
			It("should be denied with a forbidden response", func() {
				expectUserRequestForbidden(http.MethodGet,
					api.NewEndpoints().ListServiceAccounts(config.OrgID), nil)
			})
		})

		Describe("Given a request to create a group", func() {
			It("should be denied with a forbidden response", func() {
				expectUserRequestForbidden(http.MethodPost,
					api.NewEndpoints().ListGroups(config.OrgID),
					api.NewGroupPayload().Build())
			})
		})

		Describe("Given a request to update a group", func() {
			It("should be denied with a forbidden response", func() {
				_, groupID := api.CreateGroupWithCleanup(adminClient, ctx, config,
					api.NewGroupPayload().Build())

				expectUserRequestForbidden(http.MethodPut,
					api.NewEndpoints().GetGroup(config.OrgID, groupID),
					api.NewGroupPayload().Build())
			})
		})

		Describe("Given a request to delete a group", func() {
			It("should be denied with a forbidden response", func() {
				_, groupID := api.CreateGroupWithCleanup(adminClient, ctx, config,
					api.NewGroupPayload().Build())

				expectUserRequestForbidden(http.MethodDelete,
					api.NewEndpoints().GetGroup(config.OrgID, groupID), nil)
			})
		})

		Describe("Given a request to create a service account", func() {
			It("should be denied with a forbidden response", func() {
				expectUserRequestForbidden(http.MethodPost,
					api.NewEndpoints().ListServiceAccounts(config.OrgID),
					api.NewServiceAccountPayload().Build())
			})
		})

		Describe("Given a request to list users", func() {
			It("should be denied with a forbidden response", func() {
				expectUserRequestForbidden(http.MethodGet,
					api.NewEndpoints().ListUsers(config.OrgID), nil)
			})
		})

		Describe("Given a request to set quotas", func() {
			It("should be denied with a forbidden response", func() {
				current, err := adminClient.GetQuotas(ctx, config.OrgID)
				Expect(err).NotTo(HaveOccurred())
				Expect(current.Quotas).NotTo(BeEmpty())

				writes := make(identityopenapi.QuotaWriteList, len(current.Quotas))
				for i, quota := range current.Quotas {
					writes[i] = identityopenapi.QuotaWrite{Kind: quota.Kind, Quantity: quota.Quantity}
				}

				expectUserRequestForbidden(http.MethodPut,
					api.NewEndpoints().GetQuotas(config.OrgID),
					identityopenapi.QuotasWrite{Quotas: writes})
			})
		})

		Describe("Given a request to delete another principal's service account", func() {
			It("should be denied with a forbidden response", func() {
				_, saID := api.CreateServiceAccountWithCleanup(adminClient, ctx, config,
					api.NewServiceAccountPayload().Build())

				expectUserRequestForbidden(http.MethodDelete,
					api.NewEndpoints().GetServiceAccount(config.OrgID, saID), nil)
			})
		})

		Describe("Given a request to update the organization", func() {
			It("should be denied with a forbidden response", func() {
				original, err := client.GetOrganization(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				expectUserRequestForbidden(http.MethodPut,
					api.NewEndpoints().GetOrganization(config.OrgID),
					api.NewOrganizationPayload().FromRead(*original).Build())
			})
		})

		Describe("Given a request to list projects", func() {
			It("should return only the projects the user is a member of", func() {
				projects, err := userClient.ListProjects(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				var projectIDs []string

				for _, p := range projects {
					projectIDs = append(projectIDs, p.Metadata.Id)
				}

				Expect(projectIDs).To(ContainElement(config.ProjectID),
					"user should see the test project they are a member of")
			})
		})

		Describe("Given a request to get a project by ID", func() {
			It("should return the project when the user is a member", func() {
				project, err := userClient.GetProject(ctx, config.OrgID, config.ProjectID)

				Expect(err).NotTo(HaveOccurred())
				Expect(project.Metadata.Id).To(Equal(config.ProjectID))
			})

			It("should be denied access to a project the user is not a member of", func() {
				// Create a project with no group assignments so the user has no membership.
				_, projectID := api.CreateProjectWithCleanup(adminClient, ctx, config,
					api.NewProjectPayload().Build())

				// Wait for provisioning so the denial is RBAC, not a provisioning race.
				api.WaitForProjectProvisioned(adminClient, ctx, config, projectID)

				resp, _, err := userClient.DoRequest(ctx, http.MethodGet,
					api.NewEndpoints().GetProject(config.OrgID, projectID), nil, http.StatusForbidden)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusForbidden))
			})

			It("should not include a project the user is not a member of in the list", func() {
				_, projectID := api.CreateProjectWithCleanup(adminClient, ctx, config,
					api.NewProjectPayload().Build())

				api.WaitForProjectProvisioned(adminClient, ctx, config, projectID)

				projects, err := userClient.ListProjects(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				var projectIDs []string

				for _, p := range projects {
					projectIDs = append(projectIDs, p.Metadata.Id)
				}

				Expect(projectIDs).NotTo(ContainElement(projectID),
					"user should not see a project they are not a member of")
			})
		})

		Describe("Given a request to create an OAuth2 provider", func() {
			It("should be denied with a forbidden response", func() {
				expectUserRequestForbidden(http.MethodPost,
					api.NewEndpoints().ListOauth2Providers(config.OrgID),
					api.NewOauth2ProviderPayload().Build())
			})
		})

		Describe("Given a request to delete an OAuth2 provider", func() {
			It("should be denied with a forbidden response", func() {
				_, providerID := api.CreateOauth2ProviderWithCleanup(adminClient, ctx, config,
					api.NewOauth2ProviderPayload().Build())

				expectUserRequestForbidden(http.MethodDelete,
					api.NewEndpoints().GetOauth2Provider(config.OrgID, providerID), nil)
			})
		})
	})

	Context("When authenticated as a service account", func() {
		BeforeEach(func() {
			Expect(serviceAccountClient).NotTo(BeNil(),
				"SERVICE_ACCOUNT_TOKEN must be set by integration fixtures")
			Expect(config.UserSAID).NotTo(BeEmpty(), "TEST_USER_SA_ID must be set by integration fixtures")
		})

		Describe("Given a request to list service accounts", func() {
			It("should return only the requesting service account", func() {
				serviceAccounts, err := serviceAccountClient.ListServiceAccounts(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(serviceAccounts).To(HaveLen(1))
				Expect(serviceAccounts[0].Metadata.Id).To(Equal(config.UserSAID))
				Expect(serviceAccounts[0].Metadata.OrganizationId).To(Equal(config.OrgID))
			})
		})
	})
})
