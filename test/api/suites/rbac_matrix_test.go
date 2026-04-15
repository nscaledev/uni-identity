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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/test/api"
)

var _ = Describe("RBAC Enforcement", func() {
	BeforeEach(func() {
		if adminClient == nil || userClient == nil {
			Skip("ADMIN_AUTH_TOKEN and USER_AUTH_TOKEN are required for RBAC enforcement testing")
		}
	})

	Context("When authenticated as an administrator", func() {
		Describe("Given a request to list groups", func() {
			It("should return all groups in the organization with complete metadata", func() {
				groups, err := adminClient.ListGroups(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(groups).NotTo(BeEmpty())

				for _, group := range groups {
					Expect(group.Metadata.Id).NotTo(BeEmpty())
					Expect(group.Metadata.OrganizationId).To(Equal(config.OrgID))
				}
			})
		})

		Describe("Given a request to list roles", func() {
			It("should return all roles in the organization with complete metadata", func() {
				roles, err := adminClient.ListRoles(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(roles).NotTo(BeEmpty())

				for _, role := range roles {
					// RoleRead uses the base ResourceReadMetadata which does not carry
					// OrganizationId; only Id is guaranteed on this resource type.
					Expect(role.Metadata.Id).NotTo(BeEmpty())
				}
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
					if config.UserSAID == "" {
						Skip("TEST_USER_SA_ID is not configured")
					}
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
			if userClient == nil {
				Skip("USER_AUTH_TOKEN is required for user RBAC tests")
			}
		})

		// For denial tests, an error on any non-2xx response is sufficient to verify
		// that access was denied without needing to inspect the response body.

		Describe("Given a request to list groups", func() {
			It("should be denied with a forbidden response", func() {
				_, err := userClient.ListGroups(ctx, config.OrgID)
				Expect(err).To(HaveOccurred())
			})
		})

		Describe("Given a request to list roles", func() {
			It("should be denied with a forbidden response", func() {
				_, err := userClient.ListRoles(ctx, config.OrgID)
				Expect(err).To(HaveOccurred())
			})
		})

		Describe("Given a request to list service accounts", func() {
			It("should return only the requesting principal's own service account", func() {
				serviceAccounts, err := userClient.ListServiceAccounts(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(serviceAccounts).To(HaveLen(1))
				Expect(serviceAccounts[0].Metadata.Id).To(Equal(config.UserSAID))
				Expect(serviceAccounts[0].Metadata.OrganizationId).To(Equal(config.OrgID))
			})
		})

		Describe("Given a request to create a group", func() {
			It("should be denied with a forbidden response", func() {
				_, err := userClient.CreateGroup(ctx, config.OrgID,
					api.NewGroupPayload().Build())

				Expect(err).To(HaveOccurred())
			})
		})

		Describe("Given a request to update a group", func() {
			It("should be denied with a forbidden response", func() {
				_, groupID := api.CreateGroupWithCleanup(adminClient, ctx, config,
					api.NewGroupPayload().Build())

				err := userClient.UpdateGroup(ctx, config.OrgID, groupID,
					api.NewGroupPayload().Build())

				Expect(err).To(HaveOccurred())
			})
		})

		Describe("Given a request to delete a group", func() {
			It("should be denied with a forbidden response", func() {
				_, groupID := api.CreateGroupWithCleanup(adminClient, ctx, config,
					api.NewGroupPayload().Build())

				err := userClient.DeleteGroup(ctx, config.OrgID, groupID)

				Expect(err).To(HaveOccurred())
			})
		})

		Describe("Given a request to create a service account", func() {
			It("should be denied with a forbidden response", func() {
				_, err := userClient.CreateServiceAccount(ctx, config.OrgID,
					api.NewServiceAccountPayload().Build())

				Expect(err).To(HaveOccurred())
			})
		})

		Describe("Given a request to list users", func() {
			It("should be denied with a forbidden response", func() {
				_, err := userClient.ListUsers(ctx, config.OrgID)

				Expect(err).To(HaveOccurred())
			})
		})

		Describe("Given a request to set quotas", func() {
			It("should be denied with a forbidden response", func() {
				_, err := userClient.SetQuotas(ctx, config.OrgID,
					identityopenapi.QuotasWrite{})

				Expect(err).To(HaveOccurred())
			})
		})

		Describe("Given a request to delete another principal's service account", func() {
			It("should be denied with a forbidden response", func() {
				_, saID := api.CreateServiceAccountWithCleanup(adminClient, ctx, config,
					api.NewServiceAccountPayload().Build())

				err := userClient.DeleteServiceAccount(ctx, config.OrgID, saID)

				Expect(err).To(HaveOccurred())
			})
		})

		Describe("Given a request to update the organization", func() {
			It("should be denied with a forbidden response", func() {
				original, err := client.GetOrganization(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				err = userClient.UpdateOrganization(ctx, config.OrgID,
					api.NewOrganizationPayload().FromRead(*original).Build())

				Expect(err).To(HaveOccurred())
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

				// Wait for provisioning so a 404 is a real denial, not a race.
				api.WaitForProjectProvisioned(adminClient, ctx, config, projectID)

				_, err := userClient.GetProject(ctx, config.OrgID, projectID)

				Expect(err).To(HaveOccurred())
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
				_, err := userClient.CreateOauth2Provider(ctx, config.OrgID,
					api.NewOauth2ProviderPayload().Build())

				Expect(err).To(HaveOccurred())
			})
		})

		Describe("Given a request to delete an OAuth2 provider", func() {
			It("should be denied with a forbidden response", func() {
				_, providerID := api.CreateOauth2ProviderWithCleanup(adminClient, ctx, config,
					api.NewOauth2ProviderPayload().Build())

				err := userClient.DeleteOauth2Provider(ctx, config.OrgID, providerID)

				Expect(err).To(HaveOccurred())
			})
		})
	})
})
