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
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/test/api"
)

const (
	projectAdministratorRole = "project-administrator"
	projectAdministratorName = "project administrator"
)

func newBearerClient(base *api.TestConfig, token string) *api.APIClient {
	cfg := *base
	cfg.AuthToken = token

	return api.NewAPIClientWithConfig(&cfg)
}

func projectWrite(name string, groupIDs []string) identityopenapi.ProjectWrite {
	return api.NewProjectPayload().WithName(name).WithGroupIDs(groupIDs).Build()
}

func waitForEveryReplicaToExpireCachedACLs() {
	time.Sleep(config.ACLCacheTimeout + time.Second)
}

func eventuallySucceeds(check func(Gomega)) {
	GinkgoHelper()

	Eventually(check).WithTimeout(2*config.ACLCacheTimeout + 30*time.Second).WithPolling(2 * time.Second).Should(Succeed())
}

func expectProjectReadable(c *api.APIClient, projectID string) *identityopenapi.ProjectRead {
	GinkgoHelper()

	var project *identityopenapi.ProjectRead

	eventuallySucceeds(func(g Gomega) {
		var err error

		project, err = c.GetProject(ctx, config.OrgID, projectID)
		g.Expect(err).NotTo(HaveOccurred())
	})

	return project
}

func expectProjectIntact(projectID string) {
	GinkgoHelper()

	project, err := adminClient.GetProject(ctx, config.OrgID, projectID)
	Expect(err).NotTo(HaveOccurred(), "project %s must still exist", projectID)
	Expect(project.Metadata.DeletionTime).To(BeNil(), "project %s must not be marked for deletion", projectID)
	Expect(project.Metadata.ProvisioningStatus).NotTo(Equal(coreopenapi.ResourceProvisioningStatusDeprovisioning))
}

func expectStoredGroups(projectID string, want []string) {
	GinkgoHelper()

	eventuallySucceeds(func(g Gomega) {
		project, err := adminClient.GetProject(ctx, config.OrgID, projectID)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(project.Spec.GroupIDs).To(ConsistOf(want),
			"the stored group links of project %s differ", projectID)
	})
}

func updateProject(c *api.APIClient, projectID string, payload identityopenapi.ProjectWrite) *identityopenapi.PutApiV1OrganizationsOrganizationIDProjectsProjectIDResponse {
	GinkgoHelper()

	var response *identityopenapi.PutApiV1OrganizationsOrganizationIDProjectsProjectIDResponse

	eventuallySucceeds(func(g Gomega) {
		var err error

		response, err = c.UpdateProjectWithResponse(ctx, config.OrgID, projectID, payload)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(response.StatusCode()).NotTo(Equal(http.StatusConflict),
			"the controller is still reconciling project %s", projectID)
	})

	return response
}

func expectProjectUpdated(c *api.APIClient, projectID string, payload identityopenapi.ProjectWrite) {
	GinkgoHelper()

	response := updateProject(c, projectID, payload)
	Expect(response.StatusCode()).To(Equal(http.StatusOK), "update of project %s failed: %s", projectID, response.Body)
}

func expectLinkChangeRefused(c *api.APIClient, projectID string, payload identityopenapi.ProjectWrite) {
	GinkgoHelper()

	response, err := c.UpdateProjectWithResponse(ctx, config.OrgID, projectID, payload)
	Expect(err).NotTo(HaveOccurred())
	Expect(response.StatusCode()).To(Equal(http.StatusForbidden), "response: %s", response.Body)
	Expect(response.JSON403).NotTo(BeNil(), "a refusal must come back as a typed forbidden response")
	Expect(response.JSON403.Error).To(Equal(coreopenapi.Forbidden))
	Expect(response.JSON403.ErrorDescription).To(ContainSubstring("group links"),
		"the group link guard must be the one that refused, not the project role check")
}

var _ = Describe("Project Administrator Role", Ordered, ContinueOnFailure, func() {
	var (
		linkedClient   *api.APIClient
		unlinkedClient *api.APIClient

		linkedGroup, spareGroup, extraGroup                 string
		linkedProject, unlinkedProject, adminChangedProject string
		linkedName, unlinkedName, adminChangedName          string
		baselineGroups                                      []string
	)

	// The group sets that a link change can produce, as functions because the IDs exist only after BeforeAll.
	addGroup := func() []string { return []string{linkedGroup, spareGroup, extraGroup} }
	removeGroup := func() []string { return []string{linkedGroup} }
	clearGroups := func() []string { return []string{} }

	BeforeAll(func() {
		Expect(config.AdminToken).NotTo(BeEmpty(), "ADMIN_AUTH_TOKEN must be set by integration fixtures")

		roles, err := adminClient.ListRoles(ctx, config.OrgID)
		Expect(err).NotTo(HaveOccurred())

		roleIndex := slices.IndexFunc(roles, func(role identityopenapi.RoleRead) bool {
			return role.Metadata.Name == projectAdministratorRole
		})
		Expect(roleIndex).To(BeNumerically(">=", 0), "the chart must install the %s role", projectAdministratorRole)
		Expect(roles[roleIndex].Grantable).To(BeTrue(),
			"an organization administrator must be able to grant the %s role", projectAdministratorRole)

		holder := []string{roles[roleIndex].Metadata.Id}

		_, linkedGroup = api.CreateGroupWithCleanup(adminClient, ctx, config, api.NewGroupPayload().WithRoleIDs(holder).Build())
		_, unlinkedGroup := api.CreateGroupWithCleanup(adminClient, ctx, config, api.NewGroupPayload().WithRoleIDs(holder).Build())
		_, spareGroup = api.CreateGroupWithCleanup(adminClient, ctx, config, api.NewGroupPayload().Build())
		_, extraGroup = api.CreateGroupWithCleanup(adminClient, ctx, config, api.NewGroupPayload().Build())

		clientIn := func(groupID string) *api.APIClient {
			created, _ := api.CreateServiceAccountWithCleanup(adminClient, ctx, config,
				api.NewServiceAccountPayload().WithGroupIDs([]string{groupID}).Build())
			Expect(created.Status.AccessToken).NotTo(BeNil(), "the create response must carry the access token")

			return newBearerClient(config, *created.Status.AccessToken)
		}

		linkedClient = clientIn(linkedGroup)
		unlinkedClient = clientIn(unlinkedGroup)

		baselineGroups = []string{linkedGroup, spareGroup}

		linkedPayload := api.NewProjectPayload().WithGroupIDs(baselineGroups).Build()
		unlinkedPayload := api.NewProjectPayload().Build()
		adminChangedPayload := api.NewProjectPayload().WithGroupIDs([]string{spareGroup}).Build()

		linkedName, unlinkedName, adminChangedName = linkedPayload.Metadata.Name, unlinkedPayload.Metadata.Name, adminChangedPayload.Metadata.Name

		_, linkedProject = api.CreateProjectWithCleanup(adminClient, ctx, config, linkedPayload)
		_, unlinkedProject = api.CreateProjectWithCleanup(adminClient, ctx, config, unlinkedPayload)
		_, adminChangedProject = api.CreateProjectWithCleanup(adminClient, ctx, config, adminChangedPayload)

		for _, projectID := range []string{linkedProject, unlinkedProject, adminChangedProject} {
			api.WaitForProjectProvisioned(adminClient, ctx, config, projectID)
		}

		api.WaitForProjectInACL(linkedClient, ctx, config, linkedProject)

		waitForEveryReplicaToExpireCachedACLs()
	})

	Context("When a group that holds the role is linked to one project only", func() {
		Describe("Given a second project that no group holding the role links to", func() {
			It("should list the linked project with read and update and not list the unlinked project", func() {
				var acl *identityopenapi.Acl

				eventuallySucceeds(func(g Gomega) {
					var err error

					acl, err = linkedClient.GetOrganizationACL(ctx, config.OrgID)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(acl.Projects).NotTo(BeNil(), "the ACL lists no project yet")
					g.Expect(*acl.Projects).To(ContainElement(HaveField("Id", linkedProject)))
				})

				Expect(*acl.Projects).To(ContainElement(SatisfyAll(
					HaveField("Id", linkedProject),
					HaveField("Endpoints", ContainElement(SatisfyAll(
						HaveField("Name", "identity:projects"),
						HaveField("Operations", ConsistOf(identityopenapi.Read, identityopenapi.Update)),
					))),
				)))
				Expect(*acl.Projects).NotTo(ContainElement(HaveField("Id", unlinkedProject)),
					"a project that no linked group reaches must not be in the ACL")

				Expect(acl.Organization).NotTo(BeNil())
				Expect(acl.Organization.Endpoints).NotTo(BeNil())
				Expect(*acl.Organization.Endpoints).NotTo(ContainElement(HaveField("Name", "identity:projects")),
					"the role must hold no organization level project permission")
			})

			It("should allow reading the linked project", func() {
				project := expectProjectReadable(linkedClient, linkedProject)

				Expect(project.Metadata.Id).To(Equal(linkedProject))
				Expect(project.Metadata.OrganizationId).To(Equal(config.OrgID))
			})

			It("should refuse reading, updating and deleting the unlinked project while an organization administrator can read it", func() {
				project, err := adminClient.GetProject(ctx, config.OrgID, unlinkedProject)
				Expect(err).NotTo(HaveOccurred())
				Expect(project.Metadata.Id).To(Equal(unlinkedProject))

				path := api.NewEndpoints().GetProject(config.OrgID, unlinkedProject)

				expectRequestForbidden(linkedClient, projectAdministratorName, http.MethodGet, path, nil)
				expectRequestForbidden(linkedClient, projectAdministratorName, http.MethodPut, path, projectWrite(unlinkedName, []string{}))
				expectRequestForbidden(linkedClient, projectAdministratorName, http.MethodDelete, path, nil)

				expectProjectIntact(unlinkedProject)
			})
		})
	})

	Context("When a group that holds the role is linked to no project", func() {
		Describe("Given the service account in that group", func() {
			It("should list no project in the ACL", func() {
				var acl *identityopenapi.Acl

				eventuallySucceeds(func(g Gomega) {
					var err error

					acl, err = unlinkedClient.GetOrganizationACL(ctx, config.OrgID)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(acl.Organization).NotTo(BeNil(), "the ACL is not loaded yet")
					g.Expect(acl.Organization.Endpoints).NotTo(BeNil())
					g.Expect(*acl.Organization.Endpoints).To(ContainElement(HaveField("Name", "region:regions")),
						"the role must still grant its organization level reads")
				})

				if acl.Projects != nil {
					Expect(*acl.Projects).To(BeEmpty(), "a group that no project links to must grant nothing at project scope")
				}
			})

			It("should refuse reading the linked and the unlinked project while the linked service account can read the linked project", func() {
				expectProjectReadable(linkedClient, linkedProject)

				expectRequestForbidden(unlinkedClient, projectAdministratorName, http.MethodGet,
					api.NewEndpoints().GetProject(config.OrgID, linkedProject), nil)
				expectRequestForbidden(unlinkedClient, projectAdministratorName, http.MethodGet,
					api.NewEndpoints().GetProject(config.OrgID, unlinkedProject), nil)
			})
		})
	})

	Context("When a project administrator changes the linked project without changing its group links", func() {
		Describe("Given an update that carries the same group set", func() {
			It("should store the new name and keep the group links", func() {
				renamed := linkedName + "-renamed"

				expectProjectUpdated(linkedClient, linkedProject, projectWrite(renamed, baselineGroups))

				eventuallySucceeds(func(g Gomega) {
					project, err := adminClient.GetProject(ctx, config.OrgID, linkedProject)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(project.Metadata.Name).To(Equal(renamed))
				})

				expectStoredGroups(linkedProject, baselineGroups)
			})

			DescribeTable("should accept the update when the group IDs come",
				func(groups func() []string) {
					expectProjectUpdated(linkedClient, linkedProject, projectWrite(linkedName, groups()))

					expectStoredGroups(linkedProject, baselineGroups)
				},
				Entry("in a different order", func() []string { return []string{spareGroup, linkedGroup} }),
				Entry("with a repeated ID", func() []string { return []string{linkedGroup, spareGroup, linkedGroup} }),
			)
		})
	})

	Context("When a project administrator changes the group links of the linked project", func() {
		Describe("Given a service account that can read the linked project", func() {
			BeforeEach(func() {
				expectProjectReadable(linkedClient, linkedProject)
			})

			DescribeTable("should refuse changing the group links by",
				func(groups func() []string) {
					expectLinkChangeRefused(linkedClient, linkedProject, projectWrite(linkedName, groups()))

					expectStoredGroups(linkedProject, baselineGroups)
				},
				Entry("adding a group", addGroup),
				Entry("removing a group", removeGroup),
				Entry("clearing all groups", clearGroups),
				Entry("naming a group that does not exist", func() []string {
					return append(slices.Clone(baselineGroups), uuid.NewString())
				}),
			)
		})
	})

	Context("When an organization administrator changes the group links of a project that only the administrator changes", func() {
		Describe("Given the same group sets that the project administrator was refused", func() {
			DescribeTable("should accept changing the group links by",
				func(groups func() []string) {
					expectProjectUpdated(adminClient, adminChangedProject, projectWrite(adminChangedName, groups()))

					expectStoredGroups(adminChangedProject, groups())
				},
				Entry("adding a group", addGroup),
				Entry("removing a group", removeGroup),
				Entry("clearing all groups", clearGroups),
			)

			It("should still return a bad request for a group that does not exist", func() {
				before, err := adminClient.GetProject(ctx, config.OrgID, adminChangedProject)
				Expect(err).NotTo(HaveOccurred())

				unknown := uuid.NewString()

				response := updateProject(adminClient, adminChangedProject, projectWrite(adminChangedName, []string{unknown}))

				Expect(response.StatusCode()).To(Equal(http.StatusBadRequest), "response: %s", response.Body)
				Expect(response.JSON400).NotTo(BeNil())
				Expect(response.JSON400.Error).To(Equal(coreopenapi.InvalidRequest))
				Expect(response.JSON400.ErrorDescription).To(ContainSubstring(unknown),
					"the error must name the group that does not exist")

				expectStoredGroups(adminChangedProject, before.Spec.GroupIDs)
			})
		})
	})

	Context("When a project administrator calls what the role does not grant", func() {
		Describe("Given a service account that can read the linked project", func() {
			BeforeEach(func() {
				expectProjectReadable(linkedClient, linkedProject)
			})

			It("should refuse creating a project while an organization administrator can", func() {
				api.CreateProjectWithCleanup(adminClient, ctx, config, api.NewProjectPayload().Build())

				expectRequestForbidden(linkedClient, projectAdministratorName, http.MethodPost,
					api.NewEndpoints().ListProjects(config.OrgID), api.NewProjectPayload().Build())
			})

			It("should refuse deleting the linked project and leave it in place", func() {
				expectRequestForbidden(linkedClient, projectAdministratorName, http.MethodDelete,
					api.NewEndpoints().GetProject(config.OrgID, linkedProject), nil)

				expectProjectIntact(linkedProject)
			})

			It("should refuse creating a group while an organization administrator can", func() {
				api.CreateGroupWithCleanup(adminClient, ctx, config, api.NewGroupPayload().Build())

				expectRequestForbidden(linkedClient, projectAdministratorName, http.MethodPost,
					api.NewEndpoints().ListGroups(config.OrgID), api.NewGroupPayload().Build())
			})

			It("should refuse updating a group while an organization administrator can", func() {
				_, groupID := api.CreateGroupWithCleanup(adminClient, ctx, config, api.NewGroupPayload().Build())

				Expect(adminClient.UpdateGroup(ctx, config.OrgID, groupID, api.NewGroupPayload().Build())).To(Succeed())

				expectRequestForbidden(linkedClient, projectAdministratorName, http.MethodPut,
					api.NewEndpoints().GetGroup(config.OrgID, groupID), api.NewGroupPayload().Build())
			})

			It("should refuse creating a service account while an organization administrator can", func() {
				api.CreateServiceAccountWithCleanup(adminClient, ctx, config, api.NewServiceAccountPayload().Build())

				expectRequestForbidden(linkedClient, projectAdministratorName, http.MethodPost,
					api.NewEndpoints().ListServiceAccounts(config.OrgID), api.NewServiceAccountPayload().Build())
			})

			It("should refuse updating a service account while an organization administrator can", func() {
				_, serviceAccountID := api.CreateServiceAccountWithCleanup(adminClient, ctx, config,
					api.NewServiceAccountPayload().Build())

				_, err := adminClient.UpdateServiceAccount(ctx, config.OrgID, serviceAccountID,
					api.NewServiceAccountPayload().Build())
				Expect(err).NotTo(HaveOccurred())

				expectRequestForbidden(linkedClient, projectAdministratorName, http.MethodPut,
					api.NewEndpoints().GetServiceAccount(config.OrgID, serviceAccountID),
					api.NewServiceAccountPayload().Build())
			})

			It("should refuse creating a user while an organization administrator can", func() {
				api.CreateUserWithCleanup(adminClient, ctx, config,
					api.NewUserPayload(api.UserSubject(config, "project-administrator-allowed")).Build())

				expectRequestForbidden(linkedClient, projectAdministratorName, http.MethodPost,
					api.NewEndpoints().ListUsers(config.OrgID),
					api.NewUserPayload(api.UserSubject(config, "project-administrator-refused")).Build())
			})

			It("should refuse updating a user while an organization administrator can", func() {
				payload := api.NewUserPayload(api.UserSubject(config, "project-administrator-update")).Build()
				_, userID := api.CreateUserWithCleanup(adminClient, ctx, config, payload)

				updated, err := adminClient.UpdateUser(ctx, config.OrgID, userID, payload)
				Expect(err).NotTo(HaveOccurred())
				Expect(updated.Metadata.Id).To(Equal(userID))

				expectRequestForbidden(linkedClient, projectAdministratorName, http.MethodPut,
					api.NewEndpoints().GetUser(config.OrgID, userID), payload)
			})
		})
	})
})
