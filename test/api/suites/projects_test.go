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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	"github.com/unikorn-cloud/identity/test/api"
)

var _ = Describe("Project Management", func() {
	Context("When creating projects", func() {
		Describe("Given valid project data", func() {
			It("should create a project and return complete metadata", func() {
				payload := api.NewProjectPayload().Build()
				created, projectID := api.CreateProjectWithCleanup(client, ctx, config, payload)

				Expect(projectID).NotTo(BeEmpty())
				Expect(created.Metadata.Id).To(Equal(projectID))
				Expect(created.Metadata.Name).To(Equal(payload.Metadata.Name))
				Expect(created.Metadata.OrganizationId).To(Equal(config.OrgID))
				// Status is a transient initial value on create — just assert it is present.
				Expect(created.Metadata.ProvisioningStatus).NotTo(BeEmpty())

				GinkgoWriter.Printf("Created project %s (initial status: %s)\n",
					projectID, created.Metadata.ProvisioningStatus)
			})

			It("should create a project and find it in the organization list", func() {
				payload := api.NewProjectPayload().Build()
				created, projectID := api.CreateProjectWithCleanup(client, ctx, config, payload)

				api.WaitForProjectProvisioned(client, ctx, config, projectID)

				projects, err := client.ListProjects(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				var found bool

				for _, p := range projects {
					if p.Metadata.Id == projectID {
						found = true
						Expect(p.Metadata.Name).To(Equal(created.Metadata.Name))

						break
					}
				}

				Expect(found).To(BeTrue(), "Created project %s should appear in list", projectID)
			})

			It("should create a project and retrieve it by ID", func() {
				payload := api.NewProjectPayload().Build()
				created, projectID := api.CreateProjectWithCleanup(client, ctx, config, payload)

				api.WaitForProjectProvisioned(client, ctx, config, projectID)

				retrieved, err := client.GetProject(ctx, config.OrgID, projectID)

				Expect(err).NotTo(HaveOccurred())
				Expect(retrieved.Metadata.Id).To(Equal(created.Metadata.Id))
				Expect(retrieved.Metadata.Name).To(Equal(created.Metadata.Name))
			})

			It("should create a project with group associations", func() {
				_, groupID := api.CreateGroupWithCleanup(client, ctx, config,
					api.NewGroupPayload().Build())

				payload := api.NewProjectPayload().
					WithGroupIDs([]string{groupID}).
					Build()
				_, projectID := api.CreateProjectWithCleanup(client, ctx, config, payload)

				api.WaitForProjectProvisioned(client, ctx, config, projectID)

				retrieved, err := client.GetProject(ctx, config.OrgID, projectID)

				Expect(err).NotTo(HaveOccurred())
				Expect(retrieved.Spec.GroupIDs).To(ContainElement(groupID),
					"Project should have the assigned group")
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return error", func() {
				payload := api.NewProjectPayload().Build()

				_, err := client.CreateProject(ctx, "invalid-org-id", payload)

				Expect(err).To(HaveOccurred())
			})
		})
	})

	Context("When updating projects", func() {
		Describe("Given existing project", func() {
			It("should update project name successfully", func() {
				payload := api.NewProjectPayload().Build()
				_, projectID := api.CreateProjectWithCleanup(client, ctx, config, payload)

				api.WaitForProjectProvisioned(client, ctx, config, projectID)

				updatedPayload := api.NewProjectPayload().
					WithName(payload.Metadata.Name + "-updated").
					Build()

				err := client.UpdateProject(ctx, config.OrgID, projectID, updatedPayload)

				Expect(err).NotTo(HaveOccurred())

				api.WaitForProjectProvisioned(client, ctx, config, projectID)

				retrieved, err := client.GetProject(ctx, config.OrgID, projectID)

				Expect(err).NotTo(HaveOccurred())
				Expect(retrieved.Metadata.Name).To(Equal(updatedPayload.Metadata.Name))
				Expect(retrieved.Metadata.Name).NotTo(Equal(payload.Metadata.Name))
			})

			It("should update project group associations", func() {
				_, groupID := api.CreateGroupWithCleanup(client, ctx, config,
					api.NewGroupPayload().Build())

				payload := api.NewProjectPayload().Build()
				_, projectID := api.CreateProjectWithCleanup(client, ctx, config, payload)

				api.WaitForProjectProvisioned(client, ctx, config, projectID)

				updatedPayload := api.NewProjectPayload().
					WithGroupIDs([]string{groupID}).
					Build()

				err := client.UpdateProject(ctx, config.OrgID, projectID, updatedPayload)

				Expect(err).NotTo(HaveOccurred())

				api.WaitForProjectProvisioned(client, ctx, config, projectID)

				retrieved, err := client.GetProject(ctx, config.OrgID, projectID)

				Expect(err).NotTo(HaveOccurred())
				Expect(retrieved.Spec.GroupIDs).To(ContainElement(groupID))
			})

			It("should clear project group associations", func() {
				_, groupID := api.CreateGroupWithCleanup(client, ctx, config,
					api.NewGroupPayload().Build())

				payload := api.NewProjectPayload().
					WithGroupIDs([]string{groupID}).
					Build()
				_, projectID := api.CreateProjectWithCleanup(client, ctx, config, payload)

				api.WaitForProjectProvisioned(client, ctx, config, projectID)

				clearedPayload := api.NewProjectPayload().
					WithGroupIDs([]string{}).
					Build()

				err := client.UpdateProject(ctx, config.OrgID, projectID, clearedPayload)

				Expect(err).NotTo(HaveOccurred())

				api.WaitForProjectProvisioned(client, ctx, config, projectID)

				retrieved, err := client.GetProject(ctx, config.OrgID, projectID)

				Expect(err).NotTo(HaveOccurred())
				Expect(retrieved.Spec.GroupIDs).To(BeEmpty())
			})
		})

		Describe("Given invalid project ID", func() {
			It("should return not-found error", func() {
				payload := api.NewProjectPayload().Build()

				err := client.UpdateProject(ctx, config.OrgID, "00000000-0000-0000-0000-000000000000", payload)

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return error", func() {
				payload := api.NewProjectPayload().Build()

				err := client.UpdateProject(ctx, "invalid-org-id", "00000000-0000-0000-0000-000000000000", payload)

				Expect(err).To(HaveOccurred())
			})
		})
	})

	Context("When deleting projects", func() {
		Describe("Given existing project", func() {
			It("should delete project and verify via polling", func() {
				payload := api.NewProjectPayload().Build()
				_, projectID := api.CreateProjectWithCleanup(client, ctx, config, payload)

				api.WaitForProjectProvisioned(client, ctx, config, projectID)

				err := client.DeleteProject(ctx, config.OrgID, projectID)

				Expect(err).NotTo(HaveOccurred())

				Eventually(func() bool {
					_, err := client.GetProject(ctx, config.OrgID, projectID)
					return errors.Is(err, coreclient.ErrResourceNotFound)
				}).WithTimeout(config.TestTimeout).WithPolling(2*time.Second).Should(BeTrue(),
					"project %s should be deleted", projectID)

				GinkgoWriter.Printf("Verified project %s is deleted\n", projectID)
			})
		})

		Describe("Given invalid project ID", func() {
			It("should return not-found error", func() {
				err := client.DeleteProject(ctx, config.OrgID, "00000000-0000-0000-0000-000000000000")

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return error", func() {
				err := client.DeleteProject(ctx, "invalid-org-id", "00000000-0000-0000-0000-000000000000")

				Expect(err).To(HaveOccurred())
			})
		})
	})
})

var _ = Describe("Project Discovery", func() {
	Context("When listing projects", func() {
		Describe("Given valid organization", func() {
			It("should return all projects in the organization", func() {
				projects, err := client.ListProjects(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(projects).NotTo(BeEmpty())

				projectIDs := make([]string, len(projects))
				for i, project := range projects {
					Expect(project.Metadata).NotTo(BeNil())
					Expect(project.Metadata.Id).NotTo(BeEmpty())
					Expect(project.Metadata.Name).NotTo(BeEmpty())
					projectIDs[i] = project.Metadata.Id
				}

				Expect(projectIDs).To(ContainElement(config.ProjectID), "Expected project ID %s to be present in the list", config.ProjectID)
				GinkgoWriter.Printf("Found %d projects in organization %s (including test project: %s)\n", len(projects), config.OrgID, config.ProjectID)
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return error for non-existent organization", func() {
				_, err := client.ListProjects(ctx, "invalid-org-id")

				Expect(err).To(HaveOccurred())
				GinkgoWriter.Printf("Expected error for invalid organization ID: %v\n", err)
			})
		})
	})

	Context("When getting project details", func() {
		Describe("Given valid project ID", func() {
			It("should return project details", func() {
				project, err := client.GetProject(ctx, config.OrgID, config.ProjectID)

				Expect(err).NotTo(HaveOccurred())
				Expect(project).NotTo(BeNil())
				Expect(project.Metadata).NotTo(BeNil())
				Expect(project.Metadata.Id).To(Equal(config.ProjectID))
				Expect(project.Metadata.Name).NotTo(BeEmpty())

				GinkgoWriter.Printf("Retrieved project: %s (ID: %s)\n", project.Metadata.Name, project.Metadata.Id)
			})
		})

		Describe("Given invalid project ID", func() {
			It("should return not found error", func() {
				_, err := client.GetProject(ctx, config.OrgID, "invalid-project-id")

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
				GinkgoWriter.Printf("Expected error for invalid project ID: %v\n", err)
			})
		})
	})
})
