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

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	"github.com/unikorn-cloud/identity/test/api"
)

var _ = Describe("Group Management", func() {
	Context("When creating groups", func() {
		Describe("Given valid group data", func() {
			It("should create a new group with complete metadata", func() {
				payload := api.NewGroupPayload().BuildTyped()
				group, groupID := api.CreateGroupWithCleanup(client, ctx, config, payload)

				Expect(groupID).NotTo(BeEmpty(), "Group ID should be returned")
				Expect(group.Metadata).NotTo(BeNil())
				Expect(group.Metadata.Id).To(Equal(groupID))
				Expect(group.Metadata.Name).To(Equal(payload.Metadata.Name))
				Expect(group.Metadata.OrganizationId).To(Equal(config.OrgID))

				Expect(group.Spec).NotTo(BeNil())
				Expect(group.Spec.RoleIDs).To(Equal(payload.Spec.RoleIDs))
				Expect(group.Spec.ServiceAccountIDs).To(Equal(payload.Spec.ServiceAccountIDs))

				Expect(group.Metadata.ProvisioningStatus).NotTo(BeEmpty())
				Expect(group.Metadata.ProvisioningStatus).To(BeElementOf(
					coreopenapi.ResourceProvisioningStatusProvisioning,
					coreopenapi.ResourceProvisioningStatusProvisioned,
					coreopenapi.ResourceProvisioningStatusDeprovisioning,
					coreopenapi.ResourceProvisioningStatusError))

				Expect(group.Metadata.HealthStatus).NotTo(BeEmpty())
				Expect(group.Metadata.HealthStatus).To(BeElementOf(
					coreopenapi.ResourceHealthStatusHealthy,
					coreopenapi.ResourceHealthStatusDegraded,
					coreopenapi.ResourceHealthStatusError))

				GinkgoWriter.Printf("Created group: %s (ID: %s)\n", group.Metadata.Name, groupID)
			})

			It("should create a group and retrieve it by ID", func() {
				payload := api.NewGroupPayload().BuildTyped()
				createdGroup, groupID := api.CreateGroupWithCleanup(client, ctx, config, payload)

				retrievedGroup, err := client.GetGroup(ctx, config.OrgID, groupID)

				Expect(err).NotTo(HaveOccurred())
				Expect(retrievedGroup).NotTo(BeNil())
				Expect(retrievedGroup.Metadata.Id).To(Equal(createdGroup.Metadata.Id))
				Expect(retrievedGroup.Metadata.Name).To(Equal(createdGroup.Metadata.Name))
				Expect(retrievedGroup.Spec.RoleIDs).To(Equal(createdGroup.Spec.RoleIDs))

				GinkgoWriter.Printf("Retrieved group by ID: %s\n", groupID)
			})

			It("should create a group and find it in the organization list", func() {
				payload := api.NewGroupPayload().BuildTyped()
				createdGroup, groupID := api.CreateGroupWithCleanup(client, ctx, config, payload)

				groups, err := client.ListGroups(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(groups).NotTo(BeEmpty())

				found := false
				for _, group := range groups {
					if group.Metadata.Id == groupID {
						found = true
						Expect(group.Metadata.Name).To(Equal(createdGroup.Metadata.Name))
						GinkgoWriter.Printf("Found created group in list: %s\n", groupID)
						break
					}
				}

				Expect(found).To(BeTrue(), "Created group should appear in organization group list")
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return error when creating group in non-existent organization", func() {
				payload := api.NewGroupPayload().BuildTyped()

				_, err := client.CreateGroup(ctx, "invalid-org-id", payload)

				Expect(err).To(HaveOccurred())
				GinkgoWriter.Printf("Expected error for invalid organization ID: %v\n", err)
			})
		})
	})

	Context("When reading groups", func() {
		Describe("Given valid organization", func() {
			It("should return all groups in the organization with complete metadata", func() {
				groups, err := client.ListGroups(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				if len(groups) == 0 {
					Skip("Organization has no groups (valid state)")
				}

				for _, group := range groups {
					Expect(group.Metadata).NotTo(BeNil())
					Expect(group.Metadata.Id).NotTo(BeEmpty())
					Expect(group.Metadata.Name).NotTo(BeEmpty())
					Expect(group.Metadata.OrganizationId).To(Equal(config.OrgID))

					Expect(group.Spec).NotTo(BeNil())

					Expect(group.Metadata.ProvisioningStatus).NotTo(BeEmpty())
					Expect(string(group.Metadata.ProvisioningStatus)).To(BeElementOf(
						"provisioning", "provisioned", "deprovisioning", "error"))

					Expect(group.Metadata.HealthStatus).NotTo(BeEmpty())
					Expect(group.Metadata.HealthStatus).To(BeElementOf(
					coreopenapi.ResourceHealthStatusHealthy,
					coreopenapi.ResourceHealthStatusDegraded,
					coreopenapi.ResourceHealthStatusError))

					GinkgoWriter.Printf("  Group: %s (ID: %s)\n",
						group.Metadata.Name, group.Metadata.Id)
					GinkgoWriter.Printf("    Roles: %d, Service Accounts: %d\n",
						len(group.Spec.RoleIDs), len(group.Spec.ServiceAccountIDs))
				}

				GinkgoWriter.Printf("Found %d groups in organization %s\n",
					len(groups), config.OrgID)
			})
		})

		Describe("Given invalid group ID", func() {
			It("should return error for non-existent group", func() {
				_, err := client.GetGroup(ctx, config.OrgID, "00000000-0000-0000-0000-000000000000")

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue(),
					"Should return 404 not found error for non-existent group")

				GinkgoWriter.Printf("Expected error for non-existent group: %v\n", err)
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return error for non-existent organization", func() {
				_, err := client.ListGroups(ctx, "invalid-org-id")

				Expect(err).To(HaveOccurred())
				GinkgoWriter.Printf("Expected error for invalid organization ID: %v\n", err)
			})
		})
	})

	Context("When updating groups", func() {
		Describe("Given existing group", func() {
			It("should update group name successfully", func() {
				payload := api.NewGroupPayload().BuildTyped()
				originalGroup, groupID := api.CreateGroupWithCleanup(client, ctx, config, payload)

				updatedPayload := payload
				updatedPayload.Metadata.Name = originalGroup.Metadata.Name + "-updated"

				err := client.UpdateGroup(ctx, config.OrgID, groupID, updatedPayload)

				Expect(err).NotTo(HaveOccurred())

				updatedGroup, err := client.GetGroup(ctx, config.OrgID, groupID)
				Expect(err).NotTo(HaveOccurred())
				Expect(updatedGroup).NotTo(BeNil())
				Expect(updatedGroup.Metadata.Id).To(Equal(groupID))
				Expect(updatedGroup.Metadata.Name).To(Equal(updatedPayload.Metadata.Name))
				Expect(updatedGroup.Metadata.Name).NotTo(Equal(originalGroup.Metadata.Name))

				GinkgoWriter.Printf("Updated group name from '%s' to '%s'\n",
					originalGroup.Metadata.Name, updatedGroup.Metadata.Name)
			})

			It("should update group role assignments", func() {
				roles, err := client.ListRoles(ctx, config.OrgID)
				Expect(err).NotTo(HaveOccurred())

				if len(roles) == 0 {
					Skip("No roles available in organization to test role assignment")
				}

				payload := api.NewGroupPayload().BuildTyped()
				originalGroup, groupID := api.CreateGroupWithCleanup(client, ctx, config, payload)

				updatedPayload := payload
				updatedPayload.Spec.RoleIDs = []string{roles[0].Metadata.Id}

				err = client.UpdateGroup(ctx, config.OrgID, groupID, updatedPayload)

				Expect(err).NotTo(HaveOccurred())

				updatedGroup, err := client.GetGroup(ctx, config.OrgID, groupID)
				Expect(err).NotTo(HaveOccurred())
				Expect(updatedGroup).NotTo(BeNil())
				Expect(updatedGroup.Spec.RoleIDs).To(HaveLen(1))
				Expect(updatedGroup.Spec.RoleIDs[0]).To(Equal(roles[0].Metadata.Id))

				GinkgoWriter.Printf("Updated group '%s': added role %s\n",
					originalGroup.Metadata.Name, roles[0].Metadata.Name)
			})
		})

		Describe("Given invalid group ID", func() {
			It("should return error when updating non-existent group", func() {
				payload := api.NewGroupPayload().BuildTyped()

				err := client.UpdateGroup(ctx, config.OrgID, "00000000-0000-0000-0000-000000000000", payload)

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue(),
					"Should return 404 not found error for non-existent group")

				GinkgoWriter.Printf("Expected error for updating non-existent group: %v\n", err)
			})
		})
	})

	Context("When deleting groups", func() {
		Describe("Given existing group", func() {
			It("should successfully create and delete a test group with verification", func() {
				group, groupID := api.CreateGroupWithCleanup(client, ctx, config,
					api.NewGroupPayload().
						WithName("delete-test-group").
						BuildTyped())

				Expect(group.Metadata.Id).NotTo(BeEmpty())
				Expect(group.Metadata.Id).To(Equal(groupID))
				Expect(group.Metadata.Name).To(Equal("delete-test-group"))

				retrievedGroup, err := client.GetGroup(ctx, config.OrgID, groupID)
				Expect(err).NotTo(HaveOccurred())
				Expect(retrievedGroup).NotTo(BeNil())
				Expect(retrievedGroup.Metadata.Id).To(Equal(groupID))
				GinkgoWriter.Printf("Verified group exists: %s\n", groupID)

				err = client.DeleteGroup(ctx, config.OrgID, groupID)
				Expect(err).NotTo(HaveOccurred())
				GinkgoWriter.Printf("Deleted test group: %s\n", groupID)

				Eventually(func() bool {
					_, err := client.GetGroup(ctx, config.OrgID, groupID)
					return errors.Is(err, coreclient.ErrResourceNotFound)
				}).WithTimeout(config.TestTimeout).WithPolling(2 * time.Second).Should(BeTrue())

				GinkgoWriter.Printf("Verified group deletion: %s\n", groupID)
			})

			It("should delete group successfully", func() {
				payload := api.NewGroupPayload().BuildTyped()
				_, groupID := api.CreateGroupWithCleanup(client, ctx, config, payload)

				err := client.DeleteGroup(ctx, config.OrgID, groupID)

				Expect(err).NotTo(HaveOccurred())

				_, getErr := client.GetGroup(ctx, config.OrgID, groupID)
				Expect(getErr).To(HaveOccurred())
				Expect(errors.Is(getErr, coreclient.ErrResourceNotFound)).To(BeTrue(),
					"Deleted group should not be retrievable")

				GinkgoWriter.Printf("Successfully deleted group: %s\n", groupID)
			})
		})

		Describe("Given invalid group ID", func() {
			It("should return error when deleting non-existent group", func() {
				err := client.DeleteGroup(ctx, config.OrgID, "00000000-0000-0000-0000-000000000000")

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue(),
					"Should return 404 not found error for non-existent group")

				GinkgoWriter.Printf("Expected error for deleting non-existent group: %v\n", err)
			})
		})
	})
})
