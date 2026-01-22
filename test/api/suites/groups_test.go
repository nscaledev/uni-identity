//go:build integration
// +build integration

/*
Copyright 2026 the Unikorn Authors.
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

var _ = Describe("Group Management", func() {
	Context("When listing groups", func() {
		Describe("Given valid organization", func() {
			It("should return all groups in the organization", func() {
				groups, err := client.ListGroups(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				// Groups may be empty, so just check that call succeeds
				for _, group := range groups {
					Expect(group.Metadata).NotTo(BeNil())
					Expect(group.Metadata.Id).NotTo(BeEmpty())
					Expect(group.Metadata.Name).NotTo(BeEmpty())
				}

				GinkgoWriter.Printf("Found %d groups in organization %s\n", len(groups), config.OrgID)
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

	Context("When creating and deleting groups", func() {
		Describe("Given valid organization", func() {
			It("should successfully create and delete a test group", func() {
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

				// Verify group is deleted
				Eventually(func() error {
					_, err := client.GetGroup(ctx, config.OrgID, groupID)
					return err
				}).WithTimeout(config.TestTimeout).WithPolling(2 * time.Second).Should(MatchError(ContainSubstring("404")))

				GinkgoWriter.Printf("Verified group deletion: %s\n", groupID)
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should fail to create group in non-existent organization", func() {
				_, err := client.CreateGroup(ctx, "invalid-org-id",
					api.NewGroupPayload().
						WithName("test-group-invalid-org").
						BuildTyped())

				Expect(err).To(HaveOccurred())
				GinkgoWriter.Printf("Expected error for invalid organization ID: %v\n", err)
			})
		})

		Describe("Given non-existent group ID", func() {
			It("should fail to delete non-existent group", func() {
				err := client.DeleteGroup(ctx, config.OrgID, "non-existent-group-id")
				Expect(err).To(HaveOccurred())
				GinkgoWriter.Printf("Expected error for non-existent group ID: %v\n", err)
			})
		})
	})

	Context("When getting group details", func() {
		Describe("Given valid group ID", func() {
			It("should return group details", func() {
				groups, err := client.ListGroups(ctx, config.OrgID)
				Expect(err).NotTo(HaveOccurred())

				if len(groups) == 0 {
					Skip("No groups available to test GetGroup")
				}

				groupID := groups[0].Metadata.Id

				group, err := client.GetGroup(ctx, config.OrgID, groupID)
				Expect(err).NotTo(HaveOccurred())
				Expect(group).NotTo(BeNil())
				Expect(group.Metadata).NotTo(BeNil())
				Expect(group.Metadata.Id).To(Equal(groupID))

				GinkgoWriter.Printf("Retrieved group: %s (ID: %s)\n",
					group.Metadata.Name, group.Metadata.Id)
			})
		})

		Describe("Given invalid group ID", func() {
			It("should return error for non-existent group", func() {
				_, err := client.GetGroup(ctx, config.OrgID, "invalid-group-id")

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrUnexpectedStatusCode)).To(BeTrue())
				GinkgoWriter.Printf("Expected error for invalid group ID: %v\n", err)
			})
		})
	})
})
