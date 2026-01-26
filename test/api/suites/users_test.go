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

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
)

var _ = Describe("User Management", func() {
	Context("When listing users", func() {
		Describe("Given valid organization", func() {
			It("should return all users in the organization with complete metadata", func() {
				users, err := client.ListUsers(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(users).NotTo(BeEmpty(), "Organization should have at least one user")

				for _, user := range users {
					Expect(user.Metadata).NotTo(BeNil(), "User metadata should not be nil")
					Expect(user.Metadata.Id).NotTo(BeEmpty(), "User ID should not be empty")
					Expect(user.Metadata.OrganizationId).To(Equal(config.OrgID),
						"User organization ID should match requested organization")

					Expect(user.Spec).NotTo(BeNil(), "User spec should not be nil")
					Expect(user.Spec.Subject).NotTo(BeEmpty(), "User subject (email) should not be empty")

					if user.Spec.State != "" {
						Expect(string(user.Spec.State)).To(BeElementOf("active", "pending", "inactive"),
							"User state should be a valid state")
					}

					if len(user.Spec.GroupIDs) > 0 {
						Expect(user.Spec.GroupIDs).NotTo(BeEmpty(),
							"User should be a member of at least one group")

						GinkgoWriter.Printf("  User: %s (subject: %s, groups: %d)\n",
							user.Metadata.Id,
							user.Spec.Subject,
							len(user.Spec.GroupIDs))
					}

					Expect(user.Metadata.ProvisioningStatus).NotTo(BeEmpty(),
						"User provisioning status should not be empty")
					Expect(user.Metadata.ProvisioningStatus).To(BeElementOf(
						coreopenapi.ResourceProvisioningStatusProvisioning,
					coreopenapi.ResourceProvisioningStatusProvisioned,
					coreopenapi.ResourceProvisioningStatusDeprovisioning,
					coreopenapi.ResourceProvisioningStatusError),
						"User provisioning status should be valid")

					Expect(user.Metadata.HealthStatus).NotTo(BeEmpty(),
						"User health status should not be empty")
					Expect(user.Metadata.HealthStatus).To(BeElementOf(
					coreopenapi.ResourceHealthStatusHealthy,
					coreopenapi.ResourceHealthStatusDegraded,
					coreopenapi.ResourceHealthStatusError),
						"User health status should be valid")
				}

				GinkgoWriter.Printf("Found %d users in organization %s\n", len(users), config.OrgID)

				stateCounts := make(map[string]int)
				for _, user := range users {
					if user.Spec.State != "" {
						stateCounts[string(user.Spec.State)]++
					}
				}
				for state, count := range stateCounts {
					GinkgoWriter.Printf("  Users in state '%s': %d\n", state, count)
				}
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return error for non-existent organization", func() {
				_, err := client.ListUsers(ctx, "invalid-org-id")

				Expect(err).To(HaveOccurred())
				GinkgoWriter.Printf("Expected error for invalid organization ID: %v\n", err)
			})
		})
	})
})
