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

var _ = Describe("Role Management", func() {
	Context("When listing roles", func() {
		Describe("Given valid organization", func() {
			It("should return all roles in the organization with complete metadata", func() {
				roles, err := client.ListRoles(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(roles).NotTo(BeEmpty(), "Organization should have at least one role")

				rolesByName := make(map[string]bool)

				for _, role := range roles {
					Expect(role.Metadata).NotTo(BeNil(), "Role metadata should not be nil")
					Expect(role.Metadata.Id).NotTo(BeEmpty(), "Role ID should not be empty")
					Expect(role.Metadata.Name).NotTo(BeEmpty(), "Role name should not be empty")

					if role.Metadata.Description != nil {
						Expect(*role.Metadata.Description).NotTo(BeEmpty(),
							"Role description should not be empty if present")
					}

					rolesByName[role.Metadata.Name] = true

					Expect(role.Metadata.ProvisioningStatus).NotTo(BeEmpty(),
						"Role provisioning status should not be empty")
					Expect(role.Metadata.ProvisioningStatus).To(BeElementOf(
						coreopenapi.ResourceProvisioningStatusProvisioning,
					coreopenapi.ResourceProvisioningStatusProvisioned,
					coreopenapi.ResourceProvisioningStatusDeprovisioning,
					coreopenapi.ResourceProvisioningStatusError),
						"Role provisioning status should be valid")

					Expect(role.Metadata.HealthStatus).NotTo(BeEmpty(),
						"Role health status should not be empty")
					Expect(role.Metadata.HealthStatus).To(BeElementOf(
					coreopenapi.ResourceHealthStatusHealthy,
					coreopenapi.ResourceHealthStatusDegraded,
					coreopenapi.ResourceHealthStatusError),
						"Role health status should be valid")

					description := "No description"
					if role.Metadata.Description != nil {
						description = *role.Metadata.Description
					}
					GinkgoWriter.Printf("  Role: %s (ID: %s)\n", role.Metadata.Name, role.Metadata.Id)
					GinkgoWriter.Printf("    Description: %s\n", description)
					GinkgoWriter.Printf("    Status: %s, Health: %s\n",
						role.Metadata.ProvisioningStatus,
						role.Metadata.HealthStatus)
				}

				GinkgoWriter.Printf("Found %d roles in organization %s\n", len(roles), config.OrgID)

				expectedRoles := []string{"administrator", "user", "reader"}
				foundExpectedRoles := 0
				for _, expectedRole := range expectedRoles {
					if rolesByName[expectedRole] {
						foundExpectedRoles++
						GinkgoWriter.Printf("  Found expected role: %s\n", expectedRole)
					}
				}

				Expect(foundExpectedRoles).To(BeNumerically(">", 0),
					"At least one common role (administrator, user, or reader) should be present")
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return error for non-existent organization", func() {
				_, err := client.ListRoles(ctx, "invalid-org-id")

				Expect(err).To(HaveOccurred())
				GinkgoWriter.Printf("Expected error for invalid organization ID: %v\n", err)
			})
		})
	})
})
