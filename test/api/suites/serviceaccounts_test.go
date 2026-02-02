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

var _ = Describe("Service Account Management", func() {
	Context("When listing service accounts", func() {
		Describe("Given valid organization", func() {
			It("should return all service accounts in the organization with complete metadata", func() {
				serviceAccounts, err := client.ListServiceAccounts(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				if len(serviceAccounts) == 0 {
					Skip("Organization has no service accounts (valid state)")
				}

				for _, sa := range serviceAccounts {
					Expect(sa.Metadata).NotTo(BeNil(), "Service account metadata should not be nil")
					Expect(sa.Metadata.Id).NotTo(BeEmpty(), "Service account ID should not be empty")
					Expect(sa.Metadata.Name).NotTo(BeEmpty(), "Service account name should not be empty")
					Expect(sa.Metadata.OrganizationId).To(Equal(config.OrgID),
						"Service account organization ID should match requested organization")

					Expect(sa.Spec).NotTo(BeNil(), "Service account spec should not be nil")

					Expect(sa.Metadata.ProvisioningStatus).NotTo(BeEmpty(),
						"Service account provisioning status should not be empty")
					Expect(sa.Metadata.ProvisioningStatus).To(BeElementOf(
						coreopenapi.ResourceProvisioningStatusProvisioning,
						coreopenapi.ResourceProvisioningStatusProvisioned,
						coreopenapi.ResourceProvisioningStatusDeprovisioning,
						coreopenapi.ResourceProvisioningStatusError),
						"Service account provisioning status should be valid")

					Expect(sa.Metadata.HealthStatus).NotTo(BeEmpty(),
						"Service account health status should not be empty")
					Expect(sa.Metadata.HealthStatus).To(BeElementOf(
						coreopenapi.ResourceHealthStatusHealthy,
						coreopenapi.ResourceHealthStatusDegraded,
						coreopenapi.ResourceHealthStatusError),
						"Service account health status should be valid")

					GinkgoWriter.Printf("  Service Account: %s (ID: %s)\n",
						sa.Metadata.Name, sa.Metadata.Id)
					GinkgoWriter.Printf("    Groups: %d, Status: %s, Health: %s\n",
						len(sa.Spec.GroupIDs),
						sa.Metadata.ProvisioningStatus,
						sa.Metadata.HealthStatus)

					if !sa.Status.Expiry.IsZero() {
						GinkgoWriter.Printf("    Expiry: %s\n",
							sa.Status.Expiry.Format("2006-01-02 15:04:05"))
					}
				}

				GinkgoWriter.Printf("Found %d service accounts in organization %s\n",
					len(serviceAccounts), config.OrgID)
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return error for non-existent organization", func() {
				_, err := client.ListServiceAccounts(ctx, "invalid-org-id")

				Expect(err).To(HaveOccurred())
				GinkgoWriter.Printf("Expected error for invalid organization ID: %v\n", err)
			})
		})
	})
})
