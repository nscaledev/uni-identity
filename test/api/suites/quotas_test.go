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
)

var _ = Describe("Quota Management", func() {
	Context("When getting organization quotas", func() {
		Describe("Given valid organization", func() {
			It("should return complete quota information for all resource types", func() {
				quotasResponse, err := client.GetQuotas(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(quotasResponse).NotTo(BeNil())
				Expect(quotasResponse.Quotas).NotTo(BeEmpty(), "Organization should have at least one quota defined")

				expectedQuotaKinds := []string{"clusters", "servers", "networks", "gpus"}
				foundCoreQuotas := 0

				for _, quota := range quotasResponse.Quotas {
					Expect(quota.Kind).NotTo(BeEmpty(), "Quota kind should not be empty")
					Expect(quota.DisplayName).NotTo(BeEmpty(), "Quota display name should not be empty")
					Expect(quota.Description).NotTo(BeEmpty(), "Quota description should not be empty")
					Expect(quota.Quantity).To(BeNumerically(">=", 0), "Quota quantity should be non-negative")
					Expect(quota.Used).To(BeNumerically(">=", 0), "Quota used should be non-negative")
					Expect(quota.Free).To(BeNumerically(">=", 0), "Quota free should be non-negative")
					Expect(quota.Reserved).To(BeNumerically(">=", 0), "Quota reserved should be non-negative")
					Expect(quota.Committed).To(BeNumerically(">=", 0), "Quota committed should be non-negative")
					Expect(quota.Default).To(BeNumerically(">=", 0), "Quota default should be non-negative")

					totalQuota := quota.Used + quota.Free
					Expect(totalQuota).To(Equal(quota.Quantity),
						"Quota accounting should be consistent: used (%d) + free (%d) should equal quantity (%d) for %s",
						quota.Used, quota.Free, quota.Quantity, quota.Kind)

					for _, expectedKind := range expectedQuotaKinds {
						if quota.Kind == expectedKind {
							foundCoreQuotas++
							break
						}
					}

					GinkgoWriter.Printf("  Quota: %s (kind: %s)\n", quota.DisplayName, quota.Kind)
					GinkgoWriter.Printf("    Total: %d, Used: %d, Free: %d, Committed: %d\n",
						quota.Quantity, quota.Used, quota.Free, quota.Committed)
				}

				GinkgoWriter.Printf("Retrieved %d quota types for organization %s\n",
					len(quotasResponse.Quotas), config.OrgID)

				Expect(foundCoreQuotas).To(BeNumerically(">", 0),
					"At least one core quota type should be present (clusters, servers, networks, or gpus)")
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return error for non-existent organization", func() {
				_, err := client.GetQuotas(ctx, "invalid-org-id")

				Expect(err).To(HaveOccurred())
				GinkgoWriter.Printf("Expected error for invalid organization ID: %v\n", err)
			})
		})
	})
})
