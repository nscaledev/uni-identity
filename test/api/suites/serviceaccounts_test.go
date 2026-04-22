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
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/test/api"
)

var _ = Describe("Service Account Management", func() {
	Context("When listing service accounts", func() {
		Describe("Given valid organization", func() {
			It("should return all service accounts in the organization with complete metadata", func() {
				api.CreateServiceAccountWithCleanup(client, ctx, config, api.NewServiceAccountPayload().Build())

				serviceAccounts, err := client.ListServiceAccounts(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(serviceAccounts).NotTo(BeEmpty())

				for _, sa := range serviceAccounts {
					Expect(sa.Metadata.Id).NotTo(BeEmpty())
					Expect(sa.Metadata.Name).NotTo(BeEmpty())
					Expect(sa.Metadata.OrganizationId).To(Equal(config.OrgID))
					Expect(sa.Metadata.ProvisioningStatus).To(BeElementOf(
						coreopenapi.ResourceProvisioningStatusProvisioning,
						coreopenapi.ResourceProvisioningStatusProvisioned,
						coreopenapi.ResourceProvisioningStatusDeprovisioning,
						coreopenapi.ResourceProvisioningStatusError))
					Expect(sa.Metadata.HealthStatus).To(BeElementOf(
						coreopenapi.ResourceHealthStatusHealthy,
						coreopenapi.ResourceHealthStatusDegraded,
						coreopenapi.ResourceHealthStatusError))
				}

				GinkgoWriter.Printf("Found %d service accounts in organization %s\n",
					len(serviceAccounts), config.OrgID)
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return error for non-existent organization", func() {
				_, err := client.ListServiceAccounts(ctx, "invalid-org-id")

				Expect(err).To(HaveOccurred())
			})
		})
	})

	Context("When creating service accounts", func() {
		Describe("Given valid service account data", func() {
			It("should create a service account and return a one-time access token", func() {
				payload := api.NewServiceAccountPayload().Build()
				created, saID := api.CreateServiceAccountWithCleanup(client, ctx, config, payload)

				Expect(saID).NotTo(BeEmpty())
				Expect(created.Metadata.Id).To(Equal(saID))
				Expect(created.Metadata.Name).To(Equal(payload.Metadata.Name))
				Expect(created.Metadata.OrganizationId).To(Equal(config.OrgID))

				// Token is only returned on create and rotate — this is the core invariant.
				Expect(created.Status.AccessToken).NotTo(BeNil(),
					"AccessToken must be present in create response")
				Expect(*created.Status.AccessToken).NotTo(BeEmpty(),
					"AccessToken must not be empty")
				Expect(created.Status.Expiry).To(BeTemporally(">", time.Now()),
					"Token expiry must be in the future")

				GinkgoWriter.Printf("Created SA %s, token expiry: %s\n",
					saID, created.Status.Expiry.Format(time.RFC3339))
			})

			It("should create a service account and find it in the list", func() {
				payload := api.NewServiceAccountPayload().Build()
				created, saID := api.CreateServiceAccountWithCleanup(client, ctx, config, payload)

				serviceAccounts, err := client.ListServiceAccounts(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				var found bool

				for _, sa := range serviceAccounts {
					if sa.Metadata.Id == saID {
						found = true
						Expect(sa.Metadata.Name).To(Equal(created.Metadata.Name))

						break
					}
				}

				Expect(found).To(BeTrue(), "Created service account %s should appear in list", saID)
			})

			It("should create a service account with group membership", func() {
				_, groupID := api.CreateGroupWithCleanup(client, ctx, config,
					api.NewGroupPayload().Build())

				payload := api.NewServiceAccountPayload().
					WithGroupIDs([]string{groupID}).
					Build()
				_, saID := api.CreateServiceAccountWithCleanup(client, ctx, config, payload)

				// The server has no GET /serviceaccounts/{id} route; verify via list.
				serviceAccounts, err := client.ListServiceAccounts(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				var found *identityopenapi.ServiceAccountRead

				for i := range serviceAccounts {
					if serviceAccounts[i].Metadata.Id == saID {
						found = &serviceAccounts[i]

						break
					}
				}

				Expect(found).NotTo(BeNil(), "Created service account should be in list")
				Expect(found.Spec.GroupIDs).To(ContainElement(groupID),
					"Service account should have the assigned group")
			})

			It("should reflect service account membership in the group when SA is created with a group", func() {
				_, groupID := api.CreateGroupWithCleanup(client, ctx, config,
					api.NewGroupPayload().Build())

				payload := api.NewServiceAccountPayload().
					WithGroupIDs([]string{groupID}).
					Build()
				_, saID := api.CreateServiceAccountWithCleanup(client, ctx, config, payload)

				group, err := client.GetGroup(ctx, config.OrgID, groupID)

				Expect(err).NotTo(HaveOccurred())
				Expect(group.Spec.ServiceAccountIDs).To(ContainElement(saID),
					"Group should reflect the service account added via SA creation")
			})

		})

		Describe("Given invalid organization ID", func() {
			It("should return error when creating in non-existent organization", func() {
				payload := api.NewServiceAccountPayload().Build()

				_, err := client.CreateServiceAccount(ctx, "invalid-org-id", payload)

				Expect(err).To(HaveOccurred())
			})
		})
	})

	Context("When updating service accounts", func() {
		Describe("Given existing service account", func() {
			It("should update the service account name", func() {
				payload := api.NewServiceAccountPayload().Build()
				_, saID := api.CreateServiceAccountWithCleanup(client, ctx, config, payload)

				updatedPayload := api.NewServiceAccountPayload().
					WithName(payload.Metadata.Name + "-updated").
					Build()

				updated, err := client.UpdateServiceAccount(ctx, config.OrgID, saID, updatedPayload)

				Expect(err).NotTo(HaveOccurred())
				Expect(updated.Metadata.Name).To(Equal(updatedPayload.Metadata.Name))

				// Verify the change persisted in the list.
				serviceAccounts, err := client.ListServiceAccounts(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				var found bool

				for _, sa := range serviceAccounts {
					if sa.Metadata.Id == saID {
						found = true
						Expect(sa.Metadata.Name).To(Equal(updatedPayload.Metadata.Name),
							"Updated name should be reflected in list")

						break
					}
				}

				Expect(found).To(BeTrue(), "Updated service account should still be in list")
			})

			It("should not return access token in update response", func() {
				payload := api.NewServiceAccountPayload().Build()
				_, saID := api.CreateServiceAccountWithCleanup(client, ctx, config, payload)

				updatedPayload := api.NewServiceAccountPayload().
					WithName(payload.Metadata.Name + "-updated").
					Build()

				updated, err := client.UpdateServiceAccount(ctx, config.OrgID, saID, updatedPayload)

				Expect(err).NotTo(HaveOccurred())
				Expect(updated.Status.AccessToken).To(BeNil(),
					"AccessToken must not be present in update response")
			})

			It("should update service account group membership", func() {
				_, groupID := api.CreateGroupWithCleanup(client, ctx, config,
					api.NewGroupPayload().Build())

				payload := api.NewServiceAccountPayload().Build()
				_, saID := api.CreateServiceAccountWithCleanup(client, ctx, config, payload)

				updatedPayload := api.NewServiceAccountPayload().
					WithGroupIDs([]string{groupID}).
					Build()

				_, err := client.UpdateServiceAccount(ctx, config.OrgID, saID, updatedPayload)

				Expect(err).NotTo(HaveOccurred())

				// The server has no GET /serviceaccounts/{id} route; verify via list.
				serviceAccounts, err := client.ListServiceAccounts(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				var found *identityopenapi.ServiceAccountRead

				for i := range serviceAccounts {
					if serviceAccounts[i].Metadata.Id == saID {
						found = &serviceAccounts[i]

						break
					}
				}

				Expect(found).NotTo(BeNil())
				Expect(found.Spec.GroupIDs).To(ContainElement(groupID),
					"Updated group membership should be reflected in list")
			})

			It("should clear service account group membership", func() {
				_, groupID := api.CreateGroupWithCleanup(client, ctx, config,
					api.NewGroupPayload().Build())

				payload := api.NewServiceAccountPayload().
					WithGroupIDs([]string{groupID}).
					Build()
				_, saID := api.CreateServiceAccountWithCleanup(client, ctx, config, payload)

				clearedPayload := payload
				clearedPayload.Spec.GroupIDs = []string{}

				_, err := client.UpdateServiceAccount(ctx, config.OrgID, saID, clearedPayload)

				Expect(err).NotTo(HaveOccurred())

				// The server has no GET /serviceaccounts/{id} route; verify via list.
				serviceAccounts, err := client.ListServiceAccounts(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				var found *identityopenapi.ServiceAccountRead

				for i := range serviceAccounts {
					if serviceAccounts[i].Metadata.Id == saID {
						found = &serviceAccounts[i]

						break
					}
				}

				Expect(found).NotTo(BeNil())
				Expect(found.Spec.GroupIDs).To(BeEmpty(),
					"Group membership should be empty after clearing")
			})
		})

		Describe("Given invalid service account ID", func() {
			It("should return not-found error", func() {
				payload := api.NewServiceAccountPayload().Build()

				_, err := client.UpdateServiceAccount(ctx, config.OrgID, "00000000-0000-0000-0000-000000000000", payload)

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
			})
		})
	})

	Context("When rotating service account tokens", func() {
		Describe("Given existing service account", func() {
			It("should rotate the token and return a new one-time access token", func() {
				payload := api.NewServiceAccountPayload().Build()
				created, saID := api.CreateServiceAccountWithCleanup(client, ctx, config, payload)

				Expect(created.Status.AccessToken).NotTo(BeNil())
				token1 := *created.Status.AccessToken

				rotated, err := client.RotateServiceAccount(ctx, config.OrgID, saID)

				Expect(err).NotTo(HaveOccurred())
				Expect(rotated.Status.AccessToken).NotTo(BeNil(),
					"AccessToken must be present in rotate response")
				Expect(*rotated.Status.AccessToken).NotTo(BeEmpty())
				Expect(*rotated.Status.AccessToken).NotTo(Equal(token1),
					"Rotated token must differ from the original")
				Expect(rotated.Status.Expiry).To(BeTemporally(">", time.Now()),
					"Rotated token expiry must be in the future")

				GinkgoWriter.Printf("Rotated SA %s token successfully\n", saID)
			})
		})

		Describe("Given invalid service account ID", func() {
			It("should return not-found error", func() {
				_, err := client.RotateServiceAccount(ctx, config.OrgID, "00000000-0000-0000-0000-000000000000")

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
			})
		})
	})

	Context("When deleting service accounts", func() {
		Describe("Given existing service account", func() {
			It("should delete and verify the service account is gone", func() {
				payload := api.NewServiceAccountPayload().Build()
				_, saID := api.CreateServiceAccountWithCleanup(client, ctx, config, payload)

				err := client.DeleteServiceAccount(ctx, config.OrgID, saID)

				Expect(err).NotTo(HaveOccurred())

				// Deletion is asynchronous; poll until the SA is absent from the list.
				Eventually(func() bool {
					serviceAccounts, err := client.ListServiceAccounts(ctx, config.OrgID)
					if err != nil {
						return false
					}

					for _, sa := range serviceAccounts {
						if sa.Metadata.Id == saID {
							return false
						}
					}

					return true
				}).WithTimeout(config.TestTimeout).WithPolling(2 * time.Second).Should(BeTrue(),
					"deleted service account %s should be removed from list", saID)

				GinkgoWriter.Printf("Verified service account %s is deleted\n", saID)
			})
		})

		Describe("Given invalid service account ID", func() {
			It("should return not-found error", func() {
				err := client.DeleteServiceAccount(ctx, config.OrgID, "00000000-0000-0000-0000-000000000000")

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
			})
		})
	})
})
