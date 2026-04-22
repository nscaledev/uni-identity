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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	"github.com/unikorn-cloud/identity/test/api"
)

var _ = Describe("OAuth2 Provider Management", func() {
	Context("When listing OAuth2 providers", func() {
		Describe("Given valid organization", func() {
			It("should return all OAuth2 providers in the organization", func() {
				api.CreateOauth2ProviderWithCleanup(client, ctx, config, api.NewOauth2ProviderPayload().Build())

				providers, err := client.ListOauth2Providers(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(providers).NotTo(BeEmpty())

				for _, p := range providers {
					Expect(p.Metadata.Id).NotTo(BeEmpty())
					Expect(p.Metadata.Name).NotTo(BeEmpty())
					Expect(p.Spec.ClientID).NotTo(BeEmpty())
				}

				GinkgoWriter.Printf("Found %d OAuth2 providers in organization %s\n",
					len(providers), config.OrgID)
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return error for non-existent organization", func() {
				_, err := client.ListOauth2Providers(ctx, "invalid-org-id")

				Expect(err).To(HaveOccurred())
			})
		})
	})

	Context("When creating OAuth2 providers", func() {
		Describe("Given valid provider data", func() {
			It("should create a provider and return complete metadata", func() {
				payload := api.NewOauth2ProviderPayload().Build()
				created, providerID := api.CreateOauth2ProviderWithCleanup(client, ctx, config, payload)

				Expect(providerID).NotTo(BeEmpty())
				Expect(created.Metadata.Id).To(Equal(providerID))
				Expect(created.Metadata.Name).To(Equal(payload.Metadata.Name))
				Expect(created.Spec.ClientID).To(Equal(payload.Spec.ClientID))

				GinkgoWriter.Printf("Created OAuth2 provider: %s (ID: %s)\n",
					created.Metadata.Name, providerID)
			})

			It("should create a provider and find it in the organization list", func() {
				payload := api.NewOauth2ProviderPayload().Build()
				created, providerID := api.CreateOauth2ProviderWithCleanup(client, ctx, config, payload)

				providers, err := client.ListOauth2Providers(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				var found bool

				for _, p := range providers {
					if p.Metadata.Id == providerID {
						found = true
						Expect(p.Metadata.Name).To(Equal(created.Metadata.Name))
						Expect(p.Spec.ClientID).To(Equal(created.Spec.ClientID))

						break
					}
				}

				Expect(found).To(BeTrue(), "Created OAuth2 provider %s should appear in list", providerID)
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return error when creating in non-existent organization", func() {
				payload := api.NewOauth2ProviderPayload().Build()

				_, err := client.CreateOauth2Provider(ctx, "invalid-org-id", payload)

				Expect(err).To(HaveOccurred())
			})
		})
	})

	Context("When updating OAuth2 providers", func() {
		Describe("Given existing provider", func() {
			It("should update provider name successfully", func() {
				payload := api.NewOauth2ProviderPayload().Build()
				original, providerID := api.CreateOauth2ProviderWithCleanup(client, ctx, config, payload)

				updatedPayload := api.NewOauth2ProviderPayload().
					WithName(original.Metadata.Name + "-updated").
					Build()

				err := client.UpdateOauth2Provider(ctx, config.OrgID, providerID, updatedPayload)

				Expect(err).NotTo(HaveOccurred())

				providers, err := client.ListOauth2Providers(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				var found bool

				for _, p := range providers {
					if p.Metadata.Id == providerID {
						found = true
						Expect(p.Metadata.Name).To(Equal(updatedPayload.Metadata.Name))
						Expect(p.Metadata.Name).NotTo(Equal(original.Metadata.Name))

						break
					}
				}

				Expect(found).To(BeTrue(), "Updated OAuth2 provider should still appear in list")

				GinkgoWriter.Printf("Updated OAuth2 provider name: %s -> %s\n",
					original.Metadata.Name, updatedPayload.Metadata.Name)
			})

			It("should update provider client ID successfully", func() {
				payload := api.NewOauth2ProviderPayload().Build()
				_, providerID := api.CreateOauth2ProviderWithCleanup(client, ctx, config, payload)

				updatedPayload := api.NewOauth2ProviderPayload().
					WithClientID("updated-client-id").
					Build()

				err := client.UpdateOauth2Provider(ctx, config.OrgID, providerID, updatedPayload)

				Expect(err).NotTo(HaveOccurred())

				providers, err := client.ListOauth2Providers(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				var found bool

				for _, p := range providers {
					if p.Metadata.Id == providerID {
						found = true
						Expect(p.Spec.ClientID).To(Equal("updated-client-id"))

						break
					}
				}

				Expect(found).To(BeTrue(), "Updated OAuth2 provider should still appear in list")
			})
		})

		Describe("Given invalid provider ID", func() {
			It("should return not-found error", func() {
				payload := api.NewOauth2ProviderPayload().Build()

				err := client.UpdateOauth2Provider(ctx, config.OrgID, "00000000-0000-0000-0000-000000000000", payload)

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
			})
		})
	})

	Context("When deleting OAuth2 providers", func() {
		Describe("Given existing provider", func() {
			It("should delete provider and verify it is gone from the list", func() {
				payload := api.NewOauth2ProviderPayload().Build()
				_, providerID := api.CreateOauth2ProviderWithCleanup(client, ctx, config, payload)

				err := client.DeleteOauth2Provider(ctx, config.OrgID, providerID)

				Expect(err).NotTo(HaveOccurred())

				providers, err := client.ListOauth2Providers(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				for _, p := range providers {
					Expect(p.Metadata.Id).NotTo(Equal(providerID),
						"Deleted OAuth2 provider should not appear in list")
				}

				GinkgoWriter.Printf("Verified OAuth2 provider %s is deleted\n", providerID)
			})
		})

		Describe("Given invalid provider ID", func() {
			It("should return not-found error", func() {
				err := client.DeleteOauth2Provider(ctx, config.OrgID, "00000000-0000-0000-0000-000000000000")

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
			})
		})
	})
})

var _ = Describe("Global OAuth2 Provider Discovery", func() {
	Context("When listing global OAuth2 providers", func() {
		Describe("Given valid authentication", func() {
			It("should return the platform-level provider list", func() {
				providers, err := client.ListGlobalOauth2Providers(ctx)

				Expect(err).NotTo(HaveOccurred())

				for _, p := range providers {
					Expect(p.Metadata.Id).NotTo(BeEmpty())
					Expect(p.Metadata.Name).NotTo(BeEmpty())
				}

				GinkgoWriter.Printf("Found %d global OAuth2 provider(s)\n", len(providers))
			})
		})
	})
})
