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

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/test/api"
)

var _ = Describe("User Management", func() {
	Context("When listing users", func() {
		Describe("Given valid organization", func() {
			It("should return all users in the organization with complete metadata", func() {
				api.CreateUserWithCleanup(client, ctx, config, api.NewUserPayload().Build())

				users, err := client.ListUsers(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(users).NotTo(BeEmpty())

				for _, user := range users {
					Expect(user.Metadata.Id).NotTo(BeEmpty())
					Expect(user.Metadata.OrganizationId).To(Equal(config.OrgID))
					Expect(user.Spec.Subject).NotTo(BeEmpty())
					Expect(user.Metadata.ProvisioningStatus).To(BeElementOf(
						coreopenapi.ResourceProvisioningStatusProvisioning,
						coreopenapi.ResourceProvisioningStatusProvisioned,
						coreopenapi.ResourceProvisioningStatusDeprovisioning,
						coreopenapi.ResourceProvisioningStatusError))
					Expect(user.Metadata.HealthStatus).To(BeElementOf(
						coreopenapi.ResourceHealthStatusHealthy,
						coreopenapi.ResourceHealthStatusDegraded,
						coreopenapi.ResourceHealthStatusError))
				}

				GinkgoWriter.Printf("Found %d users in organization %s\n", len(users), config.OrgID)
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return error for non-existent organization", func() {
				_, err := client.ListUsers(ctx, "invalid-org-id")

				Expect(err).To(HaveOccurred())
			})
		})
	})

	Context("When creating users", func() {
		Describe("Given valid user data", func() {
			It("should create a user with subject and state", func() {
				payload := api.NewUserPayload().Build()
				created, userID := api.CreateUserWithCleanup(client, ctx, config, payload)

				Expect(userID).NotTo(BeEmpty())
				Expect(created.Metadata.Id).To(Equal(userID))
				Expect(created.Metadata.OrganizationId).To(Equal(config.OrgID))
				Expect(created.Spec.Subject).To(Equal(payload.Spec.Subject))
				Expect(created.Spec.State).NotTo(BeEmpty())
				Expect(created.Spec.GroupIDs).To(BeEmpty())

				GinkgoWriter.Printf("Created user %s (subject: %s)\n", userID, created.Spec.Subject)
			})

			It("should create a user and find it in the organization list", func() {
				payload := api.NewUserPayload().Build()
				created, userID := api.CreateUserWithCleanup(client, ctx, config, payload)

				users, err := client.ListUsers(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				var found bool

				for _, u := range users {
					if u.Metadata.Id == userID {
						found = true
						Expect(u.Spec.Subject).To(Equal(created.Spec.Subject))

						break
					}
				}

				Expect(found).To(BeTrue(), "Created user %s should appear in list", userID)
			})

			It("should create a user with group membership", func() {
				_, groupID := api.CreateGroupWithCleanup(client, ctx, config,
					api.NewGroupPayload().Build())

				payload := api.NewUserPayload().
					WithGroupIDs([]string{groupID}).
					Build()
				_, userID := api.CreateUserWithCleanup(client, ctx, config, payload)

				// GroupIDs are not included in create/update response bodies; verify via list.
				users, err := client.ListUsers(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				var found *identityopenapi.UserRead

				for i := range users {
					if users[i].Metadata.Id == userID {
						found = &users[i]

						break
					}
				}

				Expect(found).NotTo(BeNil(), "Created user should be in list")
				Expect(found.Spec.GroupIDs).To(ContainElement(groupID),
					"User should have the assigned group")
			})

			It("should reflect user membership in the group when user is created with a group", func() {
				_, groupID := api.CreateGroupWithCleanup(client, ctx, config,
					api.NewGroupPayload().Build())

				payload := api.NewUserPayload().
					WithGroupIDs([]string{groupID}).
					Build()
				_, userID := api.CreateUserWithCleanup(client, ctx, config, payload)

				group, err := client.GetGroup(ctx, config.OrgID, groupID)

				Expect(err).NotTo(HaveOccurred())
				Expect(group.Spec.UserIDs).NotTo(BeNil(),
					"Group UserIDs should be populated after a user is added")
				Expect(*group.Spec.UserIDs).To(ContainElement(userID),
					"Group should reflect the user added via user creation")
			})

		})

		Describe("Given a user created with suspended state", func() {
			It("should reflect the suspended state immediately on read", func() {
				payload := api.NewUserPayload().
					WithState(identityopenapi.Suspended).
					Build()
				created, userID := api.CreateUserWithCleanup(client, ctx, config, payload)

				Expect(created.Spec.State).To(Equal(identityopenapi.Suspended),
					"User created with suspended state should be suspended immediately")

				GinkgoWriter.Printf("Created user %s with suspended state\n", userID)
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return error when creating in non-existent organization", func() {
				payload := api.NewUserPayload().Build()

				_, err := client.CreateUser(ctx, "invalid-org-id", payload)

				Expect(err).To(HaveOccurred())
			})
		})
	})

	Context("When updating users", func() {
		Describe("Given existing user", func() {
			It("should update user group membership", func() {
				_, groupID := api.CreateGroupWithCleanup(client, ctx, config,
					api.NewGroupPayload().Build())

				payload := api.NewUserPayload().Build()
				_, userID := api.CreateUserWithCleanup(client, ctx, config, payload)

				updatedPayload := api.NewUserPayload().
					WithGroupIDs([]string{groupID}).
					Build()

				_, err := client.UpdateUser(ctx, config.OrgID, userID, updatedPayload)

				Expect(err).NotTo(HaveOccurred())

				// GroupIDs are not included in update response bodies; verify via list.
				users, err := client.ListUsers(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				var found *identityopenapi.UserRead

				for i := range users {
					if users[i].Metadata.Id == userID {
						found = &users[i]

						break
					}
				}

				Expect(found).NotTo(BeNil())
				Expect(found.Spec.GroupIDs).To(ContainElement(groupID),
					"Updated group membership should be reflected in list")
			})

			It("should clear user group membership", func() {
				_, groupID := api.CreateGroupWithCleanup(client, ctx, config,
					api.NewGroupPayload().Build())

				payload := api.NewUserPayload().
					WithGroupIDs([]string{groupID}).
					Build()
				_, userID := api.CreateUserWithCleanup(client, ctx, config, payload)

				clearedPayload := payload
				clearedPayload.Spec.GroupIDs = []string{}

				_, err := client.UpdateUser(ctx, config.OrgID, userID, clearedPayload)

				Expect(err).NotTo(HaveOccurred())

				// GroupIDs are not included in update response bodies; verify via list.
				users, err := client.ListUsers(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				var found *identityopenapi.UserRead

				for i := range users {
					if users[i].Metadata.Id == userID {
						found = &users[i]

						break
					}
				}

				Expect(found).NotTo(BeNil())
				Expect(found.Spec.GroupIDs).To(BeEmpty(),
					"Group membership should be empty after clearing")
			})

			It("should suspend an active user", func() {
				payload := api.NewUserPayload().
					WithState(identityopenapi.Active).
					Build()
				_, userID := api.CreateUserWithCleanup(client, ctx, config, payload)

				updatedPayload := payload
				updatedPayload.Spec.State = identityopenapi.Suspended

				updated, err := client.UpdateUser(ctx, config.OrgID, userID, updatedPayload)

				Expect(err).NotTo(HaveOccurred())
				Expect(updated.Spec.State).To(Equal(identityopenapi.Suspended),
					"User state should be suspended after update")

				GinkgoWriter.Printf("Suspended user %s\n", userID)
			})

			It("should reactivate a suspended user", func() {
				payload := api.NewUserPayload().
					WithState(identityopenapi.Suspended).
					Build()
				_, userID := api.CreateUserWithCleanup(client, ctx, config, payload)

				updatedPayload := payload
				updatedPayload.Spec.State = identityopenapi.Active

				updated, err := client.UpdateUser(ctx, config.OrgID, userID, updatedPayload)

				Expect(err).NotTo(HaveOccurred())
				Expect(updated.Spec.State).To(Equal(identityopenapi.Active),
					"User state should be active after reactivation")

				GinkgoWriter.Printf("Reactivated user %s\n", userID)
			})
		})

		Describe("Given invalid user ID", func() {
			It("should return not-found error", func() {
				payload := api.NewUserPayload().Build()

				_, err := client.UpdateUser(ctx, config.OrgID, "00000000-0000-0000-0000-000000000000", payload)

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
			})
		})
	})

	Context("When deleting users", func() {
		Describe("Given existing user", func() {
			It("should delete user and confirm it disappears from the list", func() {
				payload := api.NewUserPayload().Build()
				_, userID := api.CreateUserWithCleanup(client, ctx, config, payload)

				err := client.DeleteUser(ctx, config.OrgID, userID)

				Expect(err).NotTo(HaveOccurred())

				users, err := client.ListUsers(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				for _, u := range users {
					Expect(u.Metadata.Id).NotTo(Equal(userID),
						"Deleted user should not appear in list")
				}

				GinkgoWriter.Printf("Verified user %s is deleted\n", userID)
			})
		})

		Describe("Given invalid user ID", func() {
			It("should return not-found error", func() {
				err := client.DeleteUser(ctx, config.OrgID, "00000000-0000-0000-0000-000000000000")

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue())
			})
		})
	})
})
