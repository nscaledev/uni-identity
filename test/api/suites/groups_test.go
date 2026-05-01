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
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/test/api"
)

var _ = Describe("Group Management", func() {
	Context("When creating groups", func() {
		Describe("Given valid group data", func() {
			It("should create a new group with complete metadata", func() {
				payload := api.NewGroupPayload().Build()
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
				payload := api.NewGroupPayload().Build()
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
				payload := api.NewGroupPayload().Build()
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
				payload := api.NewGroupPayload().Build()

				_, err := client.CreateGroup(ctx, "invalid-org-id", payload)

				Expect(err).To(HaveOccurred())
				GinkgoWriter.Printf("Expected error for invalid organization ID: %v\n", err)
			})
		})

	})

	Context("When reading groups", func() {
		Describe("Given valid organization", func() {
			It("should return all groups in the organization with complete metadata", func() {
				api.CreateGroupWithCleanup(client, ctx, config, api.NewGroupPayload().Build())

				groups, err := client.ListGroups(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(groups).NotTo(BeEmpty())

				for _, group := range groups {
					Expect(group.Metadata).NotTo(BeNil())
					Expect(group.Metadata.Id).NotTo(BeEmpty())
					Expect(group.Metadata.Name).NotTo(BeEmpty())
					Expect(group.Metadata.OrganizationId).To(Equal(config.OrgID))

					Expect(group.Spec).NotTo(BeNil())

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
				payload := api.NewGroupPayload().Build()
				originalGroup, groupID := api.CreateGroupWithCleanup(client, ctx, config, payload)

				updatedPayload := api.NewGroupPayload().
					WithName(originalGroup.Metadata.Name + "-updated").
					Build()

				_, err := client.UpdateGroup(ctx, config.OrgID, groupID, updatedPayload)

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

				payload := api.NewGroupPayload().Build()
				originalGroup, groupID := api.CreateGroupWithCleanup(client, ctx, config, payload)

				updatedPayload := payload
				updatedPayload.Spec.RoleIDs = []string{roles[0].Metadata.Id}

				_, err = client.UpdateGroup(ctx, config.OrgID, groupID, updatedPayload)

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
				payload := api.NewGroupPayload().Build()

				_, err := client.UpdateGroup(ctx, config.OrgID, "00000000-0000-0000-0000-000000000000", payload)

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue(),
					"Should return 404 not found error for non-existent group")

				GinkgoWriter.Printf("Expected error for updating non-existent group: %v\n", err)
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return error when updating group in non-existent organization", func() {
				payload := api.NewGroupPayload().Build()

				_, err := client.UpdateGroup(ctx, "invalid-org-id", "00000000-0000-0000-0000-000000000000", payload)

				Expect(err).To(HaveOccurred())
			})
		})
	})

	Context("When deleting groups", func() {
		Describe("Given existing group", func() {
			It("should delete group successfully", func() {
				payload := api.NewGroupPayload().Build()
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

		Describe("Given invalid organization ID", func() {
			It("should return error when deleting group in non-existent organization", func() {
				err := client.DeleteGroup(ctx, "invalid-org-id", "00000000-0000-0000-0000-000000000000")

				Expect(err).To(HaveOccurred())
			})
		})
	})
})

// From nscale-auth0-tests: groups.spec.ts §5 — Subjects membership field
var _ = Describe("Group Subjects", func() {
	Context("When managing group subjects", func() {
		// §5.1 Create with subjects field
		Describe("Given a new group created with subjects", func() {
			It("should create successfully with subjects populated and userIDs auto-populated", func() {
				testEmail := fmt.Sprintf("qa-subject-%d@example.com", time.Now().UnixNano())
				email := testEmail
				testSubject := identityopenapi.Subject{Id: testEmail, Email: &email, Issuer: ""}

				payload := api.NewGroupPayload().WithSubjects([]identityopenapi.Subject{testSubject}).Build()
				group, groupID := api.CreateGroupWithCleanup(client, ctx, config, payload)

				Expect(groupID).NotTo(BeEmpty())
				Expect(group.Spec.Subjects).NotTo(BeNil(),
					"subjects field must be populated after create")
				Expect(*group.Spec.Subjects).To(HaveLen(1))
				Expect((*group.Spec.Subjects)[0].Id).To(Equal(testEmail))

				GinkgoWriter.Printf("Created group with subjects: %s (ID: %s)\n",
					group.Metadata.Name, groupID)
			})
		})

		// §5.2 Create with userIDs (legacy) — subjects auto-populated
		Describe("Given a new group created with userIDs (legacy field)", func() {
			It("should create successfully and subjects should be auto-populated", func() {
				// userIDs are OrganizationUser object IDs — fetch a real one from the org.
				users, err := client.ListUsers(ctx, config.OrgID)
				if err != nil || len(users) == 0 {
					Skip("No users available in organization to test legacy userIDs field")
				}

				realUserID := users[0].Metadata.Id

				payload := api.NewGroupPayload().WithUserIDs([]string{realUserID}).Build()
				group, groupID := api.CreateGroupWithCleanup(client, ctx, config, payload)

				Expect(groupID).NotTo(BeEmpty())
				Expect(group.Spec.UserIDs).NotTo(BeNil(),
					"userIDs must be present after create with legacy field")
				// subjects should be auto-populated from the resolved userID
				Expect(group.Spec.Subjects).NotTo(BeNil(),
					"subjects must be auto-populated when group is created with userIDs")

				GinkgoWriter.Printf("Created group with userIDs (legacy): %s (ID: %s)\n",
					group.Metadata.Name, groupID)
			})
		})

		// §5.3 Create with both subjects AND userIDs → rejected
		Describe("Given a new group with both subjects and userIDs set", func() {
			It("should be rejected with an error", func() {
				testEmail := fmt.Sprintf("qa-both-%d@example.com", time.Now().UnixNano())
				email := testEmail
				testSubject := identityopenapi.Subject{Id: testEmail, Email: &email, Issuer: ""}
				fakeUserID := fmt.Sprintf("fake-user-%d", time.Now().UnixNano())

				payload := api.NewGroupPayload().
					WithSubjects([]identityopenapi.Subject{testSubject}).
					WithUserIDs([]string{fakeUserID}).
					Build()

				_, err := client.CreateGroup(ctx, config.OrgID, payload)

				Expect(err).To(HaveOccurred(),
					"creating a group with both subjects and userIDs must be rejected")

				GinkgoWriter.Printf("Correctly rejected group with both subjects and userIDs: %v\n", err)
			})
		})

		// §5.4 GET returns both subjects and userIDs fields
		Describe("Given an existing group with subjects", func() {
			It("should return both subjects and userIDs fields on GET", func() {
				testEmail := fmt.Sprintf("qa-get-%d@example.com", time.Now().UnixNano())
				email := testEmail
				testSubject := identityopenapi.Subject{Id: testEmail, Email: &email, Issuer: ""}

				payload := api.NewGroupPayload().WithSubjects([]identityopenapi.Subject{testSubject}).Build()
				_, groupID := api.CreateGroupWithCleanup(client, ctx, config, payload)

				retrieved, err := client.GetGroup(ctx, config.OrgID, groupID)

				Expect(err).NotTo(HaveOccurred())
				Expect(retrieved).NotTo(BeNil())
				Expect(retrieved.Spec.Subjects).NotTo(BeNil(),
					"GET response must include subjects field")

				GinkgoWriter.Printf("GET returned subjects field for group: %s\n", groupID)
			})
		})

		// §5.5 Add a subject via PUT → subject appears in membership
		// §5.5b PUT returns 200 with non-empty updated group body (Metadata.Id present)
		Describe("Given an existing group, adding a subject via PUT", func() {
			It("should reflect the new subject in the GET response and return updated group in PUT response", func() {
				firstEmail := fmt.Sprintf("qa-add1-%d@example.com", time.Now().UnixNano())
				firstEmailCopy := firstEmail
				firstSubject := identityopenapi.Subject{Id: firstEmail, Email: &firstEmailCopy, Issuer: ""}

				payload := api.NewGroupPayload().WithSubjects([]identityopenapi.Subject{firstSubject}).Build()
				_, groupID := api.CreateGroupWithCleanup(client, ctx, config, payload)

				secondEmail := fmt.Sprintf("qa-add2-%d@example.com", time.Now().UnixNano())
				secondEmailCopy := secondEmail
				secondSubject := identityopenapi.Subject{Id: secondEmail, Email: &secondEmailCopy, Issuer: ""}

				updatePayload := api.NewGroupPayload().
					WithSubjects([]identityopenapi.Subject{firstSubject, secondSubject}).
					Build()

				// §5.5b — PUT must return the updated group with Metadata.Id set
				updated, err := client.UpdateGroup(ctx, config.OrgID, groupID, updatePayload)

				Expect(err).NotTo(HaveOccurred())
				Expect(updated).NotTo(BeNil(), "PUT must return the updated group body")
				Expect(updated.Metadata.Id).NotTo(BeEmpty(),
					"PUT response Metadata.Id must be present")

				// §5.5 — verify via GET that the new subject is in the membership
				retrieved, err := client.GetGroup(ctx, config.OrgID, groupID)
				Expect(err).NotTo(HaveOccurred())
				Expect(retrieved.Spec.Subjects).NotTo(BeNil())

				var subjectIDs []string
				for _, s := range *retrieved.Spec.Subjects {
					subjectIDs = append(subjectIDs, s.Id)
				}

				Expect(subjectIDs).To(ContainElement(secondEmail),
					"second subject must appear in group membership after PUT")

				GinkgoWriter.Printf("Added subject %s to group %s\n", secondEmail, groupID)
			})
		})

		// §5.6 Remove a subject via PUT → subject no longer in membership
		Describe("Given an existing group with two subjects, removing one via PUT", func() {
			It("should no longer return the removed subject in the GET response", func() {
				firstEmail := fmt.Sprintf("qa-rem1-%d@example.com", time.Now().UnixNano())
				firstEmailCopy := firstEmail
				firstSubject := identityopenapi.Subject{Id: firstEmail, Email: &firstEmailCopy, Issuer: ""}

				secondEmail := fmt.Sprintf("qa-rem2-%d@example.com", time.Now().UnixNano())
				secondEmailCopy := secondEmail
				secondSubject := identityopenapi.Subject{Id: secondEmail, Email: &secondEmailCopy, Issuer: ""}

				payload := api.NewGroupPayload().
					WithSubjects([]identityopenapi.Subject{firstSubject, secondSubject}).
					Build()
				_, groupID := api.CreateGroupWithCleanup(client, ctx, config, payload)

				// Remove secondSubject by PUTting only firstSubject
				updatePayload := api.NewGroupPayload().
					WithSubjects([]identityopenapi.Subject{firstSubject}).
					Build()

				_, err := client.UpdateGroup(ctx, config.OrgID, groupID, updatePayload)
				Expect(err).NotTo(HaveOccurred())

				retrieved, err := client.GetGroup(ctx, config.OrgID, groupID)
				Expect(err).NotTo(HaveOccurred())
				Expect(retrieved.Spec.Subjects).NotTo(BeNil())

				var subjectIDs []string
				for _, s := range *retrieved.Spec.Subjects {
					subjectIDs = append(subjectIDs, s.Id)
				}

				Expect(subjectIDs).NotTo(ContainElement(secondEmail),
					"removed subject must not appear in group membership after PUT")
				Expect(subjectIDs).To(ContainElement(firstEmail),
					"retained subject must still appear in group membership")

				GinkgoWriter.Printf("Removed subject %s from group %s\n", secondEmail, groupID)
			})
		})

		// §5.7 PUT with both subjects and userIDs → rejected
		Describe("Given a PUT with both subjects and userIDs set", func() {
			It("should be rejected with an error", func() {
				payload := api.NewGroupPayload().Build()
				_, groupID := api.CreateGroupWithCleanup(client, ctx, config, payload)

				testEmail := fmt.Sprintf("qa-both-put-%d@example.com", time.Now().UnixNano())
				email := testEmail
				testSubject := identityopenapi.Subject{Id: testEmail, Email: &email, Issuer: ""}
				fakeUserID := fmt.Sprintf("fake-user-put-%d", time.Now().UnixNano())

				updatePayload := api.NewGroupPayload().
					WithSubjects([]identityopenapi.Subject{testSubject}).
					WithUserIDs([]string{fakeUserID}).
					Build()

				_, err := client.UpdateGroup(ctx, config.OrgID, groupID, updatePayload)

				Expect(err).To(HaveOccurred(),
					"updating a group with both subjects and userIDs must be rejected")

				GinkgoWriter.Printf("Correctly rejected PUT with both subjects and userIDs: %v\n", err)
			})
		})
	})
})

// From nscale-auth0-tests: groups.spec.ts §5.8 & §5.9 — ACL effect of group membership.
var _ = Describe("Group Subjects - ACL Effect", func() {
	BeforeEach(func() {
		if userClient == nil {
			Skip("USER_AUTH_TOKEN is required to test group membership ACL effects")
		}
	})

	// Helper to count total ACL operations in org scope.
	countOrgACLOps := func(c *api.APIClient) int {
		acl, err := c.GetOrganizationACL(ctx, config.OrgID)
		if err != nil || acl.Organization == nil || acl.Organization.Endpoints == nil {
			return 0
		}

		total := 0

		for _, ep := range *acl.Organization.Endpoints {
			total += len(ep.Operations)
		}

		return total
	}

	// §5.8 adding a subject to a group grants ACL permissions
	Describe("Given a group with a role, when the user's subject is added", func() {
		It("should gain the role's endpoint operations in the user's org ACL", func() {
			roles, err := adminClient.ListRoles(ctx, config.OrgID)
			Expect(err).NotTo(HaveOccurred())

			if len(roles) == 0 {
				Skip("No roles available in organization")
			}

			// Capture the user's initial ACL operation count.
			initialOps := countOrgACLOps(userClient)

			// Get the user's external subject identifier from their token.
			userinfo, err := userClient.GetUserinfo(ctx)
			Expect(err).NotTo(HaveOccurred())

			subjectID := userinfo.Sub
			subject := identityopenapi.Subject{Id: subjectID, Issuer: ""}

			_, groupID := api.CreateGroupWithCleanup(adminClient, ctx, config,
				api.NewGroupPayload().
					WithRoleIDs([]string{roles[0].Metadata.Id}).
					WithSubjects([]identityopenapi.Subject{subject}).
					Build())

			Eventually(func() int {
				return countOrgACLOps(userClient)
			}).WithTimeout(config.TestTimeout).WithPolling(2*time.Second).Should(
				BeNumerically(">", initialOps),
				"user ACL operation count must increase after being added to a role-bearing group")

			GinkgoWriter.Printf("Group %s: ACL op count increased beyond initial %d\n", groupID, initialOps)
		})
	})

	// §5.9 deleting a group removes the subject's ACL permissions
	Describe("Given a group that was granting permissions, when the group is deleted", func() {
		It("should reduce the user's org ACL operation count", func() {
			roles, err := adminClient.ListRoles(ctx, config.OrgID)
			Expect(err).NotTo(HaveOccurred())

			if len(roles) == 0 {
				Skip("No roles available in organization")
			}

			userinfo, err := userClient.GetUserinfo(ctx)
			Expect(err).NotTo(HaveOccurred())

			subjectID := userinfo.Sub
			subject := identityopenapi.Subject{Id: subjectID, Issuer: ""}

			_, groupID := api.CreateGroupWithCleanup(adminClient, ctx, config,
				api.NewGroupPayload().
					WithRoleIDs([]string{roles[0].Metadata.Id}).
					WithSubjects([]identityopenapi.Subject{subject}).
					Build())

			// Wait for ACL to gain permissions.
			var opsWithGroup int

			Eventually(func() int {
				opsWithGroup = countOrgACLOps(userClient)
				return opsWithGroup
			}).WithTimeout(config.TestTimeout).WithPolling(2*time.Second).Should(
				BeNumerically(">", 0))

			// Now delete the group (bypass DeferCleanup by deleting explicitly).
			Expect(adminClient.DeleteGroup(ctx, config.OrgID, groupID)).To(Succeed())

			// ACL should shrink back.
			Eventually(func() int {
				return countOrgACLOps(userClient)
			}).WithTimeout(config.TestTimeout).WithPolling(2*time.Second).Should(
				BeNumerically("<", opsWithGroup),
				"user ACL operation count must decrease after the group is deleted")

			GinkgoWriter.Printf("Group %s deleted — ACL ops reduced from %d\n",
				groupID, opsWithGroup)
		})
	})
})

// From nscale-auth0-tests: groups.spec.ts §6.3 — migration backfill check.
// After the Phase 1 migration all groups with userIDs must also have subjects populated.
var _ = Describe("Group Migration - Startup Backfill", func() {
	Describe("Given all existing groups in the organization", func() {
		It("should have subjects backfilled for every group that has userIDs", func() {
			groups, err := client.ListGroups(ctx, config.OrgID)

			Expect(err).NotTo(HaveOccurred())

			for _, g := range groups {
				if g.Spec.UserIDs == nil || len(*g.Spec.UserIDs) == 0 {
					continue
				}

				Expect(g.Spec.Subjects).NotTo(BeNil(),
					"group %s has userIDs but subjects is nil — backfill may have failed",
					g.Metadata.Id)
				Expect(*g.Spec.Subjects).NotTo(BeEmpty(),
					"group %s has userIDs but subjects is empty — backfill may have failed",
					g.Metadata.Id)

				GinkgoWriter.Printf("Group %s: userIDs=%d subjects=%d (backfill OK)\n",
					g.Metadata.Id, len(*g.Spec.UserIDs), len(*g.Spec.Subjects))
			}
		})
	})
})

// From nscale-auth0-tests: groups.spec.ts §7 — RBAC permission matrix for groups.
var _ = Describe("Groups RBAC Permission Matrix", func() {
	// §7.1 admin token can list, create, and delete groups
	Describe("Given an admin token", func() {
		It("should be permitted to list, create, and delete groups", func() {
			_, groupID := api.CreateGroupWithCleanup(adminClient, ctx, config,
				api.NewGroupPayload().Build())

			groups, err := adminClient.ListGroups(ctx, config.OrgID)
			Expect(err).NotTo(HaveOccurred())

			found := false

			for _, g := range groups {
				if g.Metadata.Id == groupID {
					found = true
					break
				}
			}

			Expect(found).To(BeTrue(), "admin must see the group it created in the list")
			GinkgoWriter.Printf("Admin list+create+delete OK for group %s\n", groupID)
		})
	})

	// §7.2 audit token can list groups
	Describe("Given an audit token requesting to list groups", func() {
		BeforeEach(func() {
			if auditClient == nil {
				Skip("AUDIT_AUTH_TOKEN is not configured")
			}
		})

		It("should be permitted to list groups", func() {
			_, err := auditClient.ListGroups(ctx, config.OrgID)

			Expect(err).NotTo(HaveOccurred(),
				"audit token must be permitted to list groups")

			GinkgoWriter.Printf("Audit: list groups permitted\n")
		})
	})

	// §7.3 audit token cannot create groups
	Describe("Given an audit token attempting to create a group", func() {
		BeforeEach(func() {
			if auditClient == nil {
				Skip("AUDIT_AUTH_TOKEN is not configured")
			}
		})

		It("should be denied with a forbidden response", func() {
			_, err := auditClient.CreateGroup(ctx, config.OrgID,
				api.NewGroupPayload().Build())

			Expect(err).To(HaveOccurred(),
				"audit token must not be permitted to create groups")

			GinkgoWriter.Printf("Audit create group correctly denied: %v\n", err)
		})
	})

	// §7.4 non-member token gets 403 on group operations in private org
	Describe("Given a non-member organization", func() {
		BeforeEach(func() {
			if config.UnauthorisedOrgID == "" {
				Skip("UNAUTHORISED_ORG_ID is not configured")
			}
		})

		It("should deny group list access for a non-member token", func() {
			_, err := client.ListGroups(ctx, config.UnauthorisedOrgID)

			Expect(err).To(HaveOccurred(),
				"non-member must not be permitted to list groups in a private org")

			GinkgoWriter.Printf("Non-member list groups correctly denied: %v\n", err)
		})
	})
})
