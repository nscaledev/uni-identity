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

// From nscale-auth0-tests: console-audit-view.spec.ts §8 — ported to Go/Ginkgo.
// Tests that an audit-role token can read all console-visible resources but cannot
// mutate groups, organizations, or quotas.

//nolint:revive,testpackage // dot imports and package naming standard for Ginkgo
package suites

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/test/api"
)

var _ = Describe("Console - Audit View Permissions (Read)", func() {
	BeforeEach(func() {
		if auditClient == nil {
			Skip("AUDIT_AUTH_TOKEN is not configured — skipping audit read-access tests")
		}
	})

	// §8.1
	Describe("Given a request to list organizations", func() {
		It("audit token should succeed and return at least one organization", func() {
			orgs, err := auditClient.ListOrganizations(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(orgs).NotTo(BeEmpty())

			GinkgoWriter.Printf("Audit: listed %d organizations\n", len(orgs))
		})
	})

	// §8.2
	Describe("Given a request to view organization details", func() {
		It("audit token should return organization with matching ID", func() {
			org, err := auditClient.GetOrganization(ctx, config.OrgID)

			Expect(err).NotTo(HaveOccurred())
			Expect(org).NotTo(BeNil())
			Expect(org.Metadata.Id).To(Equal(config.OrgID))

			GinkgoWriter.Printf("Audit: fetched org %s\n", config.OrgID)
		})
	})

	// §8.3
	Describe("Given a request to list users", func() {
		It("audit token should succeed and return a list", func() {
			users, err := auditClient.ListUsers(ctx, config.OrgID)

			Expect(err).NotTo(HaveOccurred())
			// An empty list is valid — the assertion is that access is permitted (no error).
			GinkgoWriter.Printf("Audit: listed %d users\n", len(users))
		})
	})

	// §8.4
	Describe("Given a request to list roles", func() {
		It("audit token should succeed and return at least one role", func() {
			roles, err := auditClient.ListRoles(ctx, config.OrgID)

			Expect(err).NotTo(HaveOccurred())
			Expect(roles).NotTo(BeEmpty())

			GinkgoWriter.Printf("Audit: listed %d roles\n", len(roles))
		})
	})

	// §8.5
	Describe("Given a request to list groups", func() {
		It("audit token should succeed and return a list", func() {
			groups, err := auditClient.ListGroups(ctx, config.OrgID)

			Expect(err).NotTo(HaveOccurred())
			GinkgoWriter.Printf("Audit: listed %d groups\n", len(groups))
		})
	})

	// §8.6
	Describe("Given a request to list projects", func() {
		It("audit token should succeed and return a list", func() {
			projects, err := auditClient.ListProjects(ctx, config.OrgID)

			Expect(err).NotTo(HaveOccurred())
			GinkgoWriter.Printf("Audit: listed %d projects\n", len(projects))
		})
	})

	// §8.7
	Describe("Given a request to list service accounts", func() {
		It("audit token should succeed and return a list", func() {
			sas, err := auditClient.ListServiceAccounts(ctx, config.OrgID)

			Expect(err).NotTo(HaveOccurred())
			GinkgoWriter.Printf("Audit: listed %d service accounts\n", len(sas))
		})
	})

	// §8.8
	Describe("Given a request to read quotas", func() {
		It("audit token should succeed and return a quotas object", func() {
			quotas, err := auditClient.GetQuotas(ctx, config.OrgID)

			Expect(err).NotTo(HaveOccurred())
			Expect(quotas).NotTo(BeNil())

			GinkgoWriter.Printf("Audit: read quotas (%d entries)\n", len(quotas.Quotas))
		})
	})
})

var _ = Describe("Console - Audit View Permissions (Write Denied)", func() {
	BeforeEach(func() {
		if auditClient == nil {
			Skip("AUDIT_AUTH_TOKEN is not configured — skipping audit write-denied tests")
		}
	})

	// §8.9 audit token cannot create groups
	Describe("Given a POST to create a group", func() {
		It("audit token should be denied with a forbidden response", func() {
			_, err := auditClient.CreateGroup(ctx, config.OrgID,
				api.NewGroupPayload().Build())

			Expect(err).To(HaveOccurred(),
				"audit token must not be allowed to create groups")

			GinkgoWriter.Printf("Audit group create correctly denied: %v\n", err)
		})
	})

	// §8.10 audit token cannot update groups
	Describe("Given a PUT to update a group", func() {
		It("audit token should be denied with a forbidden response", func() {
			_, groupID := api.CreateGroupWithCleanup(adminClient, ctx, config,
				api.NewGroupPayload().Build())

			_, err := auditClient.UpdateGroup(ctx, config.OrgID, groupID,
				api.NewGroupPayload().Build())

			Expect(err).To(HaveOccurred(),
				"audit token must not be allowed to update groups")

			GinkgoWriter.Printf("Audit group update correctly denied: %v\n", err)
		})
	})

	// §8.11 audit token cannot delete groups
	Describe("Given a DELETE to remove a group", func() {
		It("audit token should be denied with a forbidden response", func() {
			_, groupID := api.CreateGroupWithCleanup(adminClient, ctx, config,
				api.NewGroupPayload().Build())

			err := auditClient.DeleteGroup(ctx, config.OrgID, groupID)

			Expect(err).To(HaveOccurred(),
				"audit token must not be allowed to delete groups")

			GinkgoWriter.Printf("Audit group delete correctly denied: %v\n", err)
		})
	})

	// §8.12 audit token cannot update organization
	Describe("Given a PUT to update the organization", func() {
		It("audit token should be denied with a forbidden response", func() {
			original, err := adminClient.GetOrganization(ctx, config.OrgID)
			Expect(err).NotTo(HaveOccurred())

			err = auditClient.UpdateOrganization(ctx, config.OrgID,
				api.NewOrganizationPayload().FromRead(*original).Build())

			Expect(err).To(HaveOccurred(),
				"audit token must not be allowed to update the organization")

			GinkgoWriter.Printf("Audit org update correctly denied: %v\n", err)
		})
	})

	// §8.13 audit token cannot update quotas
	Describe("Given a PUT to update quotas", func() {
		It("audit token should be denied with a forbidden response", func() {
			_, err := auditClient.SetQuotas(ctx, config.OrgID,
				identityopenapi.QuotasWrite{})

			Expect(err).To(HaveOccurred(),
				"audit token must not be allowed to update quotas")

			GinkgoWriter.Printf("Audit quota update correctly denied: %v\n", err)
		})
	})
})
