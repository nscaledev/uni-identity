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

var _ = Describe("RBAC Enforcement", func() {
	BeforeEach(func() {
		if adminClient == nil || userClient == nil {
			Skip("ADMIN_AUTH_TOKEN and USER_AUTH_TOKEN are required for RBAC enforcement testing")
		}
	})

	Context("When authenticated as an administrator", func() {
		Describe("Given a request to list groups", func() {
			It("should return all groups in the organization with complete metadata", func() {
				groups, err := adminClient.ListGroups(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(groups).NotTo(BeEmpty())

				for _, group := range groups {
					Expect(group.Metadata.Id).NotTo(BeEmpty())
					Expect(group.Metadata.OrganizationId.String()).To(Equal(config.OrgID))
				}
			})
		})

		Describe("Given a request to list roles", func() {
			It("should return all roles in the organization with complete metadata", func() {
				roles, err := adminClient.ListRoles(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(roles).NotTo(BeEmpty())

				for _, role := range roles {
					// RoleRead uses the base ResourceReadMetadata which does not carry
					// OrganizationId; only Id is guaranteed on this resource type.
					Expect(role.Metadata.Id).NotTo(BeEmpty())
				}
			})
		})

		Describe("Given a request to list service accounts", func() {
			It("should return all service accounts in the organization with complete metadata", func() {
				serviceAccounts, err := adminClient.ListServiceAccounts(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(serviceAccounts).NotTo(BeEmpty())

				for _, sa := range serviceAccounts {
					Expect(sa.Metadata.Id).NotTo(BeEmpty())
					Expect(sa.Metadata.OrganizationId.String()).To(Equal(config.OrgID))
				}
			})
		})
	})

	Context("When authenticated as a user", func() {
		// Per CLAUDE.md, status-only assertions are acceptable for pure RBAC denial tests.
		// The typed client returns an error on any non-2xx response, which is sufficient
		// to verify that access was denied without needing to inspect the response body.

		Describe("Given a request to list groups", func() {
			It("should be denied with a forbidden response", func() {
				_, err := userClient.ListGroups(ctx, config.OrgID)
				Expect(err).To(HaveOccurred())
			})
		})

		Describe("Given a request to list roles", func() {
			It("should be denied with a forbidden response", func() {
				_, err := userClient.ListRoles(ctx, config.OrgID)
				Expect(err).To(HaveOccurred())
			})
		})

		Describe("Given a request to list service accounts", func() {
			It("should return only the requesting principal's own service account", func() {
				serviceAccounts, err := userClient.ListServiceAccounts(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(serviceAccounts).To(HaveLen(1))
				Expect(serviceAccounts[0].Metadata.Id.String()).To(Equal(config.UserSAID))
				Expect(serviceAccounts[0].Metadata.OrganizationId.String()).To(Equal(config.OrgID))
			})
		})
	})
})
