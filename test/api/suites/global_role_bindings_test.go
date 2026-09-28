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

	"github.com/unikorn-cloud/identity/test/api"
)

var _ = Describe("Global role bindings", func() {
	var (
		legacyAdminClient  *api.APIClient
		bindingAdminClient *api.APIClient
	)

	Context("When a subject is bound via the legacy platform-administrator flags", func() {
		BeforeEach(func() {
			if config.PlatformAdminToken == "" {
				Skip("PLATFORM_ADMIN_AUTH_TOKEN is required for legacy platform-administrator binding testing")
			}
			legacyAdminConfig := *config
			legacyAdminConfig.AuthToken = config.PlatformAdminToken
			legacyAdminClient = api.NewAPIClientWithConfig(&legacyAdminConfig)
		})

		Describe("an organization the subject is not a member of", func() {
			BeforeEach(func() {
				if config.UnauthorisedOrgID == "" {
					Skip("UNAUTHORISED_ORG_ID is required for global role binding cross-organization testing")
				}
			})

			It("can be read", func(ctx SpecContext) {
				org, err := legacyAdminClient.GetOrganization(ctx, config.UnauthorisedOrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(org.Metadata.Id).To(Equal(config.UnauthorisedOrgID))
			})
		})
	})

	Context("When a subject is bound via --global-role-binding", func() {
		BeforeEach(func() {
			if config.BindingAdminToken == "" {
				Skip("BINDING_ADMIN_AUTH_TOKEN is required for global-role-binding testing")
			}
			bindingAdminConfig := *config
			bindingAdminConfig.AuthToken = config.BindingAdminToken
			bindingAdminClient = api.NewAPIClientWithConfig(&bindingAdminConfig)
		})

		Describe("an organization the subject is not a member of", func() {
			BeforeEach(func() {
				if config.UnauthorisedOrgID == "" {
					Skip("UNAUTHORISED_ORG_ID is required for global role binding cross-organization testing")
				}
			})

			It("can be read", func(ctx SpecContext) {
				org, err := bindingAdminClient.GetOrganization(ctx, config.UnauthorisedOrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(org.Metadata.Id).To(Equal(config.UnauthorisedOrgID))
			})
		})
	})

	Context("When a bound subject is also an organization member", func() {
		BeforeEach(func() {
			if config.BindingAdminToken == "" {
				Skip("BINDING_ADMIN_AUTH_TOKEN is required for global-role-binding testing")
			}
			bindingAdminConfig := *config
			bindingAdminConfig.AuthToken = config.BindingAdminToken
			bindingAdminClient = api.NewAPIClientWithConfig(&bindingAdminConfig)
		})

		Describe("their ACL for that organization", func() {
			It("is global-only — membership resolution is replaced, not merged", func(ctx SpecContext) {
				// The direct e2e detector for replace semantics: an
				// accidentally-additive rewrite would populate Organizations
				// alongside Global instead of replacing membership resolution.
				acl, err := bindingAdminClient.GetOrganizationACL(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(acl.Global).NotTo(BeNil())
				Expect(acl.Organizations).To(BeNil())
			})
		})
	})

	Context("Given an unbound user token", func() {
		BeforeEach(func() {
			if userClient == nil {
				Skip("USER_AUTH_TOKEN is required for unbound user organization list testing")
			}
			if config.UnauthorisedOrgID == "" {
				Skip("UNAUTHORISED_ORG_ID is required for unbound user organization list testing")
			}
		})

		Describe("the organization list", func() {
			It("includes the user's own organization but not organizations they are not a member of", func(ctx SpecContext) {
				// Unscoped ACL resolution error mapping for a direct GET is not
				// this feature's contract; the stable, body-asserting check is
				// list contents.
				//
				// Asserting only the negative (absence of UnauthorisedOrgID)
				// would pass vacuously against an empty or otherwise broken
				// list, so first prove the list was actually populated for
				// this member by requiring their own organization to be
				// present.
				orgs, err := userClient.ListOrganizations(ctx)

				Expect(err).NotTo(HaveOccurred())
				Expect(orgs).To(ContainElement(HaveField("Metadata.Id", config.OrgID)))
				Expect(orgs).NotTo(ContainElement(HaveField("Metadata.Id", config.UnauthorisedOrgID)))
			})
		})
	})
})
