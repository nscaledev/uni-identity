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
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/test/api"
)

var _ = Describe("Organization Management", func() {
	Context("When updating organizations", func() {
		Describe("Given valid organization", func() {
			It("should update the organization name and persist the change", func() {
				original, err := client.GetOrganization(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				restorePayload := api.NewOrganizationPayload().FromRead(*original).Build()
				updatedPayload := api.NewOrganizationPayload().
					FromRead(*original).
					WithName(original.Metadata.Name + "-updated").
					Build()

				DeferCleanup(func() {
					Expect(client.UpdateOrganization(ctx, config.OrgID, restorePayload)).To(Succeed(),
						"failed to restore organization name — org may be left in a mutated state")
				})

				err = client.UpdateOrganization(ctx, config.OrgID, updatedPayload)

				Expect(err).NotTo(HaveOccurred())

				retrieved, err := client.GetOrganization(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(retrieved.Metadata.Name).To(Equal(updatedPayload.Metadata.Name))
				Expect(retrieved.Metadata.Name).NotTo(Equal(original.Metadata.Name))

				GinkgoWriter.Printf("Updated organization name: %s -> %s\n",
					original.Metadata.Name, retrieved.Metadata.Name)
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return error for non-existent organization", func() {
				original, err := client.GetOrganization(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				err = client.UpdateOrganization(ctx, "invalid-org-id",
					api.NewOrganizationPayload().FromRead(*original).Build())

				Expect(err).To(HaveOccurred())
			})
		})
	})
})

var _ = Describe("Organization Discovery", func() {
	Context("When listing organizations", func() {
		Describe("Given valid authentication", func() {
			It("should return all accessible organizations", func() {
				organizations, err := client.ListOrganizations(ctx)

				Expect(err).NotTo(HaveOccurred())
				Expect(organizations).NotTo(BeEmpty())

				orgIDs := make([]string, len(organizations))
				for i, org := range organizations {
					Expect(org.Metadata).NotTo(BeNil())
					Expect(org.Metadata.Id).NotTo(BeEmpty())
					Expect(org.Metadata.Name).NotTo(BeEmpty())
					orgIDs[i] = org.Metadata.Id
				}

				Expect(orgIDs).To(ContainElement(config.OrgID), "Expected organization ID %s to be present in the list", config.OrgID)
				GinkgoWriter.Printf("Found %d organizations (including test org: %s)\n", len(organizations), config.OrgID)
			})
		})

		Describe("Given invalid authentication", func() {
			It("should reject requests without valid token", func() {
				path := client.GetListOrganizationsPath()

				unauthClient := coreclient.NewAPIClient(config.BaseURL, "", config.RequestTimeout, &api.GinkgoLogger{})
				_, respBody, err := unauthClient.DoRequest(ctx, http.MethodGet, path, nil, http.StatusOK)

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrUnexpectedStatusCode)).To(BeTrue())
				Expect(string(respBody)).To(ContainSubstring("access_denied"))
				GinkgoWriter.Printf("Expected error for missing authentication: %v\n", err)
			})
		})
	})

	Context("When getting organization details", func() {
		Describe("Given valid organization ID", func() {
			It("should return organization details", func() {
				org, err := client.GetOrganization(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(org).NotTo(BeNil())
				Expect(org.Metadata).NotTo(BeNil())
				Expect(org.Metadata.Id).To(Equal(config.OrgID))
				Expect(org.Metadata.Name).NotTo(BeEmpty())

				GinkgoWriter.Printf("Retrieved organization: %s (ID: %s)\n", org.Metadata.Name, org.Metadata.Id)
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return not found error", func() {
				_, err := client.GetOrganization(ctx, "invalid-org-id")

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrUnexpectedStatusCode)).To(BeTrue())
				GinkgoWriter.Printf("Expected error for invalid organization ID: %v\n", err)
			})
		})
	})

	Context("When listing organizations with include", func() {
		// identityopenapi.Quotas and identityopenapi.ProjectsCount are the
		// generated constants of GetApiV1OrganizationsParamsInclude.
		both := identityopenapi.OrganizationListIncludeParameter{string(identityopenapi.Quotas), string(identityopenapi.ProjectsCount)}
		includeBoth := &identityopenapi.GetApiV1OrganizationsParams{Include: &both}

		findOrg := func(items identityopenapi.Organizations, id string) *identityopenapi.OrganizationRead {
			for i := range items {
				if items[i].Metadata.Id == id {
					return &items[i]
				}
			}

			return nil
		}

		// Other specs in this suite create projects and change quotas in the
		// test organization. The assertions therefore use only stable fields
		// and lower bounds.
		expectStableQuotaFields := func(got identityopenapi.QuotaReadList, want identityopenapi.QuotaReadList) {
			Expect(got).To(HaveLen(len(want)))
			for i := range want {
				Expect(got[i].Kind).To(Equal(want[i].Kind))
				Expect(got[i].DisplayName).To(Equal(want[i].DisplayName))
				Expect(got[i].Default).To(Equal(want[i].Default))
				Expect(got[i].Format).To(Equal(want[i].Format))
			}
		}

		Describe("Given a platform administrator", func() {
			var platformAdminClient *api.APIClient

			BeforeEach(func() {
				if config.PlatformAdminToken == "" || config.UserSubjectEmail == "" {
					Skip("PLATFORM_ADMIN_AUTH_TOKEN and TEST_USER_SUBJECT_EMAIL are required")
				}

				cfg := *config
				cfg.AuthToken = config.PlatformAdminToken
				platformAdminClient = api.NewAPIClientWithConfig(&cfg)
			})

			It("returns quotas and a project count for the test organization", func(ctx SpecContext) {
				// The email filter limits the list to the organizations of the
				// fixture user. This keeps the platform administrator query small
				// on a long-lived environment.
				scoped := *includeBoth
				scoped.Email = &config.UserSubjectEmail

				resp, err := platformAdminClient.ListOrganizationsWithResponse(ctx, &scoped)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(resp.JSON200).NotTo(BeNil())

				row := findOrg(*resp.JSON200, config.OrgID)
				Expect(row).NotTo(BeNil())
				Expect(row.QuotasError).To(BeNil())
				Expect(row.Quotas).NotTo(BeNil())
				Expect(row.ProjectsCount).NotTo(BeNil())
				Expect(*row.ProjectsCount).To(BeNumerically(">=", 1))

				quotas, err := platformAdminClient.GetQuotas(ctx, config.OrgID)
				Expect(err).NotTo(HaveOccurred())
				expectStableQuotaFields(*row.Quotas, quotas.Quotas)
			})
		})

		Describe("Given an organization administrator", func() {
			It("returns both extras for its organization", func(ctx SpecContext) {
				resp, err := adminClient.ListOrganizationsWithResponse(ctx, includeBoth)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(resp.JSON200).NotTo(BeNil())

				row := findOrg(*resp.JSON200, config.OrgID)
				Expect(row).NotTo(BeNil())
				Expect(row.Quotas).NotTo(BeNil())
				Expect(row.QuotasError).To(BeNil())
				Expect(row.ProjectsCount).NotTo(BeNil())

				quotas, err := adminClient.GetQuotas(ctx, config.OrgID)
				Expect(err).NotTo(HaveOccurred())
				expectStableQuotaFields(*row.Quotas, quotas.Quotas)
			})
		})

		Describe("Given a user with project-scope project read", func() {
			BeforeEach(func() {
				if userClient == nil {
					Skip("USER_AUTH_TOKEN is required")
				}
			})

			It("returns quotas and a bounded project count", Serial, func(ctx SpecContext) {
				resp, err := userClient.ListOrganizationsWithResponse(ctx, includeBoth)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(resp.JSON200).NotTo(BeNil())

				row := findOrg(*resp.JSON200, config.OrgID)
				Expect(row).NotTo(BeNil())
				Expect(row.Quotas).NotTo(BeNil())
				Expect(row.ProjectsCount).NotTo(BeNil())

				// Another spec creates and deletes projects that this user can see.
				// This spec runs alone, so both reads see the same projects.
				projects, err := userClient.ListProjects(ctx, config.OrgID)
				Expect(err).NotTo(HaveOccurred())

				Expect(*row.ProjectsCount).To(BeNumerically(">=", 1))
				Expect(*row.ProjectsCount).To(BeNumerically("<=", len(projects)))
			})
		})

		Describe("Given no include or an invalid include", func() {
			It("omits every extra without include", func(ctx SpecContext) {
				resp, err := adminClient.ListOrganizationsWithResponse(ctx, &identityopenapi.GetApiV1OrganizationsParams{})
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(resp.JSON200).NotTo(BeNil())
				Expect(*resp.JSON200).NotTo(BeEmpty())

				for _, row := range *resp.JSON200 {
					Expect(row.Quotas).To(BeNil())
					Expect(row.QuotasError).To(BeNil())
					Expect(row.ProjectsCount).To(BeNil())
				}
			})

			It("rejects an unknown value and a comma-separated list", func(ctx SpecContext) {
				for _, raw := range []identityopenapi.OrganizationListIncludeParameter{{"nonsense"}, {"quotas,projectsCount"}} {
					resp, err := adminClient.ListOrganizationsWithResponse(ctx, &identityopenapi.GetApiV1OrganizationsParams{Include: &raw})
					Expect(err).NotTo(HaveOccurred())
					Expect(resp.StatusCode()).To(Equal(http.StatusBadRequest))
					Expect(string(resp.Body)).To(ContainSubstring("invalid_request"))
				}
			})
		})
	})
})
