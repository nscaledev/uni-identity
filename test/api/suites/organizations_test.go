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
	"cmp"
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	externalRef0 "github.com/unikorn-cloud/core/pkg/openapi"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	"github.com/unikorn-cloud/identity/pkg/ids"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/test/api"
	"k8s.io/utils/ptr"
)

// sortsAfter reports whether (name, id) sorts strictly after (prevName, prevID)
// in the server order: case-insensitive display name, then display name, then ID.
func sortsAfter(name, id, prevName, prevID string) bool {
	return cmp.Or(
		strings.Compare(strings.ToLower(name), strings.ToLower(prevName)),
		strings.Compare(name, prevName),
		strings.Compare(id, prevID),
	) > 0
}

// walkOrganizationPages walks pages for params through client.  After the
// first request, it follows NextCursor.  Later requests carry only the
// cursor and the original limit, because the filters bind into the cursor.
// It fails the spec if a page repeats an ID or breaks (case-insensitive name,
// name, id) order. It stops after maxPages even if the walk has not
// finished, so large environments stay cheap. It returns every organization
// seen in walk order and the number of pages it requested.  It also returns
// whether the walk finished (the last page had no NextCursor) before it
// reached maxPages.
func walkOrganizationPages(ctx context.Context, client *api.APIClient, params *identityopenapi.GetApiV2OrganizationsParams, maxPages int) (items []identityopenapi.OrganizationListItem, pages int, finished bool) {
	GinkgoHelper()

	limit := params.Limit

	seen := map[string]bool{}
	var lastName, lastID string

	for pages < maxPages {
		pages++

		resp, err := client.ListOrganizationsV2(ctx, params)

		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode()).To(Equal(http.StatusOK))
		Expect(resp.JSON200).NotTo(BeNil())

		for _, org := range resp.JSON200.Items {
			Expect(seen).NotTo(HaveKey(org.Metadata.Id), "organization listed twice")
			seen[org.Metadata.Id] = true

			Expect(sortsAfter(org.Metadata.Name, org.Metadata.Id, lastName, lastID)).To(BeTrue(), "order must be strictly increasing by (case-insensitive name, name, id)")
			lastName, lastID = org.Metadata.Name, org.Metadata.Id

			items = append(items, org)
		}

		if resp.JSON200.Pagination.NextCursor == nil {
			finished = true
			break
		}

		params = &identityopenapi.GetApiV2OrganizationsParams{Cursor: resp.JSON200.Pagination.NextCursor, Limit: limit}
	}

	return items, pages, finished
}

var _ = Describe("Organization Management", func() {
	Context("When updating organizations", func() {
		Describe("Given valid organization", func() {
			It("should update the organization name and persist the change", Serial, func() {
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

// platformAdminClient returns a client that uses the platform-administrator
// token, the only fixture token with global read access. It skips the spec
// when the fixtures did not provide one.
func platformAdminClient() *api.APIClient {
	if config.PlatformAdminToken == "" {
		Skip("PLATFORM_ADMIN_AUTH_TOKEN is required for this check")
	}

	platformAdminConfig := *config
	platformAdminConfig.AuthToken = config.PlatformAdminToken

	return api.NewAPIClientWithConfig(&platformAdminConfig)
}

var _ = Describe("Organization Discovery", func() {
	Context("When listing with the v2 API", func() {
		var testOrgName string

		BeforeEach(func() {
			original, err := client.GetOrganization(ctx, config.OrgID)

			Expect(err).NotTo(HaveOccurred())

			testOrgName = original.Metadata.Name
		})

		Describe("Given no parameters", func() {
			It("should return one page no longer than the configured default", func() {
				resp, err := client.ListOrganizationsV2(ctx, nil)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(resp.JSON200).NotTo(BeNil())
				// The applied default is deployment configuration, so assert the
				// contract range rather than the chart value.
				Expect(resp.JSON200.Pagination.Limit).To(And(BeNumerically(">=", 1), BeNumerically("<=", 500)))
				Expect(len(resp.JSON200.Items)).To(BeNumerically("<=", resp.JSON200.Pagination.Limit))
			})
		})

		Describe("Given a name filter for the test organization", func() {
			It("should return one page containing only the test organization", func() {
				// The suite's default client is a service account that sees
				// one organization, so this filter can never need a second
				// page.  A global reader below covers the cursor-bound walk,
				// because more than one organization is visible to it.
				resp, err := client.ListOrganizationsV2(ctx, &identityopenapi.GetApiV2OrganizationsParams{Name: &testOrgName})

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusOK))
				Expect(resp.JSON200).NotTo(BeNil())
				Expect(resp.JSON200.Pagination.NextCursor).To(BeNil())
				Expect(resp.JSON200.Items).To(ContainElement(HaveField("Metadata.Id", config.OrgID)))

				for _, org := range resp.JSON200.Items {
					Expect(strings.ToLower(org.Metadata.Name)).To(ContainSubstring(strings.ToLower(testOrgName)))
				}
			})
		})

		Describe("Given a global reader walking with limit 1", func() {
			It("should return pages in strictly increasing (name, id) order with no repeats", func() {
				// The suite's default client is a service account that sees one
				// organization, so ordering needs a global reader. The walk has a
				// page cap, so large environments stay cheap.  When an environment
				// has more organizations than the cap, the walk stops at the cap.
				// It does not fail the spec.
				admin := platformAdminClient()

				items, _, _ := walkOrganizationPages(ctx, admin, &identityopenapi.GetApiV2OrganizationsParams{Limit: ptr.To(1)}, 5)

				Expect(len(items)).To(BeNumerically(">=", 2), "the fixtures create at least two organizations")
			})
		})

		Describe("Given a global reader walking a name filter with limit 1", func() {
			// The fixtures create ci-test-org and ci-unauthorised-org-<n>, so
			// at least two organizations match "ci-".
			It("should continue using only the cursor and walk every organization matching the filter once", func() {
				admin := platformAdminClient()

				items, pages, finished := walkOrganizationPages(ctx, admin, &identityopenapi.GetApiV2OrganizationsParams{Name: ptr.To("ci-"), Limit: ptr.To(1)}, 100)

				Expect(pages).To(BeNumerically(">=", 2), "the filter must force at least two pages")
				Expect(len(items)).To(BeNumerically(">=", 2), "at least two organizations match \"ci-\"")

				for _, org := range items {
					Expect(strings.ToLower(org.Metadata.Name)).To(ContainSubstring("ci-"), "the filter bound in the cursor must apply to every page")
				}

				// A long-lived environment can hold more than the page cap of
				// "ci-" organizations, or a test organization with another name.
				// Check completeness only when the walk finished and the test
				// organization matches the filter.
				if finished && strings.Contains(strings.ToLower(testOrgName), "ci-") {
					Expect(items).To(ContainElement(HaveField("Metadata.Id", config.OrgID)))
				}
			})

			It("should accept the same name with the cursor and continue the filtered walk", func() {
				admin := platformAdminClient()
				name := ptr.To("ci-")

				first, err := admin.ListOrganizationsV2(ctx, &identityopenapi.GetApiV2OrganizationsParams{Name: name, Limit: ptr.To(1)})

				Expect(err).NotTo(HaveOccurred())
				Expect(first.StatusCode()).To(Equal(http.StatusOK))
				Expect(first.JSON200).NotTo(BeNil())
				Expect(first.JSON200.Items).To(HaveLen(1))
				Expect(first.JSON200.Pagination.NextCursor).NotTo(BeNil())

				next, err := admin.ListOrganizationsV2(ctx, &identityopenapi.GetApiV2OrganizationsParams{Cursor: first.JSON200.Pagination.NextCursor, Name: name, Limit: ptr.To(1)})

				Expect(err).NotTo(HaveOccurred())
				Expect(next.StatusCode()).To(Equal(http.StatusOK))
				Expect(next.JSON200).NotTo(BeNil())
				Expect(next.JSON200.Items).To(HaveLen(1))
				Expect(next.JSON200.Items[0].Metadata.Id).NotTo(Equal(first.JSON200.Items[0].Metadata.Id))

				for _, org := range slices.Concat(first.JSON200.Items, next.JSON200.Items) {
					Expect(strings.ToLower(org.Metadata.Name)).To(ContainSubstring("ci-"))
				}
			})
		})

		Context("When looking up organizations by ID", func() {
			Describe("Given two known organization IDs", func() {
				It("should return every requested ID a platform admin can see, in the usual order", func() {
					if config.UnauthorisedOrgID == "" {
						Skip("UNAUTHORISED_ORG_ID is required for organization ID lookup testing")
					}

					admin := platformAdminClient()

					orgID, err := ids.ParseOrganizationID(config.OrgID)
					Expect(err).NotTo(HaveOccurred())

					unauthorisedOrgID, err := ids.ParseOrganizationID(config.UnauthorisedOrgID)
					Expect(err).NotTo(HaveOccurred())

					resp, err := admin.ListOrganizationsV2(ctx, &identityopenapi.GetApiV2OrganizationsParams{Id: &[]identityopenapi.OrganizationId{orgID, unauthorisedOrgID}})

					Expect(err).NotTo(HaveOccurred())
					Expect(resp.StatusCode()).To(Equal(http.StatusOK))
					Expect(resp.JSON200).NotTo(BeNil())
					Expect(resp.JSON200.Pagination.NextCursor).To(BeNil())
					Expect(resp.JSON200.Pagination.Limit).To(Equal(2))
					Expect(resp.JSON200.Items).To(HaveLen(2))
					Expect(resp.JSON200.Items).To(ContainElement(HaveField("Metadata.Id", config.OrgID)))
					Expect(resp.JSON200.Items).To(ContainElement(HaveField("Metadata.Id", config.UnauthorisedOrgID)))

					first, second := resp.JSON200.Items[0].Metadata, resp.JSON200.Items[1].Metadata
					Expect(sortsAfter(second.Name, second.Id, first.Name, first.Id)).To(BeTrue(), "results follow the usual (case-insensitive name, name, id) order")
				})

				It("should return only the requested IDs the scoped client can see", func() {
					if config.UnauthorisedOrgID == "" {
						Skip("UNAUTHORISED_ORG_ID is required for organization ID lookup testing")
					}

					orgID, err := ids.ParseOrganizationID(config.OrgID)
					Expect(err).NotTo(HaveOccurred())

					unauthorisedOrgID, err := ids.ParseOrganizationID(config.UnauthorisedOrgID)
					Expect(err).NotTo(HaveOccurred())

					resp, err := client.ListOrganizationsV2(ctx, &identityopenapi.GetApiV2OrganizationsParams{Id: &[]identityopenapi.OrganizationId{orgID, unauthorisedOrgID}})

					Expect(err).NotTo(HaveOccurred())
					Expect(resp.StatusCode()).To(Equal(http.StatusOK))
					Expect(resp.JSON200).NotTo(BeNil())
					Expect(resp.JSON200.Items).To(ContainElement(HaveField("Metadata.Id", config.OrgID)))
					Expect(resp.JSON200.Items).NotTo(ContainElement(HaveField("Metadata.Id", config.UnauthorisedOrgID)))
				})
			})

			Describe("Given id combined with name", func() {
				It("should reject the request", func() {
					orgID, err := ids.ParseOrganizationID(config.OrgID)
					Expect(err).NotTo(HaveOccurred())

					resp, err := client.ListOrganizationsV2(ctx, &identityopenapi.GetApiV2OrganizationsParams{Id: &[]identityopenapi.OrganizationId{orgID}, Name: &testOrgName})

					Expect(err).NotTo(HaveOccurred())
					Expect(resp.StatusCode()).To(Equal(http.StatusBadRequest))
					Expect(resp.JSON400).NotTo(BeNil())
					Expect(resp.JSON400.Error).To(Equal(externalRef0.InvalidRequest))
				})
			})

			Describe("Given an unknown organization ID", func() {
				It("should return an empty page", func() {
					admin := platformAdminClient()

					unknownOrgID, err := ids.ParseOrganizationID(uuid.NewString())
					Expect(err).NotTo(HaveOccurred())

					resp, err := admin.ListOrganizationsV2(ctx, &identityopenapi.GetApiV2OrganizationsParams{Id: &[]identityopenapi.OrganizationId{unknownOrgID}})

					Expect(err).NotTo(HaveOccurred())
					Expect(resp.StatusCode()).To(Equal(http.StatusOK))
					Expect(resp.JSON200).NotTo(BeNil())
					Expect(resp.JSON200.Items).To(BeEmpty())
				})
			})
		})

		Describe("Given invalid parameters", func() {
			It("should reject a limit above the maximum", func() {
				resp, err := client.ListOrganizationsV2(ctx, &identityopenapi.GetApiV2OrganizationsParams{Limit: ptr.To(501)})

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusBadRequest))
				Expect(string(resp.Body)).To(ContainSubstring("invalid_request"))
			})

			It("should reject a malformed cursor", func() {
				resp, err := client.ListOrganizationsV2(ctx, &identityopenapi.GetApiV2OrganizationsParams{Cursor: ptr.To("bm90LWEtY3Vyc29y")})

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusBadRequest))
				Expect(string(resp.Body)).To(ContainSubstring("invalid_request"))
			})

			It("should reject a name that differs from the one bound in a server-issued cursor", func() {
				// A global reader with limit=1 always gets a second page: the
				// fixtures create at least two organizations.
				admin := platformAdminClient()

				first, err := admin.ListOrganizationsV2(ctx, &identityopenapi.GetApiV2OrganizationsParams{Limit: ptr.To(1)})

				Expect(err).NotTo(HaveOccurred())
				Expect(first.StatusCode()).To(Equal(http.StatusOK))
				Expect(first.JSON200).NotTo(BeNil())
				Expect(first.JSON200.Pagination.NextCursor).NotTo(BeNil())
				Expect(first.JSON200.Items).To(HaveLen(1))

				resp, err := admin.ListOrganizationsV2(ctx, &identityopenapi.GetApiV2OrganizationsParams{Cursor: first.JSON200.Pagination.NextCursor, Name: ptr.To("different")})

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusBadRequest))
				Expect(string(resp.Body)).To(ContainSubstring("invalid_request"))

				// The cursor alone continues the walk.
				next, err := admin.ListOrganizationsV2(ctx, &identityopenapi.GetApiV2OrganizationsParams{Cursor: first.JSON200.Pagination.NextCursor})

				Expect(err).NotTo(HaveOccurred())
				Expect(next.StatusCode()).To(Equal(http.StatusOK))
				Expect(next.JSON200).NotTo(BeNil())
				Expect(next.JSON200.Items).NotTo(ContainElement(HaveField("Metadata.Id", first.JSON200.Items[0].Metadata.Id)))
			})

			It("should return not found for an unknown email", func() {
				// Only the platform-administrator token holds global identity:users
				// read.  The suite's default client is organization-scoped and would
				// get 403.
				resp, err := platformAdminClient().ListOrganizationsV2(ctx, &identityopenapi.GetApiV2OrganizationsParams{Email: ptr.To("nobody-" + config.OrgID + "@example.invalid")})

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusNotFound))
				Expect(string(resp.Body)).To(ContainSubstring("not_found"))
			})
		})

		Describe("Given invalid authentication", func() {
			It("should reject requests without valid token", func() {
				unauthConfig := *config
				unauthConfig.AuthToken = ""

				resp, err := api.NewAPIClientWithConfig(&unauthConfig).ListOrganizationsV2(ctx, nil)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode()).To(Equal(http.StatusUnauthorized))
				Expect(string(resp.Body)).To(ContainSubstring("access_denied"))
			})
		})
	})

	Context("When listing with the deprecated v1 API", func() {
		Describe("Given valid authentication", func() {
			It("should signal deprecation", func() {
				orgs, headers, err := client.ListOrganizationsWithHeaders(ctx)

				Expect(err).NotTo(HaveOccurred())
				Expect(headers.Get("Deprecation")).To(Equal("@1790208000"))
				Expect(headers.Get("Link")).To(Equal(`</api/v2/organizations>; rel="successor-version"`))
				Expect(orgs).NotTo(BeEmpty())
			})

			It("should return organizations in ID order for a global reader", func() {
				orgs, _, err := platformAdminClient().ListOrganizationsWithHeaders(ctx)

				Expect(err).NotTo(HaveOccurred())
				Expect(len(orgs)).To(BeNumerically(">=", 2), "the fixtures create at least two organizations")

				for i := 1; i < len(orgs); i++ {
					Expect(orgs[i].Metadata.Id > orgs[i-1].Metadata.Id).To(BeTrue(), "v1 order must be strictly increasing by ID")
				}
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
})
