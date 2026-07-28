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

// Platform projects (Spec.Platform=true) are Envir-managed and must be invisible to customers
// (D16/D21). adminClient holds the organization administrator role, which grants identity:projects
// at organization scope but NOT identity:projects:platform, so it stands in for any customer
// principal the platform project must be hidden from. The fixtures seed one platform project and
// export TEST_PLATFORM_PROJECT_ID; these specs skip when it is absent.
var _ = Describe("Platform projects", func() {
	BeforeEach(func() {
		if config.PlatformProjectID == "" {
			Skip("TEST_PLATFORM_PROJECT_ID is not set by integration fixtures")
		}
	})

	Context("When a customer without identity:projects:platform acts on a platform project", func() {
		// A hidden platform project must return 404, never 403: a 403 would be an existence oracle
		// (403 = a real platform project lives here, 404 = nothing here). coreclient.ErrResourceNotFound
		// is returned only for a 404, so asserting it proves the response was 404 and not 403.
		Describe("Given a read of the platform project", func() {
			It("responds as not found rather than forbidden", func() {
				_, err := adminClient.GetProject(ctx, config.OrgID, config.PlatformProjectID)

				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue(),
					"a hidden platform project must look nonexistent (404), got: %v", err)
			})
		})

		Describe("Given an update of the platform project", func() {
			It("responds as not found rather than forbidden", func() {
				err := adminClient.UpdateProject(ctx, config.OrgID, config.PlatformProjectID,
					api.NewProjectPayload().Build())

				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue(),
					"a hidden platform project must not be mutable and must look nonexistent (404), got: %v", err)
			})
		})

		Describe("Given a delete of the platform project", func() {
			It("responds as not found rather than forbidden", func() {
				// The gate returns 404 before any deletion runs, so this does not consume the fixture.
				err := adminClient.DeleteProject(ctx, config.OrgID, config.PlatformProjectID)

				Expect(errors.Is(err, coreclient.ErrResourceNotFound)).To(BeTrue(),
					"a hidden platform project must not be deletable and must look nonexistent (404), got: %v", err)
			})
		})
	})

	Context("When a customer without identity:projects:platform reads their ACL", func() {
		Describe("Given the organization ACL", func() {
			It("does not leak platform-project IDs", func() {
				acl, err := adminClient.GetOrganizationACL(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(acl).NotTo(BeNil())

				if acl.Organization != nil {
					Expect(acl.Organization.PlatformProjects).To(BeNil(),
						"platform-project IDs must not appear in a customer's organization ACL")
				}

				if acl.Organizations != nil {
					for _, org := range *acl.Organizations {
						Expect(org.PlatformProjects).To(BeNil(),
							"platform-project IDs must not appear in a customer's organizations ACL")
					}
				}

				if acl.Projects != nil {
					for _, project := range *acl.Projects {
						Expect(project.Id).NotTo(Equal(config.PlatformProjectID),
							"the platform project must not appear in the member-project list")
					}
				}
			})
		})
	})
})
