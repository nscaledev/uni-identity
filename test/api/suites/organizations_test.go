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
	"github.com/unikorn-cloud/identity/test/api"
)

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
})

var _ = Describe("Project Discovery", func() {
	Context("When listing projects", func() {
		Describe("Given valid organization", func() {
			It("should return all projects in the organization", func() {
				projects, err := client.ListProjects(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(projects).NotTo(BeEmpty())

				projectIDs := make([]string, len(projects))
				for i, project := range projects {
					Expect(project.Metadata).NotTo(BeNil())
					Expect(project.Metadata.Id).NotTo(BeEmpty())
					Expect(project.Metadata.Name).NotTo(BeEmpty())
					projectIDs[i] = project.Metadata.Id
				}

				Expect(projectIDs).To(ContainElement(config.ProjectID), "Expected project ID %s to be present in the list", config.ProjectID)
				GinkgoWriter.Printf("Found %d projects in organization %s (including test project: %s)\n", len(projects), config.OrgID, config.ProjectID)
			})
		})

		Describe("Given invalid organization ID", func() {
			It("should return error for non-existent organization", func() {
				_, err := client.ListProjects(ctx, "invalid-org-id")

				Expect(err).To(HaveOccurred())
				GinkgoWriter.Printf("Expected error for invalid organization ID: %v\n", err)
			})
		})
	})

	Context("When getting project details", func() {
		Describe("Given valid project ID", func() {
			It("should return project details", func() {
				project, err := client.GetProject(ctx, config.OrgID, config.ProjectID)

				Expect(err).NotTo(HaveOccurred())
				Expect(project).NotTo(BeNil())
				Expect(project.Metadata).NotTo(BeNil())
				Expect(project.Metadata.Id).To(Equal(config.ProjectID))
				Expect(project.Metadata.Name).NotTo(BeEmpty())

				GinkgoWriter.Printf("Retrieved project: %s (ID: %s)\n", project.Metadata.Name, project.Metadata.Id)
			})
		})

		Describe("Given invalid project ID", func() {
			It("should return not found error", func() {
				_, err := client.GetProject(ctx, config.OrgID, "invalid-project-id")

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrUnexpectedStatusCode)).To(BeTrue())
				GinkgoWriter.Printf("Expected error for invalid project ID: %v\n", err)
			})
		})
	})
})
