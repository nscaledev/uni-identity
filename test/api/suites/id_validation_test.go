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
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Path parameter ID validation", func() {
	Context("When an organization ID path parameter is not a valid UUID", func() {
		Describe("Given a non-UUID organization ID", func() {
			It("should reject the request with 400 before reaching the handler", func() {
				path := client.GetEndpoints().GetOrganization("not-a-uuid")

				//nolint:bodyclose // DoRequest handles response body closing internally
				_, body, err := client.DoRequest(ctx, http.MethodGet, path, nil, http.StatusBadRequest)

				Expect(err).NotTo(HaveOccurred())
				Expect(string(body)).To(ContainSubstring("invalid_request"))
			})
		})
	})

	Context("When a project ID path parameter is not a valid UUID", func() {
		Describe("Given a valid organization ID but non-UUID project ID", func() {
			It("should reject the request with 400 before reaching the handler", func() {
				path := client.GetEndpoints().GetProject(config.OrgID, "not-a-uuid")

				//nolint:bodyclose // DoRequest handles response body closing internally
				_, body, err := client.DoRequest(ctx, http.MethodGet, path, nil, http.StatusBadRequest)

				Expect(err).NotTo(HaveOccurred())
				Expect(string(body)).To(ContainSubstring("invalid_request"))
			})
		})
	})

	Context("When both organization and project ID path parameters are not valid UUIDs", func() {
		Describe("Given non-UUID values for both", func() {
			It("should reject the request with 400 before reaching the handler", func() {
				path := client.GetEndpoints().GetProject("not-a-uuid", "also-not-a-uuid")

				//nolint:bodyclose // DoRequest handles response body closing internally
				_, body, err := client.DoRequest(ctx, http.MethodGet, path, nil, http.StatusBadRequest)

				Expect(err).NotTo(HaveOccurred())
				Expect(string(body)).To(ContainSubstring("invalid_request"))
			})
		})
	})

	Context("When a group ID path parameter is not a valid UUID", func() {
		Describe("Given a valid organization ID but non-UUID group ID", func() {
			It("should reject the request with 400 before reaching the handler", func() {
				path := client.GetEndpoints().GetGroup(config.OrgID, "not-a-uuid")

				//nolint:bodyclose // DoRequest handles response body closing internally
				_, body, err := client.DoRequest(ctx, http.MethodGet, path, nil, http.StatusBadRequest)

				Expect(err).NotTo(HaveOccurred())
				Expect(string(body)).To(ContainSubstring("invalid_request"))
			})
		})
	})

	Context("When a service account ID path parameter is not a valid UUID", func() {
		Describe("Given a valid organization ID but non-UUID service account ID", func() {
			It("should reject the request with 400 before reaching the handler", func() {
				path := client.GetEndpoints().GetServiceAccount(config.OrgID, "not-a-uuid")

				//nolint:bodyclose // DoRequest handles response body closing internally
				_, body, err := client.DoRequest(ctx, http.MethodDelete, path, nil, http.StatusBadRequest)

				Expect(err).NotTo(HaveOccurred())
				Expect(string(body)).To(ContainSubstring("invalid_request"))
			})
		})
	})

	Context("When a user ID path parameter is not a valid UUID", func() {
		Describe("Given a valid organization ID but non-UUID user ID", func() {
			It("should reject the request with 400 before reaching the handler", func() {
				path := client.GetEndpoints().GetUser(config.OrgID, "not-a-uuid")

				//nolint:bodyclose // DoRequest handles response body closing internally
				_, body, err := client.DoRequest(ctx, http.MethodDelete, path, nil, http.StatusBadRequest)

				Expect(err).NotTo(HaveOccurred())
				Expect(string(body)).To(ContainSubstring("invalid_request"))
			})
		})
	})

	Context("When an OAuth2 provider ID path parameter is not a valid UUID", func() {
		Describe("Given a valid organization ID but non-UUID provider ID", func() {
			It("should reject the request with 400 before reaching the handler", func() {
				path := client.GetEndpoints().GetOauth2Provider(config.OrgID, "not-a-uuid")

				//nolint:bodyclose // DoRequest handles response body closing internally
				_, body, err := client.DoRequest(ctx, http.MethodDelete, path, nil, http.StatusBadRequest)

				Expect(err).NotTo(HaveOccurred())
				Expect(string(body)).To(ContainSubstring("invalid_request"))
			})
		})
	})

	Context("When an allocation ID path parameter is not a valid UUID", func() {
		Describe("Given valid organization and project IDs but a non-UUID allocation ID", func() {
			It("should reject the request with 400 before reaching the handler", func() {
				path := client.GetEndpoints().GetAllocation(config.OrgID, config.ProjectID, "not-a-uuid")

				//nolint:bodyclose // DoRequest handles response body closing internally
				_, body, err := client.DoRequest(ctx, http.MethodGet, path, nil, http.StatusBadRequest)

				Expect(err).NotTo(HaveOccurred())
				Expect(string(body)).To(ContainSubstring("invalid_request"))
			})
		})
	})
})
