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

	"github.com/Masterminds/semver/v3"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/unikorn-cloud/identity/test/api"
)

var _ = Describe("Service Version", func() {
	Context("When reading the deployed service version", func() {
		Describe("Given a valid bearer token", func() {
			It("should return the service name and version", func() {
				version, err := client.GetVersion(ctx)
				Expect(err).NotTo(HaveOccurred())

				Expect(version.Name).To(HavePrefix("unikorn-identity"))
				// Releases are stamped with a semver tag, dev builds with a Go
				// pseudo-version (e.g. v0.0.0-20260624115013-59dc5a97ce0b), and
				// unstamped local builds default to 0.0.0; all are valid semver.
				_, semverErr := semver.NewVersion(version.Version)
				Expect(semverErr).NotTo(HaveOccurred(), "service version %q is not valid semver", version.Version)

				GinkgoWriter.Printf("Identity service version: %s %s\n", version.Name, version.Version)
			})
		})

		Describe("Given no Authorization header", func() {
			It("should return unauthorized", func() {
				unauthConfig := *config
				unauthConfig.AuthToken = ""
				unauthClient := api.NewAPIClientWithConfig(&unauthConfig)

				path := unauthClient.GetEndpoints().Version()
				resp, _, err := unauthClient.DoRequest(ctx, http.MethodGet, path, nil, 0)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))

				GinkgoWriter.Printf("Unauthenticated version request returned %d as expected\n", resp.StatusCode)
			})
		})
	})
})
