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

var _ = Describe("Readiness", func() {
	Context("When probing a serving replica", func() {
		Describe("Given no Authorization header", func() {
			It("should report ready", func() {
				unauthConfig := *config
				unauthConfig.AuthToken = ""
				unauthClient := api.NewAPIClientWithConfig(&unauthConfig)

				readiness, err := unauthClient.GetReadiness(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(readiness.Ready).To(BeTrue())
				Expect(readiness.Reason).To(BeNil())
			})
		})
	})
})
