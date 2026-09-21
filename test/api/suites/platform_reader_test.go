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
	"bytes"
	"encoding/json"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/unikorn-cloud/identity/test/api"
)

// The platform-reader canary (ID-399). This is a role-content test, not a
// production-path stand-in: production binds platform-reader issuer-wide via a
// wildcard on the staff issuer, which KinD cannot exercise (no external JWKS
// issuer; wildcards are rejected on the uni sentinel). The fixture instead
// binds the role to ci-platform-reader@nscale.test via an EXACT uni binding,
// which bypasses the wildcard read-clamp — so a write verb sneaking into the
// role definition fails these tests instead of being silently masked.
var _ = Describe("Platform reader role", func() {
	var readerClient *api.APIClient

	// Only the specs that authenticate AS the bound subject need the reader
	// token. The protected-role specs below use adminClient, so gating them on
	// this token too would silently drop protection coverage in an environment
	// that has admin credentials but no reader fixture.
	requireReaderClient := func() {
		if config.PlatformReaderToken == "" {
			Skip("PLATFORM_READER_AUTH_TOKEN is required for platform-reader testing")
		}

		readerConfig := *config
		readerConfig.AuthToken = config.PlatformReaderToken
		readerClient = api.NewAPIClientWithConfig(&readerConfig)
	}

	Context("When a bound subject reads across organizations", func() {
		BeforeEach(requireReaderClient)

		Describe("an organization the subject is not a member of", func() {
			BeforeEach(func() {
				if config.UnauthorisedOrgID == "" {
					Skip("UNAUTHORISED_ORG_ID is required for cross-organization read testing")
				}
			})

			It("can be read", func(ctx SpecContext) {
				org, err := readerClient.GetOrganization(ctx, config.UnauthorisedOrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(org.Metadata.Id).To(Equal(config.UnauthorisedOrgID))
			})
		})
	})

	Context("When a bound subject attempts a write", func() {
		BeforeEach(requireReaderClient)

		Describe("a group create in an organization", func() {
			It("is denied", func(ctx SpecContext) {
				// No cleanup: the request is denied, so nothing is created —
				// the same shape as rbac_matrix_test.go's forbidden-request
				// pattern. DoRequest returns an error on any non-403 status,
				// so asserting on err alone pins the status.
				payload := api.NewGroupPayload().Build()

				bodyBytes, err := json.Marshal(payload)
				Expect(err).NotTo(HaveOccurred())

				// Pure RBAC case: status-only assertion via the typed
				// client's DoRequest, the rbac_matrix_test.go pattern.
				_, _, err = readerClient.DoRequest(ctx, http.MethodPost,
					api.NewEndpoints().ListGroups(config.OrgID), bytes.NewReader(bodyBytes), http.StatusForbidden)

				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	Context("When the bound subject's ACL is resolved", func() {
		BeforeEach(requireReaderClient)

		Describe("the global endpoint grants", func() {
			It("contain no excluded scope and no non-read operation", func(ctx SpecContext) {
				// In-repo proxy for "access-key reads return 403 at the
				// storage service": the ACL identity serves to storage simply
				// lacks the scope. Replace-vs-merge semantics are pinned by
				// the global role bindings suite, not re-asserted here.
				acl, err := readerClient.GetOrganizationACL(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())
				Expect(acl.Global).NotTo(BeNil())

				// Positive anchor so the negative loop below cannot pass
				// vacuously on an empty ACL.
				Expect(*acl.Global).To(ContainElement(HaveField("Name", "identity:organizations")))

				for _, endpoint := range *acl.Global {
					Expect(endpoint.Name).NotTo(Equal("storage:objectstorageendpoints/accesskeys"),
						"excluded credential scope leaked into the ACL")

					for _, op := range endpoint.Operations {
						Expect(string(op)).To(Equal("read"),
							"endpoint %s grants non-read operation %s", endpoint.Name, op)
					}
				}
			})
		})
	})

	Context("Given the role is protected", func() {
		Describe("the user-facing role listing", func() {
			It("does not contain platform-reader", func(ctx SpecContext) {
				roles, err := adminClient.ListRoles(ctx, config.OrgID)

				Expect(err).NotTo(HaveOccurred())

				// Positive anchor (a known user-facing role) so the negative
				// loop cannot pass vacuously on an empty or broken listing —
				// the rbac_matrix_test.go pattern.
				Expect(roles).To(ContainElement(HaveField("Metadata.Name", "reader")))

				for _, role := range roles {
					Expect(role.Metadata.Name).NotTo(Equal("platform-reader"))
				}
			})
		})

		Describe("granting it through a group", func() {
			BeforeEach(func() {
				if config.PlatformReaderRoleID == "" {
					Skip("TEST_PLATFORM_READER_ROLE_ID is required for non-grantability testing")
				}
			})

			It("is rejected even for an administrator", func(ctx SpecContext) {
				// Uses the ADMIN client so the request passes endpoint RBAC
				// and reaches the protected-role guard itself
				// (pkg/handler/groups/client.go validateRoleIDs, which
				// returns HTTPForbidden for protected roles); the reader
				// client would be rejected earlier, proving nothing about
				// protection.
				// No cleanup: the guard denies the request, so nothing is
				// created (see the denial case above).
				payload := api.NewGroupPayload().
					WithRoleIDs([]string{config.PlatformReaderRoleID}).
					Build()

				bodyBytes, err := json.Marshal(payload)
				Expect(err).NotTo(HaveOccurred())

				// Pure RBAC case: status-only assertion via DoRequest.
				_, _, err = adminClient.DoRequest(ctx, http.MethodPost,
					api.NewEndpoints().ListGroups(config.OrgID), bytes.NewReader(bodyBytes), http.StatusForbidden)

				Expect(err).NotTo(HaveOccurred())
			})
		})
	})
})
