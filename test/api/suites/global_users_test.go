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
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/test/api"
)

var _ = Describe("Global users", func() {
	var platformAdminClient *api.APIClient

	Context("When a platform administrator deletes a global user record", func() {
		BeforeEach(func() {
			// DeleteGlobalUser is a global-scope endpoint. client is built
			// from config.AuthToken, an organization-scoped service account,
			// so it cannot carry global scope and every call below would see
			// 403 instead of the outcome under test.
			if config.PlatformAdminToken == "" {
				Skip("PLATFORM_ADMIN_AUTH_TOKEN is required for global user delete testing")
			}

			platformAdminConfig := *config
			platformAdminConfig.AuthToken = config.PlatformAdminToken
			platformAdminClient = api.NewAPIClientWithConfig(&platformAdminConfig)
		})

		Describe("Given the account still holds an organization membership", func() {
			It("should refuse with a conflict and leave the account in place", func() {
				created, membershipID := api.CreateUserWithCleanup(client, ctx, config, api.NewUserPayload().Build())
				accountID := created.Status.GlobalUserId

				// CreateUserWithCleanup removes only the membership. Add a
				// cleanup for the account itself, or this test leaks one on
				// every run.
				//
				// Ginkgo runs DeferCleanup callbacks in reverse order, so this
				// callback runs before CreateUserWithCleanup's own cleanup
				// removes the membership. The membership still exists at that
				// point, in this test, because deleting it is never part of
				// the test body. Remove it here first, or the account delete
				// call sees the same conflict and fails this cleanup. Tolerate
				// not found on both calls, because the run may already have
				// removed one or the other.
				DeferCleanup(func() {
					err := client.DeleteUser(ctx, config.OrgID, membershipID)
					if !errors.Is(err, coreclient.ErrResourceNotFound) {
						Expect(err).NotTo(HaveOccurred())
					}

					err = platformAdminClient.DeleteGlobalUser(ctx, accountID)
					if !errors.Is(err, coreclient.ErrResourceNotFound) {
						Expect(err).NotTo(HaveOccurred())
					}
				})

				Expect(accountID).NotTo(BeEmpty(),
					"the create response is the only place a caller learns the account id")
				Expect(accountID).NotTo(Equal(created.Metadata.Id),
					"the membership and the account are different objects")

				response, err := platformAdminClient.DeleteGlobalUserWithResponse(ctx, accountID)

				Expect(err).NotTo(HaveOccurred())
				Expect(response.StatusCode()).To(Equal(http.StatusConflict))
				Expect(response.JSON409).NotTo(BeNil())

				// The description is the only way to tell this refusal apart
				// from a precondition conflict, which is also a 409.
				Expect(response.JSON409.ErrorDescription).To(Equal("the account holds 1 organization membership"))

				// The membership must survive the refusal, or the refusal
				// did damage of its own.
				users, err := client.ListUsers(ctx, config.OrgID)
				Expect(err).NotTo(HaveOccurred())
				Expect(users).To(ContainElement(HaveField("Metadata.Id", Equal(membershipID))))

				// Delete the account again. The handler reads the account
				// record before it checks either refusal. A second conflict
				// here proves the account record is still there. A 404
				// here would mean the first refusal deleted the account
				// despite the conflict.
				repeat, err := platformAdminClient.DeleteGlobalUserWithResponse(ctx, accountID)

				Expect(err).NotTo(HaveOccurred())
				Expect(repeat.StatusCode()).To(Equal(http.StatusConflict))
				Expect(repeat.JSON409).NotTo(BeNil())
				Expect(repeat.JSON409.ErrorDescription).To(Equal("the account holds 1 organization membership"))
			})
		})

		Describe("Given the account's subject is named by a global role binding", func() {
			It("should refuse with unprocessable content and leave the account in place", func() {
				// ci-legacy-admin@nscale.test is the subject
				// hack/ci/test-values.yaml binds under
				// platformAdministrators.subjects. hack/ci/fixtures/main.go
				// creates that account as a member of this organization and
				// issues its own token as PLATFORM_ADMIN_AUTH_TOKEN, the same
				// token platformAdminClient above already authenticates with.
				// Resolve its globalUserID from the organization user list
				// instead of assuming a value, so this case does not depend
				// on an ID that can change between fixture runs.
				const legacyAdminSubject = "ci-legacy-admin@nscale.test"

				users, err := client.ListUsers(ctx, config.OrgID)
				Expect(err).NotTo(HaveOccurred())

				var admin *identityopenapi.UserRead

				for i := range users {
					if users[i].Spec.Subject == legacyAdminSubject {
						admin = &users[i]

						break
					}
				}

				Expect(admin).NotTo(BeNil(),
					"the platform administrator fixture must be a reachable organization member, or this case cannot run")

				accountID := admin.Status.GlobalUserId
				Expect(accountID).NotTo(BeEmpty())

				// The wire status code is the contract a remote reconciler
				// branches on, not the description text. That is why this
				// refusal is worth an integration test and not only a unit
				// test.
				//
				// The call is deterministic: the global-binding
				// check runs before the membership check in Delete, so this
				// account's own membership state cannot change the outcome.
				// The call is non-destructive: the refusal leaves the
				// account in place, so this case needs no cleanup of its
				// own.
				response, err := platformAdminClient.DeleteGlobalUserWithResponse(ctx, accountID)

				Expect(err).NotTo(HaveOccurred())
				Expect(response.StatusCode()).To(Equal(http.StatusUnprocessableEntity))
				Expect(response.JSON422).NotTo(BeNil())
				Expect(response.JSON422.ErrorDescription).To(Equal("the account subject holds a configured global role binding"))

				// The caller knew only the account id, so the description must not
				// disclose the subject, which is an email address.
				Expect(response.JSON422.ErrorDescription).NotTo(ContainSubstring(legacyAdminSubject))

				survivors, err := client.ListUsers(ctx, config.OrgID)
				Expect(err).NotTo(HaveOccurred())
				Expect(survivors).To(ContainElement(HaveField("Status.GlobalUserId", Equal(accountID))))
			})
		})

		Describe("Given the last membership has been removed", func() {
			It("should delete the account and report not found on a repeat call", func() {
				created, membershipID := api.CreateUserWithCleanup(client, ctx, config, api.NewUserPayload().Build())
				accountID := created.Status.GlobalUserId

				// The body below deletes the account. If it fails before
				// that, this cleanup removes the account, so a failed run
				// leaks nothing. Tolerate not found, because a passing run
				// has already removed it.
				DeferCleanup(func() {
					err := platformAdminClient.DeleteGlobalUser(ctx, accountID)
					if !errors.Is(err, coreclient.ErrResourceNotFound) {
						Expect(err).NotTo(HaveOccurred())
					}
				})

				Expect(client.DeleteUser(ctx, config.OrgID, membershipID)).To(Succeed())

				Expect(platformAdminClient.DeleteGlobalUser(ctx, accountID)).To(Succeed())

				// A retrying rollback calls again. It must see not found and
				// treat that as success, not as a failure to report.
				repeat, err := platformAdminClient.DeleteGlobalUserWithResponse(ctx, accountID)

				Expect(err).NotTo(HaveOccurred())
				Expect(repeat.StatusCode()).To(Equal(http.StatusNotFound))
				Expect(repeat.JSON404).NotTo(BeNil())
				Expect(repeat.JSON404.ErrorDescription).To(Equal("the account does not exist"),
					"only this description means the account is gone")
			})
		})

		Describe("Given an account that was never created", func() {
			It("should report not found", func() {
				response, err := platformAdminClient.DeleteGlobalUserWithResponse(ctx, uuid.NewString())

				Expect(err).NotTo(HaveOccurred())
				Expect(response.StatusCode()).To(Equal(http.StatusNotFound))
				Expect(response.JSON404).NotTo(BeNil())
				Expect(response.JSON404.ErrorDescription).To(Equal("the account does not exist"))
			})
		})
	})

	Context("When a request names an account ID that is not a UUID", func() {
		Describe("Given an organization administrator", func() {
			It("should reject the request with 400 before reaching the handler", func() {
				path := client.GetEndpoints().DeleteGlobalUser("not-a-uuid")

				//nolint:bodyclose // DoRequest handles response body closing internally
				_, body, err := client.DoRequest(ctx, http.MethodDelete, path, nil, http.StatusBadRequest)

				Expect(err).NotTo(HaveOccurred())

				response := &coreopenapi.Error{}
				Expect(json.Unmarshal(body, response)).To(Succeed())
				Expect(response.Error).To(Equal(coreopenapi.InvalidRequest))
			})
		})
	})

	Context("When a principal without global identity:users/global delete deletes a global user record", func() {
		Describe("Given an organization user", func() {
			BeforeEach(func() {
				Expect(userClient).NotTo(BeNil(), "USER_AUTH_TOKEN must be set by integration fixtures")
			})

			It("should be refused", func() {
				response, err := userClient.DeleteGlobalUserWithResponse(ctx, uuid.NewString())

				Expect(err).NotTo(HaveOccurred())
				Expect(response.StatusCode()).To(Equal(http.StatusForbidden))
			})
		})

		Describe("Given an organization administrator", func() {
			It("should be refused", func() {
				// client holds the organization-scoped administrator role.
				// That role has no global scope, so it must not clear the
				// same bar a platform administrator needs.
				response, err := client.DeleteGlobalUserWithResponse(ctx, uuid.NewString())

				Expect(err).NotTo(HaveOccurred())
				Expect(response.StatusCode()).To(Equal(http.StatusForbidden))
			})
		})
	})
})
