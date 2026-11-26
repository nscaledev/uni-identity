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

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/test/api"
)

// expectBadRequest checks a rejection came back as HTTP 400 with the typed
// JSON400 body populated, and that the description names want.
func expectBadRequest(status int, body []byte, json400 *coreopenapi.BadRequestResponse, want string) {
	GinkgoHelper()

	Expect(status).To(Equal(http.StatusBadRequest), "response: %s", body)
	Expect(json400).NotTo(BeNil(), "a bad request must parse into the typed JSON400 body")
	Expect(json400.Error).To(Equal(coreopenapi.InvalidRequest))
	Expect(json400.ErrorDescription).To(ContainSubstring(want))
}

// expectNoUserWithSubject fails if a refused create added the user anyway,
// deleting it first so a regression leaves nothing on a shared environment.
func expectNoUserWithSubject(subject string) {
	GinkgoHelper()

	users, err := client.ListUsers(ctx, config.OrgID)
	Expect(err).NotTo(HaveOccurred())

	for _, user := range users {
		if user.Spec.Subject == subject {
			DeferCleanup(client.DeleteUser, ctx, config.OrgID, user.Metadata.Id)
			Fail("a refused create must not add the user " + subject)
		}
	}
}

// expectNoServiceAccountNamed fails if a refused create added the service
// account anyway, deleting it first so its token does not outlive the spec.
func expectNoServiceAccountNamed(name string) {
	GinkgoHelper()

	if sa := findServiceAccount(func(sa identityopenapi.ServiceAccountRead) bool {
		return sa.Metadata.Name == name
	}); sa != nil {
		DeferCleanup(client.DeleteServiceAccount, ctx, config.OrgID, sa.Metadata.Id)
		Fail("a refused create must not add the service account " + name)
	}
}

func findServiceAccount(match func(identityopenapi.ServiceAccountRead) bool) *identityopenapi.ServiceAccountRead {
	GinkgoHelper()

	serviceAccounts, err := client.ListServiceAccounts(ctx, config.OrgID)
	Expect(err).NotTo(HaveOccurred())

	for i := range serviceAccounts {
		if match(serviceAccounts[i]) {
			return &serviceAccounts[i]
		}
	}

	return nil
}

func expectGroupHasNoMembers(groupID string) {
	GinkgoHelper()

	group, err := client.GetGroup(ctx, config.OrgID, groupID)
	Expect(err).NotTo(HaveOccurred())
	Expect(group.Spec.UserIDs).To(Or(BeNil(), HaveValue(BeEmpty())),
		"a refused write must not add a user to the existing group it named")
	Expect(group.Spec.Subjects).To(Or(BeNil(), HaveValue(BeEmpty())),
		"a refused write must not add a subject, which is what confers the group's roles")
	Expect(group.Spec.ServiceAccountIDs).To(BeEmpty(),
		"a refused write must not add a service account to the existing group it named")
}

// Each payload names an existing group before the missing one, so a write
// that applied the groups it could find before failing shows up as a member
// of the existing group.
var _ = Describe("User and service account group validation", func() {
	var (
		groupID string
		unknown string
	)

	BeforeEach(func() {
		_, groupID = api.CreateGroupWithCleanup(client, ctx, config, api.NewGroupPayload().Build())
		unknown = uuid.NewString()
	})

	Context("When creating a user", func() {
		Describe("Given a group that does not exist in the organization", func() {
			It("should return a bad request naming the group and create nothing", func() {
				subject := api.UserSubject(config, "users-unknown-group")

				response, err := client.CreateUserWithResponse(ctx, config.OrgID,
					api.NewUserPayload(subject).WithGroupIDs([]string{groupID, unknown}).Build())
				Expect(err).NotTo(HaveOccurred())

				if response.JSON201 != nil {
					DeferCleanup(client.DeleteUser, ctx, config.OrgID, response.JSON201.Metadata.Id)
				}

				expectBadRequest(response.StatusCode(), response.Body, response.JSON400, unknown)
				expectNoUserWithSubject(subject)
				expectGroupHasNoMembers(groupID)
			})
		})

		Describe("Given a subject that is not an email address", func() {
			It("should return a bad request and create nothing", func() {
				subject := "not-an-email-" + config.SubjectSuffix

				response, err := client.CreateUserWithResponse(ctx, config.OrgID,
					api.NewUserPayload(subject).WithGroupIDs([]string{groupID}).Build())
				Expect(err).NotTo(HaveOccurred())

				if response.JSON201 != nil {
					DeferCleanup(client.DeleteUser, ctx, config.OrgID, response.JSON201.Metadata.Id)
				}

				expectBadRequest(response.StatusCode(), response.Body, response.JSON400, "subject address invalid")
				expectNoUserWithSubject(subject)
				expectGroupHasNoMembers(groupID)
			})
		})
	})

	Context("When updating a user", func() {
		Describe("Given a group that does not exist in the organization", func() {
			It("should return a bad request naming the group and leave the user unchanged", func() {
				created, userID := api.CreateUserWithCleanup(client, ctx, config,
					api.NewUserPayload(api.UserSubject(config, "users-update-unknown-group")).Build())

				response, err := client.UpdateUserWithResponse(ctx, config.OrgID, userID,
					api.NewUserPayload(created.Spec.Subject).
						WithState(identityopenapi.Suspended).
						WithGroupIDs([]string{groupID, unknown}).
						Build())
				Expect(err).NotTo(HaveOccurred())

				expectBadRequest(response.StatusCode(), response.Body, response.JSON400, unknown)

				stored := readUser(userID)
				Expect(stored.Spec.GroupIDs).To(BeEmpty(), "a refused update must not change the user's groups")
				Expect(stored.Spec.State).To(Equal(created.Spec.State), "a refused update must not change the user's state")
				expectGroupHasNoMembers(groupID)
			})
		})
	})

	Context("When creating a service account", func() {
		Describe("Given a group that does not exist in the organization", func() {
			It("should return a bad request naming the group and create nothing", func() {
				payload := api.NewServiceAccountPayload().WithGroupIDs([]string{groupID, unknown}).Build()

				response, err := client.CreateServiceAccountWithResponse(ctx, config.OrgID, payload)
				Expect(err).NotTo(HaveOccurred())

				if response.JSON201 != nil {
					DeferCleanup(client.DeleteServiceAccount, ctx, config.OrgID, response.JSON201.Metadata.Id)
				}

				expectBadRequest(response.StatusCode(), response.Body, response.JSON400, unknown)
				expectNoServiceAccountNamed(payload.Metadata.Name)
				expectGroupHasNoMembers(groupID)
			})
		})
	})

	Context("When updating a service account", func() {
		Describe("Given a group that does not exist in the organization", func() {
			It("should return a bad request naming the group and leave the service account unchanged", func() {
				payload := api.NewServiceAccountPayload().Build()
				_, saID := api.CreateServiceAccountWithCleanup(client, ctx, config, payload)

				response, err := client.UpdateServiceAccountWithResponse(ctx, config.OrgID, saID,
					api.NewServiceAccountPayload().WithGroupIDs([]string{groupID, unknown}).Build())
				Expect(err).NotTo(HaveOccurred())

				expectBadRequest(response.StatusCode(), response.Body, response.JSON400, unknown)

				stored := findServiceAccount(func(sa identityopenapi.ServiceAccountRead) bool {
					return sa.Metadata.Id == saID
				})
				Expect(stored).NotTo(BeNil())
				Expect(stored.Metadata.Name).To(Equal(payload.Metadata.Name), "a refused update must not rename the service account")
				Expect(stored.Spec.GroupIDs).To(BeEmpty(), "a refused update must not change the service account's groups")
				expectGroupHasNoMembers(groupID)
			})
		})
	})
})
