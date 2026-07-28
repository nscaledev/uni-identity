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
	"net/http"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/test/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// waitForFixtureVisibility blocks until the API server has observed both
// fixtures.  The server reads roles and groups through an informer cache, so a
// spec that calls the API straight after creating the custom resources can see
// "role ID ... does not exist" or a 404 on the group until the cache catches
// up.  Every spec here must pass through this before its first API call.
func waitForFixtureVisibility(roleID, groupID string) {
	GinkgoHelper()

	Eventually(func(g Gomega) {
		roles, err := client.ListRoles(ctx, config.OrgID)
		g.Expect(err).NotTo(HaveOccurred())

		roleIDs := make([]string, 0, len(roles))
		for _, role := range roles {
			roleIDs = append(roleIDs, role.Metadata.Id)
		}

		g.Expect(roleIDs).To(ContainElement(roleID),
			"the role fixture is not visible to the API yet")

		group, err := client.GetGroup(ctx, config.OrgID, groupID)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(group.Spec.RoleIDs).To(ContainElement(roleID),
			"the group fixture is not visible to the API yet")
	}).WithTimeout(30 * time.Second).WithPolling(time.Second).Should(Succeed())
}

var _ = Describe("Group membership with ungrantable roles", func() {
	Context("When a group carries a role the admin cannot grant", func() {
		// The role is installed as a custom resource because roles have no
		// write API, and the group has to be installed the same way because
		// the API refuses to create a group carrying a role the caller cannot
		// grant — that is precisely the state a third party service leaves
		// behind, and the state this fix is about (ID-368).
		Describe("Given an unlabelled third-party role fixture and a group referencing it", func() {
			var (
				roleID    string
				roleName  string
				groupID   string
				groupName string
			)

			BeforeEach(func() {
				Expect(config.Namespace).NotTo(BeEmpty(),
					"IDENTITY_NAMESPACE must be set by integration fixtures")
				Expect(config.UserID).NotTo(BeEmpty(),
					"TEST_USER_ID must be set by integration fixtures")

				kube, err := api.NewKubernetesClient()
				Expect(err).NotTo(HaveOccurred())

				roleID = uuid.NewString()
				roleName = "radar-fixture-" + roleID[:8]

				// The role grants an endpoint no built-in role mentions, so no
				// caller in this deployment holds it and it can never be
				// granted or removed by them.
				role := &unikornv1.Role{
					ObjectMeta: metav1.ObjectMeta{
						Name:      roleID,
						Namespace: config.Namespace,
						Labels: map[string]string{
							coreconstants.NameLabel: roleName,
						},
					},
					Spec: unikornv1.RoleSpec{
						Scopes: unikornv1.RoleScopes{
							Organization: []unikornv1.RoleScope{{
								Name:       "radar:things",
								Operations: []unikornv1.Operation{unikornv1.Read},
							}},
						},
					},
				}

				cleanupRole, err := api.InstallFixture(ctx, kube, role)
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(cleanupRole)

				orgNamespace, err := api.OrganizationNamespace(ctx, kube, config.Namespace, config.OrgID)
				Expect(err).NotTo(HaveOccurred())

				groupID = uuid.NewString()
				groupName = "radar-group-" + groupID[:8]

				// These are the labels the handler stamps on a group it
				// creates itself: the display name and the organization
				// placement scope.  Both are enforced by validating admission
				// policies.
				group := &unikornv1.Group{
					ObjectMeta: metav1.ObjectMeta{
						Name:      groupID,
						Namespace: orgNamespace,
						Labels: map[string]string{
							coreconstants.NameLabel:         groupName,
							coreconstants.OrganizationLabel: config.OrgID,
						},
					},
					Spec: unikornv1.GroupSpec{
						RoleIDs: []string{roleID},
					},
				}

				cleanupGroup, err := api.InstallFixture(ctx, kube, group)
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(cleanupGroup)

				GinkgoWriter.Printf("Installed role %s (%s) and group %s (%s)\n",
					roleName, roleID, groupName, groupID)

				waitForFixtureVisibility(roleID, groupID)
			})

			It("should list the ungrantable role, flagged as not grantable", func() {
				roles, err := client.ListRoles(ctx, config.OrgID)
				Expect(err).NotTo(HaveOccurred())

				var (
					fixtureRole   *identityopenapi.RoleRead
					administrator *identityopenapi.RoleRead
				)

				for i := range roles {
					if roles[i].Metadata.Id == roleID {
						fixtureRole = &roles[i]
					}

					if roles[i].Metadata.Name == "administrator" {
						administrator = &roles[i]
					}
				}

				Expect(fixtureRole).NotTo(BeNil(),
					"ungrantable roles must still be listed so clients can resolve group role IDs")
				Expect(fixtureRole.Metadata.Name).To(Equal(roleName))
				Expect(fixtureRole.Grantable).To(BeFalse(),
					"a role whose permissions the caller does not hold is not grantable")

				Expect(administrator).NotTo(BeNil(), "the administrator role should be listed")
				Expect(administrator.Grantable).To(BeTrue(),
					"an organization administrator holds every administrator permission, so can grant it")
			})

			It("should let the admin change members while the role rides along", func() {
				payload := api.NewGroupPayload().
					WithName(groupName).
					WithRoleIDs([]string{roleID}).
					WithUserIDs([]string{config.UserID}).
					Build()

				Expect(client.UpdateGroup(ctx, config.OrgID, groupID, payload)).To(Succeed(),
					"re-sending an existing ungrantable role must not be treated as a grant")

				updated, err := client.GetGroup(ctx, config.OrgID, groupID)
				Expect(err).NotTo(HaveOccurred())
				Expect(updated.Metadata.Id).To(Equal(groupID))
				Expect(updated.Metadata.Name).To(Equal(groupName))
				Expect(updated.Spec.UserIDs).NotTo(BeNil())
				Expect(*updated.Spec.UserIDs).To(ContainElement(config.UserID),
					"the member the admin added must be present")
				Expect(updated.Spec.RoleIDs).To(ContainElement(roleID),
					"the ungrantable role must survive the round-trip")
			})

			It("should refuse to drop the role, naming it in the error", func() {
				payload := api.NewGroupPayload().
					WithName(groupName).
					WithRoleIDs([]string{}).
					Build()

				resp, body, err := client.UpdateGroupRaw(ctx, config.OrgID, groupID, payload, http.StatusForbidden)
				Expect(err).NotTo(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusForbidden))

				var apiError coreopenapi.Error
				Expect(json.Unmarshal(body, &apiError)).To(Succeed())
				Expect(apiError.Error).To(Equal(coreopenapi.Forbidden))
				Expect(apiError.ErrorDescription).To(ContainSubstring(roleID),
					"the error must name the role that blocked the update")
				Expect(apiError.ErrorDescription).To(ContainSubstring(roleName),
					"the error must give the role's display name, not only its ID")

				current, err := client.GetGroup(ctx, config.OrgID, groupID)
				Expect(err).NotTo(HaveOccurred())
				Expect(current.Spec.RoleIDs).To(ContainElement(roleID),
					"a refused update must leave the group untouched")

				GinkgoWriter.Printf("Refused role removal: %s\n", apiError.ErrorDescription)
			})
		})
	})
})
