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
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/test/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kubeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// waitForFixtureVisibility blocks until the API server has observed both
// fixtures.  The server reads roles and groups through informer caches, so a
// spec that calls the API straight after creating the custom resources can see
// a 404 on the group, or have its write rejected as naming a role that does
// not exist, until those caches catch up.  Every spec here must pass through
// this before its first API call.
//
// Group visibility is checked with a read.  Role visibility needs a write:
// the role is deliberately one nobody can grant, so it is filtered out of the
// role list and there is nothing to read it back from.  Re-sending the group's
// own role list is the probe, because it is refused while the role is missing
// from the cache and accepted once it lands, and it changes nothing either
// way.
func waitForFixtureVisibility(roleID, groupID, groupName string) {
	GinkgoHelper()

	Eventually(func(g Gomega) {
		group, err := client.GetGroup(ctx, config.OrgID, groupID)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(group.Spec.RoleIDs).To(ContainElement(roleID),
			"the group fixture is not visible to the API yet")
	}).WithTimeout(30 * time.Second).WithPolling(time.Second).Should(Succeed())

	payload := api.NewGroupPayload().
		WithName(groupName).
		WithRoleIDs([]string{roleID}).
		Build()

	Eventually(func(g Gomega) {
		response, err := client.UpdateGroupWithResponse(ctx, config.OrgID, groupID, payload)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(response.StatusCode()).To(Equal(http.StatusOK),
			"the role fixture is not visible to the API yet: %s", string(response.Body))
	}).WithTimeout(30 * time.Second).WithPolling(time.Second).Should(Succeed())
}

// readGroupResource reads the Group custom resource straight from the API
// server.  Assertions about what a write did or did not store must not go
// through the identity API: it serves groups from an informer cache, so a
// single unretried read can return the pre-write state and pass whether or not
// the write actually landed.
func readGroupResource(kube kubeclient.Client, orgNamespace, groupID string) *unikornv1.Group {
	GinkgoHelper()

	group := &unikornv1.Group{}
	Expect(kube.Get(ctx, kubeclient.ObjectKey{Namespace: orgNamespace, Name: groupID}, group)).To(Succeed())

	return group
}

var _ = Describe("Group role changes with ungrantable roles", func() {
	Context("When a group carries a role the admin cannot grant", func() {
		// The role is installed as a custom resource because roles have no
		// write API, and the group has to be installed the same way because
		// the API refuses to create a group carrying a role the caller cannot
		// grant — that is precisely the state a third-party service can
		// leave behind.
		Describe("Given an unlabelled third-party role fixture and a group referencing it", func() {
			var (
				roleID       string
				roleName     string
				groupID      string
				groupName    string
				kube         kubeclient.Client
				orgNamespace string
			)

			BeforeEach(func() {
				Expect(config.Namespace).NotTo(BeEmpty(),
					"IDENTITY_NAMESPACE must be set by integration fixtures")

				var err error

				kube, err = api.NewKubernetesClient()
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

				orgNamespace, err = api.OrganizationNamespace(ctx, kube, config.Namespace, config.OrgID)
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

				waitForFixtureVisibility(roleID, groupID, groupName)
			})

			It("should accept an edit that resends the existing role list unchanged", func() {
				renamed := groupName + "-renamed"

				payload := api.NewGroupPayload().
					WithName(renamed).
					WithRoleIDs([]string{roleID}).
					Build()

				Expect(client.UpdateGroup(ctx, config.OrgID, groupID, payload)).To(Succeed(),
					"a write that adds no role must not be grant-checked against roles the group already carries")

				stored := readGroupResource(kube, orgNamespace, groupID)
				Expect(stored.Labels[coreconstants.NameLabel]).To(Equal(renamed),
					"the rename the caller asked for must have been applied")
				Expect(stored.Spec.RoleIDs).To(ContainElement(roleID),
					"the ungrantable role must survive the round-trip")
			})

			It("should refuse to drop the role, naming it in the error", func() {
				payload := api.NewGroupPayload().
					WithName(groupName).
					WithRoleIDs([]string{}).
					Build()

				response, err := client.UpdateGroupWithResponse(ctx, config.OrgID, groupID, payload)
				Expect(err).NotTo(HaveOccurred())
				Expect(response.StatusCode()).To(Equal(http.StatusForbidden))
				Expect(response.JSON403).NotTo(BeNil(),
					"a refusal must come back as a typed forbidden response")
				Expect(response.JSON403.Error).To(Equal(coreopenapi.Forbidden))
				Expect(response.JSON403.ErrorDescription).To(ContainSubstring(roleID),
					"the error must name the role that blocked the update")
				Expect(response.JSON403.ErrorDescription).To(ContainSubstring(roleName),
					"the error must give the role's display name, not only its ID")
				Expect(response.JSON403.ErrorDescription).To(ContainSubstring("cannot be removed from the group"),
					"the removal guard must be the one that refused, not the role grant guard")

				stored := readGroupResource(kube, orgNamespace, groupID)
				Expect(stored.Spec.RoleIDs).To(ContainElement(roleID),
					"a refused update must leave the group untouched")

				GinkgoWriter.Printf("Refused role removal: %s\n", response.JSON403.ErrorDescription)
			})
		})
	})
})
