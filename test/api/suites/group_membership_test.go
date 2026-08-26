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

	kubeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// groupUserIDs flattens the optional user ID list on a group read so specs can
// assert membership without unwrapping the pointer every time.
func groupUserIDs(group *identityopenapi.GroupRead) []string {
	GinkgoHelper()

	if group.Spec.UserIDs == nil {
		return nil
	}

	return *group.Spec.UserIDs
}

// seedGroupMember puts a user into the group out of band and waits for the API
// to observe it.  Adding a member through the API is a grant of the group's
// roles and is refused here by design, so removal specs have to start from
// state the API would not create.
func seedGroupMember(kube kubeclient.Client, orgNamespace, groupID, userID string) {
	GinkgoHelper()

	Expect(api.AddGroupMember(ctx, kube, orgNamespace, groupID, userID)).To(Succeed())

	Eventually(func(g Gomega) {
		group, err := client.GetGroup(ctx, config.OrgID, groupID)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(groupUserIDs(group)).To(ContainElement(userID),
			"the seeded membership is not visible to the API yet")
	}).WithTimeout(30 * time.Second).WithPolling(time.Second).Should(Succeed())
}

// expectGroupEmptiedOfMembers waits for the API to report the group with no
// members and its role intact.  Reads go through the server's informer cache,
// which can still be serving the pre-write state for a moment after a write
// the API server has already accepted.
func expectGroupEmptiedOfMembers(groupID, roleID string) {
	GinkgoHelper()

	Eventually(func(g Gomega) {
		group, err := client.GetGroup(ctx, config.OrgID, groupID)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(groupUserIDs(group)).To(BeEmpty(),
			"the member the admin removed must be gone")
		g.Expect(group.Spec.RoleIDs).To(ContainElement(roleID),
			"the ungrantable role must survive the round-trip")
	}).WithTimeout(30 * time.Second).WithPolling(time.Second).Should(Succeed())
}

var _ = Describe("Group membership changes with ungrantable roles", func() {
	Context("When a group carries a role the admin cannot grant", func() {
		// The role is installed as a custom resource because roles have no
		// write API, and the group has to be installed the same way because
		// the API refuses to create a group carrying a role the caller cannot
		// grant — that is precisely the state a third-party service can
		// leave behind.
		Describe("Given an unlabelled third-party role fixture and a group referencing it", func() {
			var (
				roleID            string
				roleName          string
				groupID           string
				groupName         string
				kube              kubeclient.Client
				identityNamespace string
				orgNamespace      string
			)

			BeforeEach(func() {
				// These specs install role and group CRs directly (roles have
				// no write API, and the API refuses to create a group carrying
				// a role nobody can grant), so they need cluster access. An
				// HTTP-API-only run has no kubeconfig — skip there rather than
				// fail; any other client error is a real fault and fails loudly.
				var err error

				kube, err = api.NewKubernetesClient()
				if errors.Is(err, api.ErrNoKubeconfig) {
					Skip("no kubeconfig: direct-CR fixture specs need cluster access")
				}
				Expect(err).NotTo(HaveOccurred())

				// Adding a member is the operation under test, so the principal
				// to add has to come from the fixtures rather than be invented.
				Expect(config.UserID).NotTo(BeEmpty(),
					"TEST_USER_ID must be set by integration fixtures")

				// The suite already requires TEST_ORG_ID; the organization CR is
				// named by it and carries both namespaces the fixtures need, so
				// discover them rather than take a separate IDENTITY_NAMESPACE.
				identityNamespace, orgNamespace, err = api.OrganizationNamespaces(ctx, kube, config.OrgID)
				Expect(err).NotTo(HaveOccurred())

				roleID = uuid.NewString()
				roleName = "radar-fixture-" + roleID[:8]

				// The role grants an endpoint no built-in role mentions, so no
				// caller in this deployment holds it and it can never be
				// granted by them.
				role := &unikornv1.Role{
					ObjectMeta: metav1.ObjectMeta{
						Name:      roleID,
						Namespace: identityNamespace,
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

			It("should refuse a member addition, naming the role", func() {
				payload := api.NewGroupPayload().
					WithName(groupName).
					WithRoleIDs([]string{roleID}).
					WithUserIDs([]string{config.UserID}).
					Build()

				response, err := client.UpdateGroupWithResponse(ctx, config.OrgID, groupID, payload)
				Expect(err).NotTo(HaveOccurred())
				Expect(response.StatusCode()).To(Equal(http.StatusForbidden))
				Expect(response.JSON403).NotTo(BeNil(),
					"a refusal must come back as a typed forbidden response")
				Expect(response.JSON403.Error).To(Equal(coreopenapi.Forbidden))
				Expect(response.JSON403.ErrorDescription).To(ContainSubstring(roleID),
					"the error must name the role that blocked the addition")
				Expect(response.JSON403.ErrorDescription).To(ContainSubstring(roleName),
					"the error must give the role's display name, not only its ID")
				Expect(response.JSON403.ErrorDescription).To(ContainSubstring("members cannot be added to the group"),
					"the membership guard must be the one that refused, not the role grant guard")

				stored := readGroupResource(kube, orgNamespace, groupID)
				Expect(stored.Spec.UserIDs).To(BeEmpty(),
					"a refused update must leave the group untouched")
				Expect(stored.Spec.Subjects).To(BeEmpty())
				Expect(stored.Spec.RoleIDs).To(ContainElement(roleID))

				GinkgoWriter.Printf("Refused member addition: %s\n", response.JSON403.ErrorDescription)
			})

			It("should allow a member removal, and the role survives", func() {
				seedGroupMember(kube, orgNamespace, groupID, config.UserID)

				payload := api.NewGroupPayload().
					WithName(groupName).
					WithRoleIDs([]string{roleID}).
					WithUserIDs([]string{}).
					Build()

				Expect(client.UpdateGroup(ctx, config.OrgID, groupID, payload)).To(Succeed(),
					"removing a member confers nothing, so it is not gated on the group's roles")

				expectGroupEmptiedOfMembers(groupID, roleID)

				updated, err := client.GetGroup(ctx, config.OrgID, groupID)
				Expect(err).NotTo(HaveOccurred())
				Expect(updated.Metadata.Id).To(Equal(groupID))
				Expect(updated.Metadata.Name).To(Equal(groupName))
			})
		})
	})

	// Without this the whole suite passes with the membership guard replaced by an
	// unconditional refusal: every other group in it carries either no role or an
	// ungrantable one, so no other spec can tell "refused because the role is
	// ungrantable" apart from "refused always".
	Context("When a group carries a role the admin can grant", func() {
		Describe("Given a role scoped to an endpoint the administrator holds", func() {
			var (
				roleID            string
				groupID           string
				groupName         string
				kube              kubeclient.Client
				identityNamespace string
				orgNamespace      string
			)

			BeforeEach(func() {
				var err error

				kube, err = api.NewKubernetesClient()
				if errors.Is(err, api.ErrNoKubeconfig) {
					Skip("no kubeconfig: direct-CR fixture specs need cluster access")
				}
				Expect(err).NotTo(HaveOccurred())

				Expect(config.UserID).NotTo(BeEmpty(),
					"TEST_USER_ID must be set by integration fixtures")

				identityNamespace, orgNamespace, err = api.OrganizationNamespaces(ctx, kube, config.OrgID)
				Expect(err).NotTo(HaveOccurred())

				roleID = uuid.NewString()

				// identity:groups read is part of the organization
				// administrator's own permission set, so the admin holds
				// everything this role confers and may grant it.
				role := &unikornv1.Role{
					ObjectMeta: metav1.ObjectMeta{
						Name:      roleID,
						Namespace: identityNamespace,
						Labels: map[string]string{
							coreconstants.NameLabel: "grantable-fixture-" + roleID[:8],
						},
					},
					Spec: unikornv1.RoleSpec{
						Scopes: unikornv1.RoleScopes{
							Organization: []unikornv1.RoleScope{{
								Name:       "identity:groups",
								Operations: []unikornv1.Operation{unikornv1.Read},
							}},
						},
					},
				}

				cleanupRole, err := api.InstallFixture(ctx, kube, role)
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(cleanupRole)

				groupID = uuid.NewString()
				groupName = "grantable-group-" + groupID[:8]

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

				waitForFixtureVisibility(roleID, groupID)
			})

			It("should allow a member addition, because the grant traces to a holder", func() {
				payload := api.NewGroupPayload().
					WithName(groupName).
					WithRoleIDs([]string{roleID}).
					WithUserIDs([]string{config.UserID}).
					Build()

				Expect(client.UpdateGroup(ctx, config.OrgID, groupID, payload)).To(Succeed(),
					"the caller holds every permission the group's role confers, so adding a member is a grant it may make")

				stored := readGroupResource(kube, orgNamespace, groupID)
				Expect(stored.Spec.UserIDs).To(ContainElement(config.UserID),
					"the member the admin added must be on the group")
				Expect(stored.Spec.RoleIDs).To(ContainElement(roleID))
			})
		})
	})
})
