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
	"slices"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/test/api"

	kubeclient "sigs.k8s.io/controller-runtime/pkg/client"

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

// readGroupResource reads the Group custom resource straight from the API
// server.  The "left untouched" assertions after a refusal must not go through
// the identity API: it serves groups from an informer cache, so a single
// unretried read can return the pre-write state and pass whether or not the
// refused write actually landed.
func readGroupResource(kube kubeclient.Client, orgNamespace, groupID string) *unikornv1.Group {
	GinkgoHelper()

	group := &unikornv1.Group{}
	Expect(kube.Get(ctx, kubeclient.ObjectKey{Namespace: orgNamespace, Name: groupID}, group)).To(Succeed())

	return group
}

// readUser returns the organization user record, which carries the subject and
// the group memberships a user write has to resend to leave them intact.
func readUser(userID string) identityopenapi.UserRead {
	GinkgoHelper()

	users, err := client.ListUsers(ctx, config.OrgID)
	Expect(err).NotTo(HaveOccurred())

	for i := range users {
		if users[i].Metadata.Id == userID {
			return users[i]
		}
	}

	Fail("user " + userID + " is not a member of the test organization")

	return identityopenapi.UserRead{}
}

var _ = Describe("Group membership with ungrantable roles", func() {
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
				Expect(config.UserID).NotTo(BeEmpty(),
					"TEST_USER_ID must be set by integration fixtures")

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

			It("should refuse a member addition through the groups API, naming the role", func() {
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
					"the membership guard must be the one that refused, not the role grant or removal guard")

				current := readGroupResource(kube, orgNamespace, groupID)
				Expect(current.Spec.UserIDs).To(BeEmpty(),
					"a refused update must leave the group untouched")
				Expect(current.Spec.Subjects).To(BeEmpty())
				Expect(current.Spec.RoleIDs).To(ContainElement(roleID))

				GinkgoWriter.Printf("Refused member addition: %s\n", response.JSON403.ErrorDescription)
			})

			It("should allow a member removal through the groups API, and the role survives", func() {
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
					"the removal guard must be the one that refused, not the membership or role grant guard")

				current := readGroupResource(kube, orgNamespace, groupID)
				Expect(current.Spec.RoleIDs).To(ContainElement(roleID),
					"a refused update must leave the group untouched")

				GinkgoWriter.Printf("Refused role removal: %s\n", response.JSON403.ErrorDescription)
			})

			It("should refuse joining the group through the users API, naming the role", func() {
				user := readUser(config.UserID)

				payload := api.NewUserPayload().
					WithSubject(user.Spec.Subject).
					WithState(user.Spec.State).
					WithGroupIDs(append(slices.Clone(user.Spec.GroupIDs), groupID)).
					Build()

				response, err := client.UpdateUserWithResponse(ctx, config.OrgID, config.UserID, payload)
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
					"the membership guard must be the one that refused, not the role grant or removal guard")

				current := readGroupResource(kube, orgNamespace, groupID)
				Expect(current.Spec.UserIDs).To(BeEmpty(),
					"a refused user write must leave the group untouched")
				Expect(current.Spec.Subjects).To(BeEmpty())

				GinkgoWriter.Printf("Refused user-path member addition: %s\n", response.JSON403.ErrorDescription)
			})

			It("should allow leaving the group through the users API", func() {
				user := readUser(config.UserID)

				seedGroupMember(kube, orgNamespace, groupID, config.UserID)

				payload := api.NewUserPayload().
					WithSubject(user.Spec.Subject).
					WithState(user.Spec.State).
					WithGroupIDs(slices.Clone(user.Spec.GroupIDs)).
					Build()

				updated, err := client.UpdateUser(ctx, config.OrgID, config.UserID, payload)
				Expect(err).NotTo(HaveOccurred())
				Expect(updated.Metadata.Id).To(Equal(config.UserID))
				Expect(updated.Spec.GroupIDs).NotTo(ContainElement(groupID),
					"the user must no longer report the group it just left")

				// Leaving confers nothing, so nothing gates it on the group's
				// roles: the membership really is gone from the group.
				expectGroupEmptiedOfMembers(groupID, roleID)
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
				roleID       string
				groupID      string
				groupName    string
				kube         kubeclient.Client
				orgNamespace string
			)

			BeforeEach(func() {
				Expect(config.Namespace).NotTo(BeEmpty(),
					"IDENTITY_NAMESPACE must be set by integration fixtures")
				Expect(config.UserID).NotTo(BeEmpty(),
					"TEST_USER_ID must be set by integration fixtures")

				var err error

				kube, err = api.NewKubernetesClient()
				Expect(err).NotTo(HaveOccurred())

				roleID = uuid.NewString()

				// identity:groups read is part of the organization
				// administrator's own permission set, so the admin holds
				// everything this role confers and may grant it.
				role := &unikornv1.Role{
					ObjectMeta: metav1.ObjectMeta{
						Name:      roleID,
						Namespace: config.Namespace,
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

				orgNamespace, err = api.OrganizationNamespace(ctx, kube, config.Namespace, config.OrgID)
				Expect(err).NotTo(HaveOccurred())

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
