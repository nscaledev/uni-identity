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
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
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
// Both probes are plain reads: the group through its GET, and the role through
// the roles list, which returns every non-protected role — ungrantable ones
// included, flagged `grantable: false` — so the fixture role appears there
// once the cache holds it.  Neither probe exercises the group-update path
// these specs are about, so a regression there fails inside a spec where it
// belongs, not here as a fixture-visibility timeout blaming the cluster.
func waitForFixtureVisibility(roleID, groupID string) {
	GinkgoHelper()

	Eventually(func(g Gomega) {
		roles, err := client.ListRoles(ctx, config.OrgID)
		g.Expect(err).NotTo(HaveOccurred())

		roleIDs := make([]string, len(roles))
		for i := range roles {
			roleIDs[i] = roles[i].Metadata.Id
		}

		g.Expect(roleIDs).To(ContainElement(roleID),
			"the role fixture is not visible to the API yet")
	}).WithTimeout(30 * time.Second).WithPolling(time.Second).Should(Succeed())

	Eventually(func(g Gomega) {
		group, err := client.GetGroup(ctx, config.OrgID, groupID)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(group.Spec.RoleIDs).To(ContainElement(roleID),
			"the group fixture is not visible to the API yet")
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

			It("should allow dropping the role even though the caller cannot grant it", func() {
				payload := api.NewGroupPayload().
					WithName(groupName).
					WithRoleIDs([]string{}).
					Build()

				Expect(client.UpdateGroup(ctx, config.OrgID, groupID, payload)).To(Succeed(),
					"removals are not grant-checked: dropping a role confers nothing on anybody")

				stored := readGroupResource(kube, orgNamespace, groupID)
				Expect(stored.Spec.RoleIDs).To(BeEmpty(),
					"the removal the caller asked for must have been applied")
			})
		})
	})
})
