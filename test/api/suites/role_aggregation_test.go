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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/test/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kubeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// chartRoleID derives a role ID from its name exactly as the chart's
// resource.id helper does, so a fixture can take the ID of a role on the
// aggregation allow-list.
func chartRoleID(name string) string {
	sum := sha256.Sum256([]byte(name))
	s := hex.EncodeToString(sum[:])

	return fmt.Sprintf("f%s-%s-4%s-8%s-%s", s[1:8], s[8:12], s[13:16], s[17:20], s[20:32])
}

func roleByName(roles identityopenapi.Roles, name string) *identityopenapi.RoleRead {
	for i := range roles {
		if roles[i].Metadata.Name == name {
			return &roles[i]
		}
	}

	return nil
}

func holdsEndpoint(endpoints *identityopenapi.AclEndpoints, name string) bool {
	if endpoints == nil {
		return false
	}

	for _, endpoint := range *endpoints {
		if endpoint.Name == name {
			return true
		}
	}

	return false
}

func sourceNames(role *identityopenapi.RoleRead) []string {
	if role.AggregatedFrom == nil {
		return nil
	}

	names := make([]string, 0, len(*role.AggregatedFrom))
	for _, source := range *role.AggregatedFrom {
		names = append(names, source.Name)
	}

	return names
}

// kubeForAggregation returns a cluster client and the identity namespace, or
// skips on an HTTP-API-only run.
func kubeForAggregation() (kubeclient.Client, string) {
	GinkgoHelper()

	kube, err := api.NewKubernetesClient()
	if errors.Is(err, api.ErrNoKubeconfig) {
		Skip("no kubeconfig: role aggregation specs need cluster access")
	}

	Expect(err).NotTo(HaveOccurred())

	identityNamespace, _, err := api.OrganizationNamespaces(ctx, kube, config.OrgID)
	Expect(err).NotTo(HaveOccurred())

	return kube, identityNamespace
}

var _ = Describe("Role Aggregation", func() {
	Context("When reading the built-in roles", func() {
		Describe("Given the role controller has run", func() {
			It("should report each built-in role's sources", func() {
				Eventually(func(g Gomega) {
					roles, err := client.ListRoles(ctx, config.OrgID)
					g.Expect(err).NotTo(HaveOccurred())

					admin := roleByName(roles, "administrator")
					g.Expect(admin).NotTo(BeNil())
					g.Expect(sourceNames(admin)).To(ContainElements("administrator-base", "auditor", "user"))

					reader := roleByName(roles, "reader")
					g.Expect(reader).NotTo(BeNil())
					g.Expect(sourceNames(reader)).To(ConsistOf("reader-base"))

					public := roleByName(roles, "public-administrator")
					if public != nil {
						g.Expect(public.AggregatedFrom).To(BeNil(), "public-administrator never aggregates")
					}
				}).WithTimeout(2 * time.Minute).WithPolling(2 * time.Second).Should(Succeed())
			})
		})
	})

	Context("When a service labels a role for aggregation", func() {
		Describe("Given an allow-listed role labelled aggregate-to-reader", func() {
			var (
				roleID string
				kube   kubeclient.Client
			)

			BeforeEach(func() {
				var identityNamespace string

				kube, identityNamespace = kubeForAggregation()

				// fleet-operator is on the chart's allow-list, and the policy
				// checks the ID, so the fixture takes its real ID.
				roleID = chartRoleID("fleet-operator")

				role := &unikornv1.Role{
					ObjectMeta: metav1.ObjectMeta{
						Name:      roleID,
						Namespace: identityNamespace,
						Labels: map[string]string{
							coreconstants.NameLabel:              "fleet-operator",
							unikornv1.AggregateToLabel("reader"): "true",
						},
						Annotations: map[string]string{
							coreconstants.DescriptionAnnotation: "Fleet operator",
						},
					},
					Spec: unikornv1.RoleSpec{
						Scopes: unikornv1.RoleScopes{
							Organization: []unikornv1.RoleScope{{
								Name:       "radar:topology",
								Operations: []unikornv1.Operation{unikornv1.Read},
							}},
						},
					},
				}

				cleanup, err := api.InstallFixture(ctx, kube, role)
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(cleanup)
			})

			It("should give every built-in role up the chain the role's scopes", func() {
				Eventually(func(g Gomega) {
					roles, err := client.ListRoles(ctx, config.OrgID)
					g.Expect(err).NotTo(HaveOccurred())

					for _, name := range []string{"reader", "user", "auditor", "administrator"} {
						role := roleByName(roles, name)
						g.Expect(role).NotTo(BeNil())

						held := holdsEndpoint(role.Scopes.Organization, "radar:topology") ||
							holdsEndpoint(role.Scopes.Project, "radar:topology")
						g.Expect(held).To(BeTrue(), "%s should hold radar:topology", name)
					}

					g.Expect(sourceNames(roleByName(roles, "reader"))).To(ContainElement("fleet-operator"))
				}).WithTimeout(2 * time.Minute).WithPolling(2 * time.Second).Should(Succeed())
			})

			It("should let an org admin with no other role create a group with it", func() {
				// The admin's ACL is cached for up to a minute, so retry until
				// the aggregated scope reaches it.
				var group *identityopenapi.GroupRead

				Eventually(func() error {
					var err error

					payload := api.NewGroupPayload().
						WithName("fleet-group-" + uuid.NewString()[:8]).
						WithRoleIDs([]string{roleID}).
						Build()

					group, err = adminClient.CreateGroup(ctx, config.OrgID, payload)

					return err
				}).WithTimeout(3*time.Minute).WithPolling(5*time.Second).Should(Succeed(),
					"an org admin must be able to grant a labelled role")

				DeferCleanup(func() {
					Expect(adminClient.DeleteGroup(ctx, config.OrgID, group.Metadata.Id)).To(Succeed())
				})

				Expect(group.Spec.RoleIDs).To(ContainElement(roleID))
			})

			It("should report the administrator as able to grant every labelled role", func() {
				Eventually(func(g Gomega) {
					admin := &unikornv1.Role{}
					g.Expect(kube.Get(ctx, kubeclient.ObjectKey{Namespace: identityNamespaceOf(kube), Name: chartRoleID("administrator")}, admin)).To(Succeed())

					grantable, err := unikornv1core.GetCondition(admin.Status.Conditions, unikornv1.RoleConditionGrantable)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(grantable.Status).To(Equal(metav1.ConditionTrue), grantable.Message)

					available, err := unikornv1core.GetCondition(admin.Status.Conditions, unikornv1core.ConditionAvailable)
					g.Expect(err).NotTo(HaveOccurred())
					g.Expect(available.Status).To(Equal(metav1.ConditionTrue), available.Message)
				}).WithTimeout(2 * time.Minute).WithPolling(2 * time.Second).Should(Succeed())
			})
		})
	})

	Context("When a role breaks the aggregation rules", func() {
		Describe("Given the role-aggregation admission policy", func() {
			var (
				kube              kubeclient.Client
				identityNamespace string
			)

			BeforeEach(func() {
				kube, identityNamespace = kubeForAggregation()
			})

			labelled := func(id string, spec unikornv1.RoleSpec) *unikornv1.Role {
				return &unikornv1.Role{
					ObjectMeta: metav1.ObjectMeta{
						Name:      id,
						Namespace: identityNamespace,
						Labels: map[string]string{
							coreconstants.NameLabel:              "aggregation-policy-fixture",
							unikornv1.AggregateToLabel("reader"): "true",
						},
					},
					Spec: spec,
				}
			}

			orgScope := func(name string) unikornv1.RoleScopes {
				return unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{{Name: name, Operations: []unikornv1.Operation{unikornv1.Read}}}}
			}

			expectRefused := func(role *unikornv1.Role, fragment string) {
				GinkgoHelper()

				err := kube.Create(ctx, role)
				if err == nil {
					DeferCleanup(func() { _ = kube.Delete(ctx, role) })
				}

				Expect(err).To(HaveOccurred(), "the admission policy should refuse this role")
				Expect(err.Error()).To(ContainSubstring(fragment))
			}

			It("should refuse the label on a role that is not on the allow-list", func() {
				expectRefused(labelled(uuid.NewString(), unikornv1.RoleSpec{Scopes: orgScope("radar:topology")}), "allowedSources")
			})

			It("should refuse the label on a protected role", func() {
				expectRefused(labelled(chartRoleID("fleet-operator"), unikornv1.RoleSpec{Protected: true, Scopes: orgScope("radar:topology")}), "protected")
			})

			It("should refuse the label on a role with global scopes", func() {
				expectRefused(labelled(chartRoleID("fleet-operator"), unikornv1.RoleSpec{
					Scopes: unikornv1.RoleScopes{Global: []unikornv1.RoleScope{{Name: "radar:topology", Operations: []unikornv1.Operation{unikornv1.Read}}}},
				}), "global scopes")
			})

			It("should refuse the label on a role with identity:allocations", func() {
				expectRefused(labelled(chartRoleID("fleet-operator"), unikornv1.RoleSpec{Scopes: orgScope("identity:allocations")}), "identity:allocations")
			})

			It("should refuse the label on a role with credential scopes", func() {
				expectRefused(labelled(chartRoleID("fleet-operator"), unikornv1.RoleSpec{Scopes: orgScope("storage:objectstorageendpoints/accesskeys")}), "accesskeys")
			})

			It("should refuse an aggregating role that also sets scopes", func() {
				role := &unikornv1.Role{
					ObjectMeta: metav1.ObjectMeta{
						Name:      uuid.NewString(),
						Namespace: identityNamespace,
						Labels:    map[string]string{coreconstants.NameLabel: "aggregation-policy-fixture"},
					},
					Spec: unikornv1.RoleSpec{
						AggregationRule: &unikornv1.RoleAggregationRule{RoleRefs: []string{chartRoleID("reader-base")}},
						Scopes:          orgScope("radar:topology"),
					},
				}

				expectRefused(role, "must not set spec.scopes")
			})
		})
	})
})

// identityNamespaceOf finds the identity namespace from the test organization.
func identityNamespaceOf(kube kubeclient.Client) string {
	GinkgoHelper()

	identityNamespace, _, err := api.OrganizationNamespaces(ctx, kube, config.OrgID)
	Expect(err).NotTo(HaveOccurred())

	return identityNamespace
}
