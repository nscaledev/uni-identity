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

//nolint:revive // dot imports are the standard Ginkgo DSL
package rbac_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	"sigs.k8s.io/yaml"
)

// splitIDNamespace is the UUIDv5 namespace for per-service role IDs. An
// external permissions catalogue refers to the roles by ID, so it must never
// change.
const splitIDNamespace = "6f1c0b5e-8f4b-4a7e-9a39-6d1f2f0e9c11"

type splitService struct {
	Prefixes []string `json:"prefixes"`
	Scopes   []string `json:"scopes"`
}

type builtinRoleSplits struct {
	Roles    []string                `json:"roles"`
	Services map[string]splitService `json:"services"`
	IDs      map[string]string       `json:"ids"`
}

type splitValues struct {
	Roles  map[string]chartRole `json:"roles"`
	Splits builtinRoleSplits    `json:"builtinRoleSplits"`
}

func loadSplitValues() splitValues {
	raw, err := os.ReadFile(filepath.Clean(chartValuesPath))
	Expect(err).NotTo(HaveOccurred())

	var values splitValues

	Expect(yaml.Unmarshal(raw, &values)).To(Succeed())
	Expect(values.Splits.Roles).NotTo(BeEmpty())
	Expect(values.Splits.Services).NotTo(BeEmpty())

	return values
}

// servicesOf returns every service that claims scope. An exact scope name
// wins over a prefix, as in the chart template.
func servicesOf(services map[string]splitService, scope string) []string {
	var exact, prefixed []string

	for name, service := range services {
		if slices.Contains(service.Scopes, scope) {
			exact = append(exact, name)
		}

		for _, prefix := range service.Prefixes {
			if strings.HasPrefix(scope, prefix+":") {
				prefixed = append(prefixed, name)
			}
		}
	}

	if len(exact) > 0 {
		return exact
	}

	return prefixed
}

func splitLevel(in endpointOperations, services map[string]splitService, service string) endpointOperations {
	out := endpointOperations{}

	for scope, operations := range in {
		if slices.Equal(servicesOf(services, scope), []string{service}) {
			out[scope] = operations
		}
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

// splitCopies returns the copies the chart renders, by name. A copy with no
// scopes is not rendered.
func splitCopies(values splitValues) map[string]chartRole {
	copies := map[string]chartRole{}

	for _, name := range values.Splits.Roles {
		original := values.Roles[name]

		for service := range values.Splits.Services {
			var copied chartRole

			copied.Scopes.Organization = splitLevel(original.Scopes.Organization, values.Splits.Services, service)
			copied.Scopes.Project = splitLevel(original.Scopes.Project, values.Splits.Services, service)

			if copied.Scopes.Organization != nil || copied.Scopes.Project != nil {
				copies[name+"-"+service] = copied
			}
		}
	}

	return copies
}

func hasOperation(role chartRole, operation string) bool {
	for _, level := range []endpointOperations{role.Scopes.Global, role.Scopes.Organization, role.Scopes.Project} {
		for _, operations := range level {
			if slices.Contains(operations, operation) {
				return true
			}
		}
	}

	return false
}

func TestBuiltinRoleSplits(t *testing.T) {
	t.Parallel()

	RegisterFailHandler(Fail)
	RunSpecs(t, "Built-in Role Splits Suite")
}

var _ = Describe("Per-service built-in role copies", func() {
	var values splitValues

	BeforeEach(func() {
		values = loadSplitValues()
	})

	Context("When loading the Identity chart defaults", func() {
		Describe("Given the roles to split", func() {
			It("names only unprotected built-in roles with no global scopes", func() {
				for _, name := range values.Splits.Roles {
					role, ok := values.Roles[name]
					Expect(ok).To(BeTrue(), "split role %q is not a built-in role", name)
					Expect(role.Protected).To(BeFalse(), "split role %q is protected", name)
					Expect(role.Scopes.Global).To(BeEmpty(), "split role %q has global scopes", name)
				}
			})

			It("maps every scope to exactly one service", func() {
				for _, name := range values.Splits.Roles {
					role := values.Roles[name]

					for _, level := range []endpointOperations{role.Scopes.Organization, role.Scopes.Project} {
						for scope := range level {
							Expect(servicesOf(values.Splits.Services, scope)).To(HaveLen(1), "role %q scope %q", name, scope)
						}
					}
				}
			})
		})

		Describe("Given the fixed role IDs", func() {
			It("pins every rendered copy to the UUIDv5 of its name, with no stale IDs", func() {
				namespace := uuid.MustParse(splitIDNamespace)
				want := map[string]string{}

				for name := range splitCopies(values) {
					want[name] = uuid.NewSHA1(namespace, []byte(name)).String()
				}

				Expect(values.Splits.IDs).To(Equal(want))
			})

			It("uses each ID once", func() {
				seen := map[string]string{}

				for name, id := range values.Splits.IDs {
					Expect(seen).NotTo(HaveKey(id), "%q and %q share ID %s", name, seen[id], id)
					seen[id] = name
				}
			})
		})
	})

	Context("When granting a copy", func() {
		org := ids.MustParseOrganizationID(organizationID)

		Describe("Given a holder of administrator", func() {
			It("can grant every copy", func() {
				ctx := rbac.NewContext(GinkgoT().Context(), aclForHolder(values.Roles["administrator"]))

				for name, copied := range splitCopies(values) {
					Expect(rbac.AllowRole(ctx, asRole(copied), org)).To(Succeed(), "administrator must grant %q", name)
				}
			})
		})

		Describe("Given a holder of user", func() {
			// user already holds these scopes at organization level, so the
			// copies give nothing user does not have.
			grantable := []string{"administrator-images", "administrator-region"}

			It("cannot grant any other administrator copy", func() {
				ctx := rbac.NewContext(GinkgoT().Context(), aclForHolder(values.Roles["user"]))
				refused := 0

				for name, copied := range splitCopies(values) {
					if !strings.HasPrefix(name, "administrator-") {
						continue
					}

					err := rbac.AllowRole(ctx, asRole(copied), org)

					if slices.Contains(grantable, name) {
						Expect(err).NotTo(HaveOccurred(), "user must grant %q", name)
						continue
					}

					Expect(err).To(HaveOccurred(), "user must not grant %q", name)

					refused++
				}

				Expect(refused).To(BeNumerically(">", 0))
			})
		})

		Describe("Given a holder of auditor", func() {
			It("cannot grant a user copy that needs create", func() {
				ctx := rbac.NewContext(GinkgoT().Context(), aclForHolder(values.Roles["auditor"]))
				refused := 0

				for name, copied := range splitCopies(values) {
					if !strings.HasPrefix(name, "user-") || !hasOperation(copied, "create") {
						continue
					}

					Expect(rbac.AllowRole(ctx, asRole(copied), org)).NotTo(Succeed(), "auditor must not grant %q", name)

					refused++
				}

				Expect(refused).To(BeNumerically(">", 0))
			})
		})
	})
})
