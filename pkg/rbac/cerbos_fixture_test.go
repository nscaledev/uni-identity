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

package rbac_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// This file is the shared fixture for the A5 bindings resolver unit tests and
// the Cerbos decision-parity integration test: ONE dataset covering all four
// actor classes and every parity subtlety the resolver replicates from the
// legacy ACL accumulation (see bindings.go for the file:line citations).

const (
	parityNamespace = "parity-identity-ns"

	// Organizations: A and B are provisioned, ghost has no status namespace
	// (the user path silently skips it, the service-account path errors on
	// it), missing is never created at all.
	parityOrgA       = "parity-org-a"
	parityOrgANS     = "parity-org-a-ns"
	parityOrgB       = "parity-org-b"
	parityOrgBNS     = "parity-org-b-ns"
	parityOrgGhost   = "parity-org-ghost"
	parityOrgMissing = "parity-org-missing"

	// Roles.  parityRoleMissing is deliberately never created: a group
	// referencing it must be a hard consistency error.
	parityRoleGlobalAdmin   = "prole-global-admin"
	parityRoleOrgAdmin      = "prole-org-admin"
	parityRoleMixed         = "prole-mixed"
	parityRoleProjectDev    = "prole-project-dev"
	parityRoleProjectReader = "prole-project-reader"
	parityRoleAuditor       = "prole-auditor"
	parityRoleMissing       = "prole-missing"

	// Groups.  parityGroupGhost is never created: a project referencing it
	// must be silently skipped.
	parityGroupAdmins  = "parity-group-admins"
	parityGroupMixed   = "parity-group-mixed"
	parityGroupDevs    = "parity-group-devs"
	parityGroupDevsDup = "parity-group-devs-dup"
	parityGroupLegacy  = "parity-group-legacy"
	parityGroupBroken  = "parity-group-broken"
	parityGroupGhost   = "parity-group-ghost"
	parityGroupAuditB  = "parity-group-audit-b"

	parityProjectX = "parity-project-x"
	parityProjectY = "parity-project-y"

	// Subjects.  parityAdminSubject is a platform administrator who ALSO has
	// a group membership (parityGroupMixed) that must be ignored.
	parityAdminSubject = "parity-admin@example.com"
	parityAliceSubject = "parity-alice@example.com"
	parityBobSubject   = "parity-bob@example.com"
	parityCarolSubject = "parity-carol@example.com"
	parityErinSubject  = "parity-erin@example.com"

	// Service accounts are pure IDs in group.Spec.ServiceAccountIDs; no
	// ServiceAccount CR is consulted by the legacy resolution.
	paritySA1      = "parity-sa-1"
	paritySALonely = "parity-sa-lonely"
	paritySAGhost  = "parity-sa-ghost"

	// System accounts: the CN → role map lives in rbac.Options.
	paritySystemCN      = "parity-system-cn"
	paritySystemRogueCN = "parity-system-rogue"

	// Carol is a member of parityGroupLegacy via the deprecated UserIDs
	// field, which holds OrganizationUser resource names, so her subject
	// resolves through the User → OrganizationUser chain.
	parityUserCarol    = "parity-user-carol"
	parityOrgUserCarol = "parity-orguser-carol"
)

type parityFixture struct {
	client client.Client
	rbac   *rbac.RBAC

	// roles is the exact Role set the fake client holds, for feeding
	// generate.Generate in the parity integration test.
	roles []unikornv1.Role
}

// parityRoles returns the fixture role catalogue.  parityRoleMixed carries a
// global scope block on purpose: granted via a group it must never surface as
// a global grant (groups yield no global bindings).
func parityRoles() []unikornv1.Role {
	scope := func(name string, operations ...unikornv1.Operation) unikornv1.RoleScope {
		return unikornv1.RoleScope{Name: name, Operations: operations}
	}

	role := func(name string, scopes unikornv1.RoleScopes) unikornv1.Role {
		return unikornv1.Role{
			ObjectMeta: metav1.ObjectMeta{Namespace: parityNamespace, Name: name},
			Spec:       unikornv1.RoleSpec{Scopes: scopes},
		}
	}

	return []unikornv1.Role{
		role(parityRoleGlobalAdmin, unikornv1.RoleScopes{
			Global: []unikornv1.RoleScope{scope("identity:organizations", unikornv1.Read, unikornv1.Update)},
		}),
		role(parityRoleOrgAdmin, unikornv1.RoleScopes{
			Organization: []unikornv1.RoleScope{scope("identity:groups", unikornv1.Create, unikornv1.Read, unikornv1.Update)},
		}),
		role(parityRoleMixed, unikornv1.RoleScopes{
			Global:       []unikornv1.RoleScope{scope("identity:oauth2providers", unikornv1.Read)},
			Organization: []unikornv1.RoleScope{scope("identity:allocations", unikornv1.Read)},
		}),
		role(parityRoleProjectDev, unikornv1.RoleScopes{
			Organization: []unikornv1.RoleScope{scope("identity:projects", unikornv1.Read)},
			Project:      []unikornv1.RoleScope{scope("compute:clusters", unikornv1.Create, unikornv1.Read, unikornv1.Delete)},
		}),
		role(parityRoleProjectReader, unikornv1.RoleScopes{
			Project: []unikornv1.RoleScope{scope("compute:clusters", unikornv1.Read)},
		}),
		role(parityRoleAuditor, unikornv1.RoleScopes{
			Organization: []unikornv1.RoleScope{scope("identity:auditlogs", unikornv1.Read)},
		}),
	}
}

// parityGroups returns the fixture groups across both provisioned orgs.
func parityGroups() []unikornv1.Group {
	subjects := func(ids ...string) []unikornv1.GroupSubject {
		out := make([]unikornv1.GroupSubject, len(ids))
		for i, id := range ids {
			out[i] = unikornv1.GroupSubject{ID: id}
		}

		return out
	}

	group := func(namespace, name string, spec unikornv1.GroupSpec) unikornv1.Group {
		return unikornv1.Group{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Spec:       spec,
		}
	}

	return []unikornv1.Group{
		group(parityOrgANS, parityGroupAdmins, unikornv1.GroupSpec{
			RoleIDs:  []string{parityRoleOrgAdmin},
			Subjects: subjects(parityAliceSubject),
		}),
		// The platform administrator's membership here must be ignored by
		// the resolver's early return.
		group(parityOrgANS, parityGroupMixed, unikornv1.GroupSpec{
			RoleIDs:  []string{parityRoleMixed},
			Subjects: subjects(parityAliceSubject, parityAdminSubject),
		}),
		// Bob and sa-1 hold parityRoleProjectDev through TWO groups (devs
		// and devs-dup for bob) so deduplication is observable.
		group(parityOrgANS, parityGroupDevs, unikornv1.GroupSpec{
			RoleIDs:           []string{parityRoleProjectDev},
			Subjects:          subjects(parityBobSubject),
			ServiceAccountIDs: []string{paritySA1},
		}),
		group(parityOrgANS, parityGroupDevsDup, unikornv1.GroupSpec{
			RoleIDs:  []string{parityRoleProjectDev},
			Subjects: subjects(parityBobSubject),
		}),
		// Carol is a member only via the deprecated UserIDs field, which
		// holds OrganizationUser resource names, not subjects.
		group(parityOrgANS, parityGroupLegacy, unikornv1.GroupSpec{
			RoleIDs: []string{parityRoleProjectReader},
			UserIDs: []string{parityOrgUserCarol},
		}),
		group(parityOrgANS, parityGroupBroken, unikornv1.GroupSpec{
			RoleIDs:  []string{parityRoleMissing},
			Subjects: subjects(parityErinSubject),
		}),
		group(parityOrgBNS, parityGroupAuditB, unikornv1.GroupSpec{
			RoleIDs:  []string{parityRoleAuditor},
			Subjects: subjects(parityAliceSubject),
		}),
	}
}

// newParityFixture builds the fake-client dataset and an RBAC instance
// configured with a platform administrator and a system account.
func newParityFixture(t *testing.T) *parityFixture {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	builder := fake.NewClientBuilder().WithScheme(scheme)

	organization := func(name, namespace string) *unikornv1.Organization {
		return &unikornv1.Organization{
			ObjectMeta: metav1.ObjectMeta{Namespace: parityNamespace, Name: name},
			Status:     unikornv1.OrganizationStatus{Namespace: namespace},
		}
	}

	project := func(namespace, name, organizationID string, groupIDs ...string) *unikornv1.Project {
		return &unikornv1.Project{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace,
				Name:      name,
				Labels:    map[string]string{constants.OrganizationLabel: organizationID},
			},
			Spec: unikornv1.ProjectSpec{GroupIDs: groupIDs},
		}
	}

	objects := []client.Object{
		organization(parityOrgA, parityOrgANS),
		organization(parityOrgB, parityOrgBNS),
		// Ghost has no provisioned namespace: silently skipped for users,
		// a hard error for service accounts homed there.
		organization(parityOrgGhost, ""),

		// parityGroupGhost in project-x does not exist and must be skipped;
		// parityGroupAdmins is linked although its role has no project
		// scopes, mirroring real data where linkage and grants are disjoint.
		project(parityOrgANS, parityProjectX, parityOrgA, parityGroupDevs, parityGroupDevsDup, parityGroupAdmins, parityGroupGhost),
		project(parityOrgANS, parityProjectY, parityOrgA, parityGroupLegacy),

		// Carol's User → OrganizationUser chain for the deprecated UserIDs
		// fallback (resolveOrganizationUserName).
		&unikornv1.User{
			ObjectMeta: metav1.ObjectMeta{Namespace: parityNamespace, Name: parityUserCarol},
			Spec:       unikornv1.UserSpec{Subject: parityCarolSubject, State: unikornv1.UserStateActive},
		},
		&unikornv1.OrganizationUser{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: parityOrgANS,
				Name:      parityOrgUserCarol,
				Labels:    map[string]string{constants.UserLabel: parityUserCarol},
			},
			Spec: unikornv1.OrganizationUserSpec{State: unikornv1.UserStateActive},
		},
	}

	roles := parityRoles()
	for i := range roles {
		objects = append(objects, &roles[i])
	}

	groups := parityGroups()
	for i := range groups {
		objects = append(objects, &groups[i])
	}

	c := builder.WithObjects(objects...).Build()

	options := &rbac.Options{
		PlatformAdministratorSubjects: []string{parityAdminSubject},
		PlatformAdministratorRoleIDs:  []string{parityRoleGlobalAdmin},
		SystemAccountRoleIDs:          map[string]string{paritySystemCN: parityRoleGlobalAdmin},
	}

	return &parityFixture{
		client: c,
		rbac:   rbac.New(c, parityNamespace, options),
		roles:  parityRoles(),
	}
}

// parityUserInfo builds the authorization info a user-account token yields.
func parityUserInfo(subject string, orgIDs ...string) *authorization.Info {
	return &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: subject,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.User,
				OrgIds:  orgIDs,
			},
		},
	}
}

// parityServiceAccountInfo builds the authorization info a service-account
// token yields.
func parityServiceAccountInfo(subject string, orgIDs ...string) *authorization.Info {
	return &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: subject,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.Service,
				OrgIds:  orgIDs,
			},
		},
	}
}

// paritySystemInfo builds the authorization info X.509 middleware yields for
// a system account.
func paritySystemInfo(commonName string) *authorization.Info {
	return &authorization.Info{
		SystemAccount: true,
		Userinfo: &openapi.Userinfo{
			Sub: commonName,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.System,
			},
		},
	}
}
