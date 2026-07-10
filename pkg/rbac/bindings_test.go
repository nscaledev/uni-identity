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

	"github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// The assertions here pin decision PARITY with the legacy ACL accumulation,
// not merely resolver behaviour: each case cites the legacy path it mirrors,
// and a change that breaks one of them is an authorization-semantics change
// that would surface as a legacy/Cerbos verdict divergence in shadow mode.

func TestResolveBindingsPlatformAdministrator(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// The administrator is a member of parityGroupMixed, but the platform
	// administrator path EARLY RETURNS with the configured global roles only
	// (processUserAccountACL's admin short-circuit): memberships must contribute nothing.
	bindings, err := fx.rbac.ResolveBindings(t.Context(), parityUserInfo(parityAdminSubject, parityOrgA))
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{{RoleID: parityRoleGlobalAdmin}}, bindings)
}

func TestResolveBindingsPlatformAdministratorRequiresClaims(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// The nil-claims check runs BEFORE the administrator short-circuit
	// (processUserAccountACL's nil-claims guard), so even an administrator fails without claims.
	info := parityUserInfo(parityAdminSubject)
	info.Userinfo.HttpsunikornCloudOrgauthz = nil

	_, err := fx.rbac.ResolveBindings(t.Context(), info)
	require.ErrorIs(t, err, rbac.ErrNoAuthz)
}

func TestResolveBindingsPlatformAdministratorUnknownRole(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// A configured administrator role that has no Role CR is a hard
	// consistency error (accumulateGlobalPermissions).
	broken := rbac.New(fx.client, parityNamespace, &rbac.Options{
		PlatformAdministratorSubjects: []string{parityAdminSubject},
		PlatformAdministratorRoleIDs:  []string{parityRoleMissing},
	})

	_, err := broken.ResolveBindings(t.Context(), parityUserInfo(parityAdminSubject, parityOrgA))
	require.ErrorIs(t, err, errors.ErrConsistency)
}

func TestResolveBindingsSystemAccount(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// A registered CN maps to exactly one global binding
	// (processSystemAccountACL).
	bindings, err := fx.rbac.ResolveBindings(t.Context(), paritySystemInfo(paritySystemCN))
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{{RoleID: parityRoleGlobalAdmin}}, bindings)
}

func TestResolveBindingsSystemAccountUnregistered(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// An unregistered CN is an ERROR (processSystemAccountACL's map lookup), never an empty
	// result: an empty result would be a silent deny-all that masks a
	// configuration mistake.
	_, err := fx.rbac.ResolveBindings(t.Context(), paritySystemInfo(paritySystemRogueCN))
	require.ErrorIs(t, err, errors.ErrConsistency)
}

func TestResolveBindingsServiceAccount(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// Membership via group.Spec.ServiceAccountIDs yields the org-level
	// binding for every group role AND the project-level binding for each
	// project linked to the group (accumulateOrganizationPermissions and accumulateProjectPermissions).
	bindings, err := fx.rbac.ResolveBindings(t.Context(), parityServiceAccountInfo(paritySA1, parityOrgA))
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{
		{RoleID: parityRoleProjectDev, OrganizationID: parityOrgA},
		{RoleID: parityRoleProjectDev, OrganizationID: parityOrgA, ProjectID: parityProjectX},
	}, bindings)
}

func TestResolveBindingsServiceAccountOrganizationCount(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// Service accounts are bound to exactly one organization
	// (getServiceAccountContext).
	for _, orgIDs := range [][]string{nil, {parityOrgA, parityOrgB}} {
		_, err := fx.rbac.ResolveBindings(t.Context(), parityServiceAccountInfo(paritySA1, orgIDs...))
		require.ErrorIs(t, err, rbac.ErrWrongOrganizationCount)
	}
}

func TestResolveBindingsServiceAccountRequiresClaims(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	info := parityServiceAccountInfo(paritySA1, parityOrgA)
	info.Userinfo.HttpsunikornCloudOrgauthz = nil

	// A nil claims object falls back to the user path in the actor-class
	// dispatch (GetACL treats missing claims as a user account,
	// getUserACLContext), which then fails with ErrNoAuthz (the nil-claims guard).
	_, err := fx.rbac.ResolveBindings(t.Context(), info)
	require.ErrorIs(t, err, rbac.ErrNoAuthz)
}

func TestResolveBindingsServiceAccountUnprovisionedHomeOrg(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// An unprovisioned home organization is a HARD ERROR for service
	// accounts (getOrganizationNamespace via getServiceAccountContext) — deliberately
	// asymmetric with the user path's silent skip below.  Replicated as-is
	// for decision parity.
	_, err := fx.rbac.ResolveBindings(t.Context(), parityServiceAccountInfo(paritySAGhost, parityOrgGhost))
	require.ErrorIs(t, err, rbac.ErrResourceReference)
}

func TestResolveBindingsServiceAccountWithoutGroups(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// No memberships short-circuits to an empty grant set without touching
	// the role catalogue (processServiceAccountACL's zero-groups short-circuit): empty, not an error.
	bindings, err := fx.rbac.ResolveBindings(t.Context(), parityServiceAccountInfo(paritySALonely, parityOrgA))
	require.NoError(t, err)
	require.Empty(t, bindings)
}

func TestResolveBindingsUserAcrossAllOrganizations(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// Alice's claims span org A, the unprovisioned ghost org and org B:
	//
	//   - bindings resolve across ALL organizations (the legacy Allow* reads
	//     the plural acl.Organizations built across all orgs,
	//     handler.go:107/159/194), so the org B auditor grant must appear;
	//   - the ghost org is SILENTLY SKIPPED (the empty-Status.Namespace guard in accumulateOrganizationScopedPermissions);
	//   - parityGroupAdmins is linked to project X, so its role additionally
	//     yields a project binding even though the role carries no project
	//     scopes — the policies decide what the binding grants;
	//   - project X's reference to the nonexistent parityGroupGhost is
	//     silently skipped (accumulateProjectPermissions);
	//   - parityRoleMixed has a global scope block, but groups NEVER yield
	//     global bindings (accumulateGlobalPermissions is never fed group roles): no {prole-mixed} global entry.
	//
	// The exact match also pins the deterministic sorted order.
	bindings, err := fx.rbac.ResolveBindings(t.Context(), parityUserInfo(parityAliceSubject, parityOrgA, parityOrgGhost, parityOrgB))
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{
		{RoleID: parityRoleAuditor, OrganizationID: parityOrgB},
		{RoleID: parityRoleMixed, OrganizationID: parityOrgA},
		{RoleID: parityRoleOrgAdmin, OrganizationID: parityOrgA},
		{RoleID: parityRoleOrgAdmin, OrganizationID: parityOrgA, ProjectID: parityProjectX},
	}, bindings)
}

func TestResolveBindingsUserDeduplicatesAcrossGroups(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// Bob holds parityRoleProjectDev via BOTH parityGroupDevs and
	// parityGroupDevsDup, and both groups are linked to project X: each
	// binding must appear exactly once.
	bindings, err := fx.rbac.ResolveBindings(t.Context(), parityUserInfo(parityBobSubject, parityOrgA))
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{
		{RoleID: parityRoleProjectDev, OrganizationID: parityOrgA},
		{RoleID: parityRoleProjectDev, OrganizationID: parityOrgA, ProjectID: parityProjectX},
	}, bindings)
}

func TestResolveBindingsUserLegacyUserIDsFallback(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// Carol is a member of parityGroupLegacy only through the deprecated
	// UserIDs field, so membership resolves through the User →
	// OrganizationUser chain (resolveOrganizationUserName).
	bindings, err := fx.rbac.ResolveBindings(t.Context(), parityUserInfo(parityCarolSubject, parityOrgA))
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{
		{RoleID: parityRoleProjectReader, OrganizationID: parityOrgA},
		{RoleID: parityRoleProjectReader, OrganizationID: parityOrgA, ProjectID: parityProjectY},
	}, bindings)
}

func TestResolveBindingsUserBrokenRoleReference(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// A member group referencing a nonexistent role is a HARD ERROR
	// (accumulateOrganizationPermissions' role lookup) — the counterpart of the silent unknown-group skip,
	// replicated asymmetry and all.
	_, err := fx.rbac.ResolveBindings(t.Context(), parityUserInfo(parityErinSubject, parityOrgA))
	require.ErrorIs(t, err, errors.ErrConsistency)
}

func TestResolveBindingsUserRequiresClaims(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	info := parityUserInfo(parityAliceSubject, parityOrgA)
	info.Userinfo.HttpsunikornCloudOrgauthz = nil

	_, err := fx.rbac.ResolveBindings(t.Context(), info)
	require.ErrorIs(t, err, rbac.ErrNoAuthz)
}

func TestResolveBindingsUserWithoutOrganizations(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// Empty claims yield an empty grant set (processUserAccountACL's empty-OrgIds loop), not an error.
	bindings, err := fx.rbac.ResolveBindings(t.Context(), parityUserInfo(parityAliceSubject))
	require.NoError(t, err)
	require.Empty(t, bindings)
}

func TestResolveBindingsUserOnlyUnprovisionedOrganization(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// A claims list containing only the unprovisioned org resolves to
	// nothing, silently (the empty-Status.Namespace guard).
	bindings, err := fx.rbac.ResolveBindings(t.Context(), parityUserInfo(parityAliceSubject, parityOrgGhost))
	require.NoError(t, err)
	require.Empty(t, bindings)
}

func TestResolveBindingsUserMissingOrganization(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// An organization in the claims with no Organization CR at all is an
	// error (the organization Get propagates), NOT a skip: only the
	// unprovisioned-namespace case is skipped.
	_, err := fx.rbac.ResolveBindings(t.Context(), parityUserInfo(parityAliceSubject, parityOrgMissing))
	require.Error(t, err)
}
