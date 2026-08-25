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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos"
	idconstants "github.com/unikorn-cloud/identity/pkg/constants"
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
		PlatformAdministratorSubjects: []rbac.PlatformAdministratorSubject{{Issuer: parityAdminIssuer, Subject: parityAdminSubject}},
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

// The global-role-binding cases below mirror processUserAccountACL's binding
// path (resolveGlobalRoleBindings / resolveGroupRoleBindings feeding
// accumulateMatchedBindings): a matched binding REPLACES membership
// resolution entirely, and the bound roles are granted globally.

func TestResolveBindingsGlobalRoleBindingReplacesMemberships(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// Without a binding Alice resolves four membership bindings
	// (TestResolveBindingsUserAcrossAllOrganizations). An exact subject
	// binding makes accumulateMatchedBindings return early, so memberships
	// contribute NOTHING and only the bound role appears, globally.
	r := fx.withOptions(func(o *rbac.Options) {
		o.GlobalRoleBindings = rbac.GlobalRoleBindingsValue{{
			Issuer:  idconstants.UNISentinel,
			Subject: parityAliceSubject,
			RoleIDs: []string{parityRoleAuditor},
		}}
	})

	bindings, err := r.ResolveBindings(t.Context(), parityUserInfo(parityAliceSubject, parityOrgA, parityOrgB))
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{{RoleID: parityRoleAuditor}}, bindings)
}

func TestResolveBindingsGlobalGroupRoleBindingReplacesMemberships(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// A group binding grants its roles' FULL global scopes
	// (accumulateMatchedBindings feeds group bindings to
	// accumulateGlobalPermissions, not the read-clamped variant) and replaces
	// membership resolution just as a subject binding does.
	r := fx.withOptions(func(o *rbac.Options) {
		o.GlobalGroupRoleBindings = rbac.GlobalGroupRoleBindingsValue{{
			Issuer:  parityExternalIssuer,
			Group:   parityExternalGroup,
			RoleIDs: []string{parityRoleAuditor},
		}}
	})

	info := parityUserInfo(parityAliceSubject, parityOrgA)
	info.SrcIss = parityExternalIssuer
	info.Groups = []string{parityExternalGroup}

	bindings, err := r.ResolveBindings(t.Context(), info)
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{{RoleID: parityRoleAuditor}}, bindings)
}

func TestResolveBindingsGlobalRoleBindingWrongIssuerFallsThrough(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// resolveGlobalRoleBindings requires b.Issuer == srcIss. Alice's token is
	// UNI-local, so an external-issuer binding must not match, and membership
	// resolution proceeds unchanged.
	r := fx.withOptions(func(o *rbac.Options) {
		o.GlobalRoleBindings = rbac.GlobalRoleBindingsValue{{
			Issuer:  parityExternalIssuer,
			Subject: parityAliceSubject,
			RoleIDs: []string{parityRoleAuditor},
		}}
	})

	bindings, err := r.ResolveBindings(t.Context(), parityUserInfo(parityAliceSubject, parityOrgA))
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{
		{RoleID: parityRoleMixed, OrganizationID: parityOrgA},
		{RoleID: parityRoleOrgAdmin, OrganizationID: parityOrgA},
		{RoleID: parityRoleOrgAdmin, OrganizationID: parityOrgA, ProjectID: parityProjectX},
	}, bindings)
}

func TestResolveBindingsGlobalRoleBindingSubjectIsCaseSensitive(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// resolveGlobalRoleBindings compares trimmed subjects with ==, not
	// EqualFold: the case-insensitive platform-admin match was replaced by
	// generic bindings. A case-mismatched binding must NOT match, so
	// memberships still resolve.
	r := fx.withOptions(func(o *rbac.Options) {
		o.GlobalRoleBindings = rbac.GlobalRoleBindingsValue{{
			Issuer:  idconstants.UNISentinel,
			Subject: strings.ToUpper(parityAliceSubject),
			RoleIDs: []string{parityRoleAuditor},
		}}
	})

	bindings, err := r.ResolveBindings(t.Context(), parityUserInfo(parityAliceSubject, parityOrgA))
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{
		{RoleID: parityRoleMixed, OrganizationID: parityOrgA},
		{RoleID: parityRoleOrgAdmin, OrganizationID: parityOrgA},
		{RoleID: parityRoleOrgAdmin, OrganizationID: parityOrgA, ProjectID: parityProjectX},
	}, bindings)
}

func TestResolveBindingsWildcardBindingIsReadClamped(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// Legacy clamps a WILDCARD subject binding to read
	// (accumulateGlobalReadPermissions). The clamped binding activates the
	// role's read-only global bucket, so the write scopes of
	// parityRoleGlobalAdmin (identity:organizations read+update) stay
	// withheld, exactly as the legacy path withholds them.
	r := fx.withOptions(func(o *rbac.Options) {
		o.GlobalRoleBindings = rbac.GlobalRoleBindingsValue{{
			Issuer:   parityExternalIssuer,
			Subject:  rbac.WildcardSubject,
			RoleIDs:  []string{parityRoleGlobalAdmin},
			Wildcard: true,
		}}
	})

	info := parityUserInfo(parityAliceSubject, parityOrgA)
	info.SrcIss = parityExternalIssuer

	bindings, err := r.ResolveBindings(t.Context(), info)
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{{RoleID: parityRoleGlobalAdmin, GlobalRead: true}}, bindings)
}

func TestResolveBindingsWildcardBindingMissingRoleIsAConsistencyError(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// The clamp still validates the role catalogue: accumulateGlobalReadPermissions
	// errors on a role with no Role CR, so a silent skip here would under-grant
	// and mask the configuration mistake.
	r := fx.withOptions(func(o *rbac.Options) {
		o.GlobalRoleBindings = rbac.GlobalRoleBindingsValue{{
			Issuer:   parityExternalIssuer,
			Subject:  rbac.WildcardSubject,
			RoleIDs:  []string{parityRoleMissing},
			Wildcard: true,
		}}
	})

	info := parityUserInfo(parityAliceSubject, parityOrgA)
	info.SrcIss = parityExternalIssuer

	_, err := r.ResolveBindings(t.Context(), info)
	require.ErrorIs(t, err, errors.ErrConsistency)
}

func TestResolveBindingsDuplicateBindingsCompactToOnePerForm(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// Three matched bindings name ONE role in two forms: two wildcard entries
	// clamp it, an exact entry does not. normalizeBindings must return one
	// binding per form. slices.Compact merges neighbours only, so the
	// comparator has to order the clamp flag as well: without that tiebreaker
	// the three bindings compare equal, their order comes from the input rather
	// than the data, and a duplicate survives into the rendered request.
	r := fx.withOptions(func(o *rbac.Options) {
		o.GlobalRoleBindings = rbac.GlobalRoleBindingsValue{
			{
				Issuer:   parityExternalIssuer,
				Subject:  rbac.WildcardSubject,
				RoleIDs:  []string{parityRoleGlobalAdmin},
				Wildcard: true,
			},
			{
				Issuer:   parityExternalIssuer,
				Subject:  rbac.WildcardSubject,
				RoleIDs:  []string{parityRoleGlobalAdmin},
				Wildcard: true,
			},
			{
				Issuer:  parityExternalIssuer,
				Subject: parityAliceSubject,
				RoleIDs: []string{parityRoleGlobalAdmin},
			},
		}
	})

	info := parityUserInfo(parityAliceSubject, parityOrgA)
	info.SrcIss = parityExternalIssuer

	bindings, err := r.ResolveBindings(t.Context(), info)
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{
		{RoleID: parityRoleGlobalAdmin},
		{RoleID: parityRoleGlobalAdmin, GlobalRead: true},
	}, bindings)
}

func TestResolveBindingsWildcardAndGroupBindingOnOneRoleKeepBothForms(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// The same role reached by a wildcard subject binding and by a group
	// binding grants two DIFFERENT things: the clamped read bucket and the full
	// global bucket. Both must survive normalization, in a stable order, so the
	// group path keeps the writes it is deliberately not clamped out of.
	r := fx.withOptions(func(o *rbac.Options) {
		o.GlobalRoleBindings = rbac.GlobalRoleBindingsValue{{
			Issuer:   parityExternalIssuer,
			Subject:  rbac.WildcardSubject,
			RoleIDs:  []string{parityRoleGlobalAdmin},
			Wildcard: true,
		}}
		o.GlobalGroupRoleBindings = rbac.GlobalGroupRoleBindingsValue{{
			Issuer:  parityExternalIssuer,
			Group:   parityExternalGroup,
			RoleIDs: []string{parityRoleGlobalAdmin},
		}}
	})

	info := parityUserInfo(parityAliceSubject, parityOrgA)
	info.SrcIss = parityExternalIssuer
	info.Groups = []string{parityExternalGroup}

	bindings, err := r.ResolveBindings(t.Context(), info)
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{
		{RoleID: parityRoleGlobalAdmin},
		{RoleID: parityRoleGlobalAdmin, GlobalRead: true},
	}, bindings)
}

func TestResolveBindingsSubjectAndGroupBindingsUnion(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// accumulateMatchedBindings loops BOTH lists, so a subject binding and a
	// group binding that match together grant the union, not whichever won.
	r := fx.withOptions(func(o *rbac.Options) {
		o.GlobalRoleBindings = rbac.GlobalRoleBindingsValue{{
			Issuer:  parityExternalIssuer,
			Subject: parityAliceSubject,
			RoleIDs: []string{parityRoleGlobalAdmin},
		}}
		o.GlobalGroupRoleBindings = rbac.GlobalGroupRoleBindingsValue{{
			Issuer:  parityExternalIssuer,
			Group:   parityExternalGroup,
			RoleIDs: []string{parityRoleMixed},
		}}
	})

	bindings, err := r.ResolveBindings(t.Context(), parityExternalUserInfo(parityAliceSubject, parityOrgA))
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{
		{RoleID: parityRoleGlobalAdmin},
		{RoleID: parityRoleMixed},
	}, bindings)
}

func TestResolveBindingsGlobalRoleBindingWithMultipleRoles(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// One binding may name several roles
	// (--global-role-binding=<issuer>::<subject>::<roleID>[,<roleID>...]); each
	// yields its own global binding, in sorted order.
	r := fx.withOptions(func(o *rbac.Options) {
		o.GlobalRoleBindings = rbac.GlobalRoleBindingsValue{{
			Issuer:  idconstants.UNISentinel,
			Subject: parityAliceSubject,
			RoleIDs: []string{parityRoleMixed, parityRoleGlobalAdmin},
		}}
	})

	bindings, err := r.ResolveBindings(t.Context(), parityUserInfo(parityAliceSubject, parityOrgA))
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{
		{RoleID: parityRoleGlobalAdmin},
		{RoleID: parityRoleMixed},
	}, bindings)
}

func TestResolveBindingsOverlappingBindingsDeduplicateTheRole(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// A role reachable through BOTH a subject and a group binding must appear
	// once: the wire format is a set, and a duplicate binding string would be
	// redundant policy input (normalizeBindings).
	r := fx.withOptions(func(o *rbac.Options) {
		o.GlobalRoleBindings = rbac.GlobalRoleBindingsValue{{
			Issuer:  parityExternalIssuer,
			Subject: parityAliceSubject,
			RoleIDs: []string{parityRoleGlobalAdmin},
		}}
		o.GlobalGroupRoleBindings = rbac.GlobalGroupRoleBindingsValue{{
			Issuer:  parityExternalIssuer,
			Group:   parityExternalGroup,
			RoleIDs: []string{parityRoleGlobalAdmin},
		}}
	})

	bindings, err := r.ResolveBindings(t.Context(), parityExternalUserInfo(parityAliceSubject, parityOrgA))
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{{RoleID: parityRoleGlobalAdmin}}, bindings)
}

func TestResolveBindingsGroupRoleBindingBrokenRoleReference(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// A group binding naming a nonexistent role is a HARD error, mirroring
	// accumulateGlobalPermissions: a silent skip would quietly under-grant and
	// mask the configuration mistake.
	r := fx.withOptions(func(o *rbac.Options) {
		o.GlobalGroupRoleBindings = rbac.GlobalGroupRoleBindingsValue{{
			Issuer:  parityExternalIssuer,
			Group:   parityExternalGroup,
			RoleIDs: []string{"prole-does-not-exist"},
		}}
	})

	_, err := r.ResolveBindings(t.Context(), parityExternalUserInfo(parityAliceSubject, parityOrgA))
	require.ErrorIs(t, err, errors.ErrConsistency)
}

func TestResolveBindingsWildcardBindingIgnoredOnUNISentinel(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// resolveGlobalRoleBindings skips a wildcard on the UNI sentinel, so it
	// never MATCHES and the fail-closed refusal must not fire: a configured
	// wildcard cannot break UNI-local users. Memberships resolve normally.
	r := fx.withOptions(func(o *rbac.Options) {
		o.GlobalRoleBindings = rbac.GlobalRoleBindingsValue{{
			Issuer:   idconstants.UNISentinel,
			Subject:  rbac.WildcardSubject,
			RoleIDs:  []string{parityRoleGlobalAdmin},
			Wildcard: true,
		}}
	})

	bindings, err := r.ResolveBindings(t.Context(), parityUserInfo(parityAliceSubject, parityOrgA))
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{
		{RoleID: parityRoleMixed, OrganizationID: parityOrgA},
		{RoleID: parityRoleOrgAdmin, OrganizationID: parityOrgA},
		{RoleID: parityRoleOrgAdmin, OrganizationID: parityOrgA, ProjectID: parityProjectX},
	}, bindings)
}

func TestResolveBindingsWildcardBindingLeavesOtherIssuersUnaffected(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// The wildcard is scoped to ONE issuer. A UNI-local user must be untouched
	// by a wildcard configured for an external IdP — neither granted by it nor
	// failed closed on its account.
	r := fx.withOptions(func(o *rbac.Options) {
		o.GlobalRoleBindings = rbac.GlobalRoleBindingsValue{{
			Issuer:   parityExternalIssuer,
			Subject:  rbac.WildcardSubject,
			RoleIDs:  []string{parityRoleGlobalAdmin},
			Wildcard: true,
		}}
	})

	bindings, err := r.ResolveBindings(t.Context(), parityUserInfo(parityAliceSubject, parityOrgA))
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{
		{RoleID: parityRoleMixed, OrganizationID: parityOrgA},
		{RoleID: parityRoleOrgAdmin, OrganizationID: parityOrgA},
		{RoleID: parityRoleOrgAdmin, OrganizationID: parityOrgA, ProjectID: parityProjectX},
	}, bindings)
}

func TestResolveBindingsWildcardAlongsideExactKeepsBoth(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// accumulateMatchedBindings loops every matched binding, so a wildcard and
	// an exact binding on one principal both contribute: the wildcard its
	// clamped read bucket, the exact binding its full global bucket. Dropping
	// either would diverge from the legacy union.
	r := fx.withOptions(func(o *rbac.Options) {
		o.GlobalRoleBindings = rbac.GlobalRoleBindingsValue{
			{
				Issuer:  parityExternalIssuer,
				Subject: parityAliceSubject,
				RoleIDs: []string{parityRoleMixed},
			},
			{
				Issuer:   parityExternalIssuer,
				Subject:  rbac.WildcardSubject,
				RoleIDs:  []string{parityRoleGlobalAdmin},
				Wildcard: true,
			},
		}
	})

	info := parityUserInfo(parityAliceSubject, parityOrgA)
	info.SrcIss = parityExternalIssuer

	bindings, err := r.ResolveBindings(t.Context(), info)
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{
		{RoleID: parityRoleGlobalAdmin, GlobalRead: true},
		{RoleID: parityRoleMixed},
	}, bindings)
}

func TestResolveBindingsServiceAccountIgnoresGlobalRoleBindings(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// Legacy resolves global bindings ONLY in processUserAccountACL, so a
	// binding whose subject collides with a service account ID must not grant
	// it global authority: the membership walk stands.
	r := fx.withOptions(func(o *rbac.Options) {
		o.GlobalRoleBindings = rbac.GlobalRoleBindingsValue{{
			Issuer:  idconstants.UNISentinel,
			Subject: paritySA1,
			RoleIDs: []string{parityRoleGlobalAdmin},
		}}
	})

	bindings, err := r.ResolveBindings(t.Context(), parityServiceAccountInfo(paritySA1, parityOrgA))
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{
		{RoleID: parityRoleProjectDev, OrganizationID: parityOrgA},
		{RoleID: parityRoleProjectDev, OrganizationID: parityOrgA, ProjectID: parityProjectX},
	}, bindings)
}

func TestResolveBindingsSystemAccountIgnoresGlobalRoleBindings(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	// Same invariant for system accounts: their authority comes from the CN →
	// role map alone, never from a binding that happens to name the CN.
	r := fx.withOptions(func(o *rbac.Options) {
		o.GlobalRoleBindings = rbac.GlobalRoleBindingsValue{{
			Issuer:  idconstants.UNISentinel,
			Subject: paritySystemCN,
			RoleIDs: []string{parityRoleImpersonator},
		}}
	})

	bindings, err := r.ResolveBindings(t.Context(), paritySystemInfo(paritySystemCN))
	require.NoError(t, err)
	require.Equal(t, []cerbos.RoleBinding{{RoleID: parityRoleGlobalAdmin}}, bindings)
}
