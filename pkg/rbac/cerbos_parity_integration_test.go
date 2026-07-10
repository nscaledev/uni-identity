//go:build integration

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

// This file is the A5 decision-parity integration test (run it with make
// test-cerbos-decisions): a miniature of the A7 shadow comparison.  From ONE
// fake-client fixture dataset it computes every verdict twice — legacy
// (GetACL + the Allow* scope functions, exactly as the middleware wires them)
// and Cerbos (generate.Generate over the SAME fixture roles, served by the
// pinned image, queried through ResolveBindings + Check) — and requires them
// to be EQUAL across a matrix of {platform admin, user, service account,
// system account} × {global, org, project} × {granted op, ungranted op,
// wrong org, wrong project, unknown endpoint, resolution failure}.
//
// A mismatch here is an authorization bug in the migration (or a genuine
// legacy quirk the resolver failed to replicate): escalate it, never
// special-case it.
package rbac_test

import (
	"context"
	goerrors "errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos/generate"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// parityCase is one cell of the parity matrix.  organizationID=="" is a
// global-scope check, projectID=="" an org-scope check, otherwise project
// scope — mapping exactly onto AllowGlobalScope/AllowOrganizationScope/
// AllowProjectScope on the legacy side and the Resource scope attributes on
// the Cerbos side.
type parityCase struct {
	name           string
	info           *authorization.Info
	organizationID string
	projectID      string
	endpoint       string
	operation      openapi.AclOperation

	// expectAllow is the intended fixture semantics; the legacy verdict is
	// asserted against it first so a fixture bug cannot silently produce a
	// vacuous deny==deny parity.
	expectAllow bool

	// wantLegacyError marks cases where the legacy side denies by GetACL
	// FAILING (the middleware rejects the request) rather than by an Allow*
	// verdict.  Usually paired with wantResolveError, but not always: the
	// legacy user path errors on a request scoped to a non-member
	// organization, while the Cerbos resolver has no request-scope
	// parameter at all (owner decision: resolve across ALL orgs) and denies
	// through policy instead — same verdict, different mechanism.
	wantLegacyError bool

	// wantResolveError marks cases where the Cerbos side fails before a
	// policy verdict (the resolver errors): the fail-closed deny must come
	// from ErrResolutionFailed, not the PDP.
	wantResolveError bool
}

//nolint:funlen
func parityCases() []parityCase {
	return []parityCase{
		// Platform administrator: global grants flow down to org and project
		// scope; nothing outside the configured role is granted.
		{name: "AdminGlobalGranted", info: parityUserInfo(parityAdminSubject, parityOrgA), endpoint: "identity:organizations", operation: openapi.Read, expectAllow: true},
		{name: "AdminGlobalUngrantedOp", info: parityUserInfo(parityAdminSubject, parityOrgA), endpoint: "identity:organizations", operation: openapi.Delete},
		{name: "AdminGlobalUnknownEndpoint", info: parityUserInfo(parityAdminSubject, parityOrgA), endpoint: "identity:unknown", operation: openapi.Read},
		{name: "AdminOrgFlowDown", info: parityUserInfo(parityAdminSubject, parityOrgA), organizationID: parityOrgA, endpoint: "identity:organizations", operation: openapi.Read, expectAllow: true},
		// identity:groups is deliberately the endpoint the administrator's
		// (ignored) group membership would grant at org scope: this cell is
		// the matrix witness that platform administrators' memberships
		// contribute nothing — a resolver that consulted them would flip it
		// to ALLOW against the legacy deny.  Do not change the endpoint.
		{name: "AdminOrgUngrantedEndpoint", info: parityUserInfo(parityAdminSubject, parityOrgA), organizationID: parityOrgA, endpoint: "identity:groups", operation: openapi.Read},
		{name: "AdminProjectFlowDown", info: parityUserInfo(parityAdminSubject, parityOrgA), organizationID: parityOrgA, projectID: parityProjectX, endpoint: "identity:organizations", operation: openapi.Update, expectAllow: true},

		// System account: one configured global role, same flow-down.
		{name: "SystemGlobalGranted", info: paritySystemInfo(paritySystemCN), endpoint: "identity:organizations", operation: openapi.Read, expectAllow: true},
		{name: "SystemGlobalUngrantedOp", info: paritySystemInfo(paritySystemCN), endpoint: "identity:organizations", operation: openapi.Delete},
		{name: "SystemGlobalUnknownEndpoint", info: paritySystemInfo(paritySystemCN), endpoint: "identity:unknown", operation: openapi.Read},
		{name: "SystemOrgFlowDown", info: paritySystemInfo(paritySystemCN), organizationID: parityOrgA, endpoint: "identity:organizations", operation: openapi.Update, expectAllow: true},
		{name: "SystemProjectFlowDown", info: paritySystemInfo(paritySystemCN), organizationID: parityOrgA, projectID: parityProjectX, endpoint: "identity:organizations", operation: openapi.Read, expectAllow: true},
		{name: "SystemUnregisteredCN", info: paritySystemInfo(paritySystemRogueCN), organizationID: parityOrgA, endpoint: "identity:organizations", operation: openapi.Read, wantLegacyError: true, wantResolveError: true},

		// Service account sa-1, home org A, roles via ServiceAccountIDs.
		{name: "ServiceAccountOrgGranted", info: parityServiceAccountInfo(paritySA1, parityOrgA), organizationID: parityOrgA, endpoint: "identity:projects", operation: openapi.Read, expectAllow: true},
		{name: "ServiceAccountOrgUngrantedOp", info: parityServiceAccountInfo(paritySA1, parityOrgA), organizationID: parityOrgA, endpoint: "identity:projects", operation: openapi.Update},
		// The org-mismatch FALLTHROUGH ported as-is: legacy GetACL scoped to
		// org B does NOT error for an org-A service account — it falls
		// through to home-org resolution and the org-B check then denies.
		{name: "ServiceAccountWrongOrgFallthrough", info: parityServiceAccountInfo(paritySA1, parityOrgA), organizationID: parityOrgB, endpoint: "identity:projects", operation: openapi.Read},
		{name: "ServiceAccountProjectGranted", info: parityServiceAccountInfo(paritySA1, parityOrgA), organizationID: parityOrgA, projectID: parityProjectX, endpoint: "compute:clusters", operation: openapi.Create, expectAllow: true},
		{name: "ServiceAccountProjectUngrantedOp", info: parityServiceAccountInfo(paritySA1, parityOrgA), organizationID: parityOrgA, projectID: parityProjectX, endpoint: "compute:clusters", operation: openapi.Update},
		{name: "ServiceAccountWrongProject", info: parityServiceAccountInfo(paritySA1, parityOrgA), organizationID: parityOrgA, projectID: parityProjectY, endpoint: "compute:clusters", operation: openapi.Read},
		{name: "ServiceAccountGlobalDenied", info: parityServiceAccountInfo(paritySA1, parityOrgA), endpoint: "identity:projects", operation: openapi.Read},
		{name: "ServiceAccountUnknownEndpoint", info: parityServiceAccountInfo(paritySA1, parityOrgA), organizationID: parityOrgA, endpoint: "identity:unknown", operation: openapi.Read},
		{name: "ServiceAccountNoGroups", info: parityServiceAccountInfo(paritySALonely, parityOrgA), organizationID: parityOrgA, endpoint: "identity:projects", operation: openapi.Read},
		// Unprovisioned home org: a hard error on both sides (the legacy
		// user path would skip it silently — the asymmetry is deliberate).
		{name: "ServiceAccountUnprovisionedHomeOrg", info: parityServiceAccountInfo(paritySAGhost, parityOrgGhost), organizationID: parityOrgGhost, endpoint: "identity:projects", operation: openapi.Read, wantLegacyError: true, wantResolveError: true},

		// User alice: different grants in org A and org B; bindings resolve
		// across ALL her organizations.
		{name: "UserOrgGranted", info: parityUserInfo(parityAliceSubject, parityOrgA, parityOrgGhost, parityOrgB), organizationID: parityOrgA, endpoint: "identity:groups", operation: openapi.Create, expectAllow: true},
		{name: "UserOrgGrantedSecondGroup", info: parityUserInfo(parityAliceSubject, parityOrgA, parityOrgGhost, parityOrgB), organizationID: parityOrgA, endpoint: "identity:allocations", operation: openapi.Read, expectAllow: true},
		{name: "UserOrgUngrantedOp", info: parityUserInfo(parityAliceSubject, parityOrgA, parityOrgGhost, parityOrgB), organizationID: parityOrgA, endpoint: "identity:groups", operation: openapi.Delete},
		{name: "UserCrossOrgGranted", info: parityUserInfo(parityAliceSubject, parityOrgA, parityOrgGhost, parityOrgB), organizationID: parityOrgB, endpoint: "identity:auditlogs", operation: openapi.Read, expectAllow: true},
		{name: "UserWrongOrg", info: parityUserInfo(parityAliceSubject, parityOrgA, parityOrgGhost, parityOrgB), organizationID: parityOrgB, endpoint: "identity:groups", operation: openapi.Read},
		// parityRoleMixed HAS a global scope block, but group grants never
		// yield global authority.
		{name: "UserGroupNeverGlobal", info: parityUserInfo(parityAliceSubject, parityOrgA, parityOrgGhost, parityOrgB), endpoint: "identity:oauth2providers", operation: openapi.Read},
		{name: "UserGlobalScopeNotInOrgCheck", info: parityUserInfo(parityAliceSubject, parityOrgA, parityOrgGhost, parityOrgB), organizationID: parityOrgA, endpoint: "identity:oauth2providers", operation: openapi.Read},
		// Org-level grants flow DOWN into project-scope checks.
		{name: "UserOrgGrantFlowsToProject", info: parityUserInfo(parityAliceSubject, parityOrgA, parityOrgGhost, parityOrgB), organizationID: parityOrgA, projectID: parityProjectX, endpoint: "identity:groups", operation: openapi.Read, expectAllow: true},
		{name: "UserProjectDenied", info: parityUserInfo(parityAliceSubject, parityOrgA, parityOrgGhost, parityOrgB), organizationID: parityOrgA, projectID: parityProjectX, endpoint: "compute:clusters", operation: openapi.Read},
		{name: "UserUnknownEndpoint", info: parityUserInfo(parityAliceSubject, parityOrgA, parityOrgGhost, parityOrgB), organizationID: parityOrgA, endpoint: "identity:unknown", operation: openapi.Read},

		// User bob: project-scoped workload authority via two groups.
		{name: "UserProjectGranted", info: parityUserInfo(parityBobSubject, parityOrgA), organizationID: parityOrgA, projectID: parityProjectX, endpoint: "compute:clusters", operation: openapi.Create, expectAllow: true},
		{name: "UserProjectUngrantedOp", info: parityUserInfo(parityBobSubject, parityOrgA), organizationID: parityOrgA, projectID: parityProjectX, endpoint: "compute:clusters", operation: openapi.Update},
		{name: "UserWrongProject", info: parityUserInfo(parityBobSubject, parityOrgA), organizationID: parityOrgA, projectID: parityProjectY, endpoint: "compute:clusters", operation: openapi.Read},
		// Legacy denies this via the ErrNotInOrganization error (bob holds
		// no org-B membership, so GetACL scoped to org B refuses); Cerbos
		// denies it as a plain policy deny, since the resolver is
		// request-scope-free.  Same verdict, different mechanism — the
		// expected consequence of the resolve-all-orgs owner decision.
		{name: "UserProjectWrongOrg", info: parityUserInfo(parityBobSubject, parityOrgA), organizationID: parityOrgB, projectID: parityProjectX, endpoint: "compute:clusters", operation: openapi.Read, wantLegacyError: true},
		{name: "UserOrgGrantedViaProjectRole", info: parityUserInfo(parityBobSubject, parityOrgA), organizationID: parityOrgA, endpoint: "identity:projects", operation: openapi.Read, expectAllow: true},

		// User carol: membership only via the deprecated UserIDs field.
		{name: "UserLegacyFallbackProjectGranted", info: parityUserInfo(parityCarolSubject, parityOrgA), organizationID: parityOrgA, projectID: parityProjectY, endpoint: "compute:clusters", operation: openapi.Read, expectAllow: true},
		{name: "UserLegacyFallbackUngrantedOp", info: parityUserInfo(parityCarolSubject, parityOrgA), organizationID: parityOrgA, projectID: parityProjectY, endpoint: "compute:clusters", operation: openapi.Create},
		{name: "UserLegacyFallbackWrongProject", info: parityUserInfo(parityCarolSubject, parityOrgA), organizationID: parityOrgA, projectID: parityProjectX, endpoint: "compute:clusters", operation: openapi.Read},

		// User erin: her group references a role that does not exist — a
		// hard consistency error on both sides.
		{name: "UserBrokenRoleReference", info: parityUserInfo(parityErinSubject, parityOrgA), organizationID: parityOrgA, endpoint: "identity:groups", operation: openapi.Read, wantLegacyError: true, wantResolveError: true},
	}
}

// legacyVerdict computes the legacy allow/deny for a case exactly as the
// middleware does: GetACL scoped to the request organization, then the Allow*
// function matching the check's scope level.  A GetACL error is a deny — the
// middleware rejects the request outright in that case.
func legacyVerdict(t *testing.T, r *rbac.RBAC, tc parityCase) bool {
	t.Helper()

	ctx := authorization.NewContext(t.Context(), tc.info)

	acl, err := r.GetACL(ctx, tc.organizationID)
	if err != nil {
		require.True(t, tc.wantLegacyError, "legacy GetACL failed unexpectedly: %v", err)

		return false
	}

	require.False(t, tc.wantLegacyError, "legacy GetACL succeeded but the case expects it to fail")

	ctx = rbac.NewContext(ctx, acl)

	switch {
	case tc.projectID != "":
		return rbac.AllowProjectScope(ctx, tc.endpoint, tc.operation, tc.organizationID, tc.projectID) == nil
	case tc.organizationID != "":
		return rbac.AllowOrganizationScope(ctx, tc.endpoint, tc.operation, tc.organizationID) == nil
	default:
		return rbac.AllowGlobalScope(ctx, tc.endpoint, tc.operation) == nil
	}
}

// cerbosVerdict computes the Cerbos allow/deny for a case via Check.  Only a
// clean policy deny (or, for wantResolveError cases, a resolution failure)
// counts as deny: anything else — crucially PDP unavailability — fails the
// test loudly so an outage can never masquerade as successful deny parity.
func cerbosVerdict(t *testing.T, r *rbac.RBAC, tc parityCase) bool {
	t.Helper()

	ctx := authorization.NewContext(t.Context(), tc.info)

	resource := rbac.Resource{Kind: tc.endpoint, OrganizationID: tc.organizationID, ProjectID: tc.projectID}

	err := r.Check(ctx, resource, tc.operation)

	switch {
	case err == nil:
		return true
	case goerrors.Is(err, rbac.ErrPolicyDenied):
		require.False(t, tc.wantResolveError, "expected a resolution failure, got a policy deny")

		return false
	case goerrors.Is(err, rbac.ErrResolutionFailed):
		require.True(t, tc.wantResolveError, "unexpected resolution failure: %v", err)

		return false
	default:
		require.FailNowf(t, "cerbos check failed for a non-decision reason", "error: %v", err)

		return false
	}
}

// TestCerbosDecisionParity is THE A5 deliverable: for every matrix case the
// Cerbos verdict must equal the legacy verdict computed from the same fixture
// data.  Any divergence is a finding to escalate.
func TestCerbosDecisionParity(t *testing.T) {
	t.Parallel()

	fx := newParityFixture(t)

	endpoint := startParityCerbos(t, writeParityStore(t, fx))

	client, err := cerbos.New(&cerbos.Options{Endpoint: endpoint, CheckTimeout: 5 * time.Second})
	require.NoError(t, err)

	fx.rbac.WithCerbos(client)

	cases := parityCases()
	t.Logf("decision parity matrix: %d cases", len(cases))

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			legacy := legacyVerdict(t, fx.rbac, tc)
			require.Equal(t, tc.expectAllow, legacy, "the LEGACY verdict diverges from the intended fixture semantics — fix the fixture or the case, not the comparison")

			cerbosAllowed := cerbosVerdict(t, fx.rbac, tc)
			require.Equal(t, legacy, cerbosAllowed, "DECISION PARITY VIOLATION: legacy=%v cerbos=%v — escalate, do not special-case", legacy, cerbosAllowed)
		})
	}

	// CheckMany must agree with Check case by case, in request order, from a
	// single batched CheckResources call.  Restricted to one subject: a
	// batch shares one principal.
	t.Run("CheckManyAgreesWithCheck", func(t *testing.T) {
		t.Parallel()

		var checks []rbac.CheckRequest

		var expected []bool

		for _, tc := range cases {
			if tc.info.Userinfo.Sub != parityAliceSubject {
				continue
			}

			checks = append(checks, rbac.CheckRequest{
				Resource: rbac.Resource{Kind: tc.endpoint, OrganizationID: tc.organizationID, ProjectID: tc.projectID},
				Action:   tc.operation,
			})

			expected = append(expected, tc.expectAllow)
		}

		require.NotEmpty(t, checks)

		ctx := authorization.NewContext(t.Context(), parityUserInfo(parityAliceSubject, parityOrgA, parityOrgGhost, parityOrgB))

		allowed, err := fx.rbac.CheckMany(ctx, checks)
		require.NoError(t, err)
		require.Equal(t, expected, allowed)
	})

	// A6 facade parity: representative cells re-run THROUGH the Allow*
	// facade — legacy exactly as legacyVerdict computes it, Cerbos via an
	// engine-seeded context in cerbos mode — proving the dispatch plumbing
	// itself does not distort decisions.  The engine is a cerbos-mode RBAC
	// over the same fixture data and PDP.
	t.Run("AllowFacadeAgreesInCerbosMode", func(t *testing.T) {
		t.Parallel()

		engine := rbac.New(fx.client, parityNamespace, &rbac.Options{
			PlatformAdministratorSubjects: []string{parityAdminSubject},
			PlatformAdministratorRoleIDs:  []string{parityRoleGlobalAdmin},
			SystemAccountRoleIDs:          map[string]string{paritySystemCN: parityRoleGlobalAdmin},
			AuthorizationEngine:           rbac.EngineCerbos,
		}).WithCerbos(client)

		// One representative allow and deny per scope level across the
		// actor classes; wantLegacyError cells are excluded (the middleware
		// rejects those requests before any Allow* runs).
		selected := []string{
			"AdminGlobalGranted",
			"AdminGlobalUngrantedOp",
			"SystemOrgFlowDown",
			"ServiceAccountOrgUngrantedOp",
			"ServiceAccountProjectGranted",
			"UserOrgGranted",
			"UserWrongOrg",
			"UserOrgGrantFlowsToProject",
			"UserProjectGranted",
			"UserWrongProject",
		}

		for _, tc := range cases {
			if !slices.Contains(selected, tc.name) {
				continue
			}

			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				legacy := legacyVerdict(t, fx.rbac, tc)

				ctx := rbac.NewEngineContext(authorization.NewContext(t.Context(), tc.info), engine)

				var err error

				switch {
				case tc.projectID != "":
					err = rbac.AllowProjectScope(ctx, tc.endpoint, tc.operation, tc.organizationID, tc.projectID)
				case tc.organizationID != "":
					err = rbac.AllowOrganizationScope(ctx, tc.endpoint, tc.operation, tc.organizationID)
				default:
					err = rbac.AllowGlobalScope(ctx, tc.endpoint, tc.operation)
				}

				// Only a genuine policy deny counts as deny — an outage or
				// resolver failure must fail the test loudly rather than
				// masquerade as deny parity.
				if err != nil {
					require.ErrorIs(t, err, rbac.ErrPolicyDenied, "the facade denied for a non-policy reason: %v", err)
				}

				require.Equal(t, legacy, err == nil, "FACADE PARITY VIOLATION: legacy=%v cerbos-facade=%v — escalate, do not special-case", legacy, err == nil)
			})
		}
	})

	// A7 shadow comparator, half one: with the PARITY store, shadow mode
	// must serve exactly the legacy verdicts across the whole matrix and log
	// ZERO divergences (and, against a healthy PDP with resolvable subjects,
	// zero evaluation failures).  Serial (no t.Parallel): the log capture
	// swaps the process-global default logger.
	//
	//nolint:paralleltest
	t.Run("ShadowModeParityStoreLogsNoDivergence", func(t *testing.T) {
		capture := captureShadowLogs(t)

		engine := rbac.New(fx.client, parityNamespace, &rbac.Options{
			PlatformAdministratorSubjects: []string{parityAdminSubject},
			PlatformAdministratorRoleIDs:  []string{parityRoleGlobalAdmin},
			SystemAccountRoleIDs:          map[string]string{paritySystemCN: parityRoleGlobalAdmin},
			AuthorizationEngine:           rbac.EngineShadow,
		}).WithCerbos(client)

		for _, tc := range cases {
			// The middleware rejects these before any Allow* runs.
			if tc.wantLegacyError {
				continue
			}

			legacy := legacyVerdict(t, fx.rbac, tc)
			served := shadowFacadeVerdict(t, fx, engine, tc)

			require.Equal(t, legacy, served, "shadow mode must serve the legacy verdict (case %s)", tc.name)
		}

		require.Empty(t, capture.messages(shadowDivergenceMessage), "the parity store must produce ZERO divergences")
		require.Empty(t, capture.messages(shadowFailureMessage), "a healthy PDP must produce zero evaluation failures")
	})

	// A7 shadow comparator, half two: a deliberately-divergent store — the
	// generated store with ONE extra allow the legacy fixture lacks — must
	// produce EXACTLY the corresponding divergence, carrying the full field
	// set, while the served verdict STAYS legacy's even on the divergent
	// cell.  Serial for the same reason as above.
	//
	//nolint:paralleltest
	t.Run("ShadowModeDetectsInjectedDivergence", func(t *testing.T) {
		capture := captureShadowLogs(t)

		divergentEndpoint := startParityCerbos(t, writeDivergentParityStore(t, fx))

		divergentClient, err := cerbos.New(&cerbos.Options{Endpoint: divergentEndpoint, CheckTimeout: 5 * time.Second})
		require.NoError(t, err)

		engine := rbac.New(fx.client, parityNamespace, &rbac.Options{
			PlatformAdministratorSubjects: []string{parityAdminSubject},
			PlatformAdministratorRoleIDs:  []string{parityRoleGlobalAdmin},
			SystemAccountRoleIDs:          map[string]string{paritySystemCN: parityRoleGlobalAdmin},
			AuthorizationEngine:           rbac.EngineShadow,
		}).WithCerbos(divergentClient)

		for _, tc := range cases {
			if tc.wantLegacyError {
				continue
			}

			legacy := legacyVerdict(t, fx.rbac, tc)
			served := shadowFacadeVerdict(t, fx, engine, tc)

			require.Equal(t, legacy, served, "the served verdict must STAY legacy even where the stores diverge (case %s)", tc.name)
		}

		divergences := capture.messages(shadowDivergenceMessage)
		require.Len(t, divergences, 1, "exactly the one injected divergence must be detected")

		// The injected extra allow flips exactly the UserOrgUngrantedOp cell:
		// alice, identity:groups delete at organization scope in org A.
		attrs := recordAttrs(divergences[0])
		require.Equal(t, parityAliceSubject, attrs["subject"])
		require.Equal(t, "user", attrs["actor_type"])
		require.Equal(t, "identity:groups", attrs["endpoint"])
		require.Equal(t, "delete", attrs["operation"])
		require.Equal(t, parityOrgA, attrs["organization_id"])
		require.Empty(t, attrs["project_id"])
		require.Equal(t, "deny", attrs["legacy_verdict"])
		require.Equal(t, "allow", attrs["cerbos_verdict"])
		require.Equal(t, "allowed", attrs["cerbos_class"])

		// The policy correlate is carried, but the PDP echoes the REQUESTED
		// policy version/scope, which identity's coarse checks leave unset
		// (the server-default version applies) — so both are empty against a
		// real PDP until A15's policy-hash signal upgrades the correlate.
		// The unit tests prove non-empty values are plumbed through.
		require.Contains(t, attrs, "policy_version")
		require.Contains(t, attrs, "policy_scope")

		require.Empty(t, capture.messages(shadowFailureMessage))
	})
}

// shadowFacadeVerdict serves one matrix case through the Allow* facade with a
// shadow-mode engine seeded, exactly as the middleware wires a request: an
// ACL for the legacy walk, authorization info for the Cerbos side.
func shadowFacadeVerdict(t *testing.T, fx *parityFixture, engine *rbac.RBAC, tc parityCase) bool {
	t.Helper()

	ctx := authorization.NewContext(t.Context(), tc.info)

	acl, err := fx.rbac.GetACL(ctx, tc.organizationID)
	require.NoError(t, err)

	ctx = rbac.NewEngineContext(rbac.NewContext(ctx, acl), engine)

	switch {
	case tc.projectID != "":
		return rbac.AllowProjectScope(ctx, tc.endpoint, tc.operation, tc.organizationID, tc.projectID) == nil
	case tc.organizationID != "":
		return rbac.AllowOrganizationScope(ctx, tc.endpoint, tc.operation, tc.organizationID) == nil
	default:
		return rbac.AllowGlobalScope(ctx, tc.endpoint, tc.operation) == nil
	}
}

// writeDivergentParityStore generates a policy store from a MUTATED copy of
// the fixture roles — parityRoleOrgAdmin additionally grants identity:groups
// delete at organization scope, an extra allow the legacy fixture lacks — so
// exactly one matrix verdict (UserOrgUngrantedOp) flips on the Cerbos side.
func writeDivergentParityStore(t *testing.T, fx *parityFixture) string {
	t.Helper()

	roles := make([]unikornv1.Role, len(fx.roles))

	mutated := false

	for i := range fx.roles {
		role := fx.roles[i].DeepCopy()

		if role.Name == parityRoleOrgAdmin {
			for j := range role.Spec.Scopes.Organization {
				if role.Spec.Scopes.Organization[j].Name == "identity:groups" {
					role.Spec.Scopes.Organization[j].Operations = append(role.Spec.Scopes.Organization[j].Operations, unikornv1.Delete)
					mutated = true
				}
			}
		}

		roles[i] = *role
	}

	require.True(t, mutated, "the fixture no longer carries the scope the divergence is injected into")

	output, err := generate.Generate(roles)
	require.NoError(t, err)

	files, err := output.Files()
	require.NoError(t, err)

	dir := parityStoreDir(t)

	for name, data := range files {
		//nolint:gosec // the store must be readable by the container's non-root cerbos user.
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o644))
	}

	return dir
}

// writeParityStore generates the Cerbos policy store from the SAME fixture
// roles the fake client (and therefore the legacy side) resolves against,
// and materializes it for the PDP container.
func writeParityStore(t *testing.T, fx *parityFixture) string {
	t.Helper()

	output, err := generate.Generate(fx.roles)
	require.NoError(t, err)

	files, err := output.Files()
	require.NoError(t, err)

	dir := parityStoreDir(t)

	for name, data := range files {
		//nolint:gosec // the store must be readable by the container's non-root cerbos user.
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o644))
	}

	return dir
}

// parityStoreDir returns a scratch directory the PDP container can mount and
// read as its non-root user.  Mirrors the controller integration test's
// storeDir: on non-Linux hosts the directory must live under the repository
// (docker file sharing covers the home directory; t.TempDir lives outside
// it, e.g. /var/folders on darwin, which colima does not share).
func parityStoreDir(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	if runtime.GOOS != "linux" {
		cwd, err := os.Getwd()
		require.NoError(t, err)

		dir, err = os.MkdirTemp(cwd, ".cerbos-parity-store-*") //nolint:usetesting // must live under the repository for docker file sharing, see above.
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, os.RemoveAll(dir))
		})
	}

	// The container's cerbos user (65534) must traverse and read the store:
	// temp directories are created 0700, owned by the test user.
	require.NoError(t, os.Chmod(dir, 0o755))

	return dir
}

// The docker harness below is a small, deliberate duplication of the client
// integration test's (pkg/authz/cerbos/client_integration_test.go): the
// brief for this test explicitly prefers a copied helper over a speculative
// shared testutil package.  The PDP configuration is NOT duplicated — the
// container mounts pkg/authz/cerbos/testdata/config, the single fixture
// config that unit tests pin to the chart's.

// parityDefaultImage must match the Makefile's CERBOS_VERSION; make
// test-cerbos-decisions overrides via CERBOS_IMAGE.
const parityDefaultImage = "ghcr.io/cerbos/cerbos:0.53.0"

// parityCerbosUID mirrors the chart's runAsUser for the sidecar container.
const parityCerbosUID = "65534"

// startParityCerbos runs the pinned Cerbos image with the generated policy
// store under the chart's pod constraints, waits for health and returns the
// gRPC endpoint.
func startParityCerbos(t *testing.T, policiesDir string) string {
	t.Helper()

	image := os.Getenv("CERBOS_IMAGE")
	if image == "" {
		image = parityDefaultImage
	}

	cwd, err := os.Getwd()
	require.NoError(t, err)

	configDir := filepath.Clean(filepath.Join(cwd, "..", "authz", "cerbos", "testdata", "config"))

	name := fmt.Sprintf("cerbos-parity-test-%d", time.Now().UnixNano())

	// Registered before docker run so a partially created container never
	// leaks; removal is idempotent.
	t.Cleanup(func() {
		//nolint:usetesting // t.Context() is already canceled inside Cleanup and would kill the removal command.
		_ = exec.CommandContext(context.Background(), "docker", "rm", "--force", name).Run()
	})

	cmd := exec.CommandContext(t.Context(), "docker", "run",
		"--detach",
		"--name", name,
		"--user", parityCerbosUID+":"+parityCerbosUID,
		"--read-only",
		"--tmpfs", "/tmp",
		"--tmpfs", "/.cache",
		"--volume", configDir+":/config:ro",
		"--volume", policiesDir+":/policies:ro",
		"--publish", "127.0.0.1:0:3593",
		image,
		"server", "--config=/config/config.yaml",
	)

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "docker run: %s", out)

	parityWaitHealthy(t, name)

	return parityHostPort(t, name, "3593/tcp")
}

// parityHostPort resolves the random host port Docker bound for a container
// port.
func parityHostPort(t *testing.T, name, port string) string {
	t.Helper()

	out, err := exec.CommandContext(t.Context(), "docker", "port", name, port).Output()
	require.NoError(t, err, "docker port %s %s", name, port)

	addr, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	require.NotEmpty(t, addr)

	return addr
}

// parityWaitHealthy polls the PDP with the chart's exact probe command until
// healthy.
func parityWaitHealthy(t *testing.T, name string) {
	t.Helper()

	deadline := time.Now().Add(time.Minute)

	arguments := []string{"exec", name, "/cerbos", "healthcheck", "--config=/config/config.yaml"}

	for {
		if time.Now().After(deadline) {
			logs, _ := exec.CommandContext(t.Context(), "docker", "logs", name).CombinedOutput()
			require.FailNowf(t, "cerbos did not become healthy", "container logs:\n%s", logs)
		}

		if err := exec.CommandContext(t.Context(), "docker", arguments...).Run(); err == nil {
			return
		}

		time.Sleep(200 * time.Millisecond)
	}
}
