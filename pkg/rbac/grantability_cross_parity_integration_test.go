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

// This file is the A16 grantability cross-parity integration test (run it with
// make test-cerbos-decisions).  It is the parity story AllowRole's godoc defers
// to.
//
// WHY THIS EXISTS.  Enforcement runs on Cerbos (the generated policy), but the
// grant-guard (AllowRole, handler.go) prevents privilege escalation entirely in
// thin Go: it trusts Role.Spec.Scopes as a role's permission set and checks the
// caller's materialized ACL holds each declared scope via the legacy Allow*
// walk.  Those two models only stay honest if the generated Cerbos policy grants
// a holder of role R EXACTLY R's declared scopes (with the standard downward
// flow) — no more, no less.  If the policy grants MORE, an escalation slips PAST
// the grant-guard (the security-critical direction); if LESS, a granted role
// under-functions.  This test proves neither happens, for EVERY role — the nine
// built-in roles from charts/identity/values.yaml plus the out-of-repo
// open-vocabulary roles (radar:*/envir:*) — so a change to the generator or the
// role catalogue that diverges the two engines fails here rather than in
// production.
//
// It is TEST-ONLY: AllowRole stays thin-Go and unchanged.  It does NOT touch the
// curated TestCerbosDecisionParity matrix (that encodes specific legacy quirks);
// it reuses that harness's docker/store helpers (startParityCerbos, parityStoreDir;
// xparityServeStore mirrors writeParityStore over an explicit role slice) and the
// grant_guard_test.go role-expansion helpers (loadChartRoles, asRole), and rides
// the same make target and CI invocation with no new wiring.
//
// HOW.  For every role R the store under test contains, the fixture holds a
// principal bound to EXACTLY R (isolation is what makes over-grant observable),
// then probes that principal against the FULL (endpoint, operation) vocabulary
// of all roles under test, at every scope level (global, org, project).  The Go
// side (the grant-guard's model: aclForRoleScopes(R) + the legacy Allow*) and
// the Cerbos side (Check on the real PDP over the real generated policy) must
// return the SAME verdict for every probe, both directions.  Comparing verdicts
// (not error identity) tolerates the documented legacy/Cerbos error-shape
// asymmetries; a PDP/resolution failure fails the test LOUDLY (an outage must
// never masquerade as a deny).
//
// A single principal can hold a role at global scope XOR at org/project scope,
// never both: global authority comes from platform-admin/system-account
// configuration (which never consults groups), org/project authority from group
// membership (which never yields global bindings, see bindings.go).  No built-in
// or open-vocab role mixes global with org/project scopes, so one principal
// class per role suffices — asserted below so a future mixed role fails loudly
// rather than silently under-covering one of its halves.
package rbac_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos/generate"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	// xparityNamespace holds the Role and Organization resources getRoles /
	// getOrganizationNamespace read; xparityOrgNS is the organization's
	// provisioned namespace where Groups and the Project live.  Distinct from
	// the parityNamespace TestCerbosDecisionParity uses so the two integration
	// fixtures never share a fake client.
	xparityNamespace = "xparity-identity-ns"
	xparityOrgNS     = "xparity-org-ns"

	// xparityChunk caps a CheckMany batch at Cerbos's default
	// server.requestLimits.maxResourcesPerRequest (50); the test config sets no
	// override, so the sweep must chunk under it.
	xparityChunk = 40
)

// xparityEndpointOp is one (endpoint, operation) pair in the probe vocabulary.
type xparityEndpointOp struct {
	endpoint  string
	operation openapi.AclOperation
}

// xparityScope is one scope level to probe at.  An empty organizationID is a
// global check, an empty projectID an org check, otherwise a project check —
// mapping onto AllowGlobalScope/AllowOrganizationScope/AllowProjectScope on the
// Go side and the Resource scope attributes on the Cerbos side, exactly as
// parityCase does.
type xparityScope struct {
	name           string
	organizationID string
	projectID      string
}

// xparityHolder pairs one role with a principal bound to EXACTLY that role and
// the ACL the grant-guard would materialize for such a holder.
type xparityHolder struct {
	roleName string
	info     *authorization.Info
	acl      *openapi.Acl
}

// aclEndpointsForScopes projects a role's scope bucket into ACL endpoints.  It
// is the []unikornv1.RoleScope analogue of grant_guard_test.go's
// toACLEndpoints (which reads the chart's map shape); operation string values
// are identical across the two named types, so the conversion is verbatim.
func aclEndpointsForScopes(scopes []unikornv1.RoleScope) openapi.AclEndpoints {
	endpoints := make(openapi.AclEndpoints, 0, len(scopes))

	for _, scope := range scopes {
		operations := make(openapi.AclOperations, len(scope.Operations))
		for i, operation := range scope.Operations {
			operations[i] = openapi.AclOperation(operation)
		}

		endpoints = append(endpoints, openapi.AclEndpoint{Name: scope.Name, Operations: operations})
	}

	return endpoints
}

// aclForRoleScopes builds the effective ACL a principal holding exactly this
// role would have, mirroring grant_guard_test.go's aclForHolder but over
// unikornv1.RoleScopes so it applies uniformly to the chart roles AND the
// open-vocab fixture roles (which are not chartRoles).  The global block lands
// at global scope, the organization block at organization scope, and the
// project block in the single accessible project — exactly as pkg/rbac
// accumulates real group membership, so the legacy Allow* walk over this ACL is
// the faithful grant-guard model of what a holder of the role is allowed.
func aclForRoleScopes(scopes unikornv1.RoleScopes) *openapi.Acl {
	acl := &openapi.Acl{}

	if len(scopes.Global) > 0 {
		global := aclEndpointsForScopes(scopes.Global)
		acl.Global = &global
	}

	organization := openapi.AclOrganization{Id: organizationID}

	if len(scopes.Organization) > 0 {
		endpoints := aclEndpointsForScopes(scopes.Organization)
		organization.Endpoints = &endpoints
	}

	if len(scopes.Project) > 0 {
		projects := openapi.AclProjectList{
			{Id: projectID, Endpoints: aclEndpointsForScopes(scopes.Project)},
		}
		organization.Projects = &projects
	}

	organizations := openapi.AclOrganizationList{organization}
	acl.Organizations = &organizations

	return acl
}

// xparityRoleCatalogue is the full role set under test: the nine built-in roles
// parsed from charts/identity/values.yaml (via loadChartRoles/asRole, the same
// source of truth the Go-lattice guard uses) plus the two out-of-repo
// open-vocabulary roles transcribed in cerbos_fixture_test.go.  Every role is
// re-stamped into the cross-parity namespace so getRoles resolves it.  Sorted by
// name for a deterministic sweep.
func xparityRoleCatalogue(t *testing.T) []unikornv1.Role {
	t.Helper()

	chart := loadChartRoles(t)

	roles := make([]unikornv1.Role, 0, len(chart)+2)

	for name, definition := range chart {
		role := asRole(definition)
		role.Name = name
		role.Namespace = xparityNamespace

		roles = append(roles, *role)
	}

	for _, role := range parityRoles() {
		if role.Name != parityRoleFleetOperator && role.Name != parityRoleEnvirProjectViewer {
			continue
		}

		role.Namespace = xparityNamespace

		roles = append(roles, role)
	}

	slices.SortFunc(roles, func(a, b unikornv1.Role) int {
		return strings.Compare(a.Name, b.Name)
	})

	return roles
}

// xparityVocabulary is the union of every (endpoint, operation) granted by any
// role under test, at any scope.  Probing each role against this full union —
// not just its own grants — is what exercises the complement and so catches
// over-grant.  Sorted for a stable sweep.
func xparityVocabulary(roles []unikornv1.Role) []xparityEndpointOp {
	seen := map[xparityEndpointOp]bool{}

	var vocabulary []xparityEndpointOp

	collect := func(scopes []unikornv1.RoleScope) {
		for _, scope := range scopes {
			for _, operation := range scope.Operations {
				pair := xparityEndpointOp{endpoint: scope.Name, operation: openapi.AclOperation(operation)}
				if !seen[pair] {
					seen[pair] = true

					vocabulary = append(vocabulary, pair)
				}
			}
		}
	}

	for i := range roles {
		collect(roles[i].Spec.Scopes.Global)
		collect(roles[i].Spec.Scopes.Organization)
		collect(roles[i].Spec.Scopes.Project)
	}

	slices.SortFunc(vocabulary, func(a, b xparityEndpointOp) int {
		if c := strings.Compare(a.endpoint, b.endpoint); c != 0 {
			return c
		}

		return strings.Compare(string(a.operation), string(b.operation))
	})

	return vocabulary
}

// newXparityCrossParityFixture assembles the full role set, builds a fake client
// that binds one isolated principal to each role, generates the Cerbos store
// from those roles, serves it via the shared docker harness and returns an RBAC
// wired to that PDP together with the per-role holders.
func newXparityCrossParityFixture(t *testing.T) (*rbac.RBAC, []xparityHolder, []unikornv1.Role) {
	t.Helper()

	roles := xparityRoleCatalogue(t)

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	objects := []client.Object{
		&unikornv1.Organization{
			ObjectMeta: metav1.ObjectMeta{Namespace: xparityNamespace, Name: organizationID},
			Status:     unikornv1.OrganizationStatus{Namespace: xparityOrgNS},
		},
	}

	for i := range roles {
		objects = append(objects, &roles[i])
	}

	systemAccountRoleIDs := map[string]string{}

	var projectGroupIDs []string

	holders := make([]xparityHolder, 0, len(roles))

	for i := range roles {
		role := roles[i]

		hasGlobal := len(role.Spec.Scopes.Global) > 0
		hasOrgOrProject := len(role.Spec.Scopes.Organization) > 0 || len(role.Spec.Scopes.Project) > 0

		require.Truef(t, hasGlobal || hasOrgOrProject, "role %q declares no scopes; the sweep cannot hold it", role.Name)
		require.Falsef(t, hasGlobal && hasOrgOrProject,
			"role %q mixes global with org/project scopes; a single principal can hold a role at global XOR org/project scope (groups never yield global bindings, admins/system accounts never consult groups) — extend the harness to a dual holder before adding such a role",
			role.Name)

		holder := xparityHolder{roleName: role.Name, acl: aclForRoleScopes(role.Spec.Scopes)}

		if hasGlobal {
			// Global roles are held via a system account (CN -> exactly this
			// role), the resolver's only single-role global-binding source; the
			// binding string, hence the Cerbos verdict, is identical however a
			// global holder is configured, so this is a faithful global holder.
			commonName := "xparity-system-" + role.Name
			systemAccountRoleIDs[commonName] = role.Name
			holder.info = paritySystemInfo(commonName)
		} else {
			// Org/project roles are held via a user in a group bound to exactly
			// this role, in the one organization; the shared project links the
			// group so the resolver emits the project binding too.
			subject := "xparity-" + role.Name + "@example.com"
			groupName := "xparity-group-" + role.Name

			objects = append(objects, &unikornv1.Group{
				ObjectMeta: metav1.ObjectMeta{Namespace: xparityOrgNS, Name: groupName},
				Spec: unikornv1.GroupSpec{
					RoleIDs:  []string{role.Name},
					Subjects: []unikornv1.GroupSubject{{ID: subject}},
				},
			})

			projectGroupIDs = append(projectGroupIDs, groupName)
			holder.info = parityUserInfo(subject, organizationID)
		}

		holders = append(holders, holder)
	}

	// One shared project links every org/project group.  A holder is a member of
	// only its own group, so projectGroupBindings emits a project binding for
	// exactly that holder's role — isolation is preserved (bindings.go).
	objects = append(objects, &unikornv1.Project{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: xparityOrgNS,
			Name:      projectID,
			Labels:    map[string]string{constants.OrganizationLabel: organizationID},
		},
		Spec: unikornv1.ProjectSpec{GroupIDs: projectGroupIDs},
	})

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

	r := rbac.New(c, xparityNamespace, &rbac.Options{SystemAccountRoleIDs: systemAccountRoleIDs})

	r.WithCerbos(xparityServeStore(t, roles))

	return r, holders, roles
}

// xparityServeStore generates the Cerbos policy store from the role set (the
// SAME roles the fake client binds, so the two engines resolve against
// identical data) and serves it through the shared docker harness, returning a
// PDP client.  Mirrors writeParityStore, over an explicit role slice.
func xparityServeStore(t *testing.T, roles []unikornv1.Role) *cerbos.Client {
	t.Helper()

	output, err := generate.Generate(roles)
	require.NoError(t, err)

	files, err := output.Files()
	require.NoError(t, err)

	dir := parityStoreDir(t)

	for name, data := range files {
		//nolint:gosec // the store must be readable by the container's non-root cerbos user.
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o644))
	}

	endpoint := startParityCerbos(t, dir)

	pdp, err := cerbos.New(&cerbos.Options{Endpoint: endpoint, CheckTimeout: 5 * time.Second})
	require.NoError(t, err)

	return pdp
}

// xparityGoVerdict is the grant-guard's Go-side verdict for one probe: the
// legacy Allow* walk over the holder's materialized ACL, with no engine seeded
// (so the facade takes the legacy path, exactly as legacyVerdict does).  This IS
// what AllowRole trusts: a role's declared scopes with the standard downward
// flow (global satisfies org and project; org satisfies project).
func xparityGoVerdict(t *testing.T, acl *openapi.Acl, pair xparityEndpointOp, scope xparityScope) bool {
	t.Helper()

	ctx := rbac.NewContext(t.Context(), acl)

	switch {
	case scope.projectID != "":
		return rbac.AllowProjectScope(ctx, pair.endpoint, pair.operation, scope.organizationID, scope.projectID) == nil
	case scope.organizationID != "":
		return rbac.AllowOrganizationScope(ctx, pair.endpoint, pair.operation, scope.organizationID) == nil
	default:
		return rbac.AllowGlobalScope(ctx, pair.endpoint, pair.operation) == nil
	}
}

// xparityCerbosVerdicts is the Cerbos-side verdict for the whole vocabulary at
// one scope for one holder, batched (one CheckMany per chunk).  A resolver,
// transport or PDP failure surfaces as a CheckMany error and fails the test
// LOUDLY — an outage must never be read as a deny and pass as false parity; a
// plain policy deny is a false entry, not an error, exactly as cerbosVerdict
// classifies it.
func xparityCerbosVerdicts(t *testing.T, r *rbac.RBAC, info *authorization.Info, vocabulary []xparityEndpointOp, scope xparityScope) []bool {
	t.Helper()

	ctx := authorization.NewContext(t.Context(), info)

	verdicts := make([]bool, 0, len(vocabulary))

	for start := 0; start < len(vocabulary); start += xparityChunk {
		end := start + xparityChunk
		if end > len(vocabulary) {
			end = len(vocabulary)
		}

		checks := make([]rbac.CheckRequest, 0, end-start)

		for _, pair := range vocabulary[start:end] {
			checks = append(checks, rbac.CheckRequest{
				Resource: rbac.Resource{Kind: pair.endpoint, OrganizationID: scope.organizationID, ProjectID: scope.projectID},
				Action:   pair.operation,
			})
		}

		allowed, err := r.CheckMany(ctx, checks)
		require.NoErrorf(t, err, "cerbos CheckMany failed at %s scope — a PDP/resolution failure must fail the test, never read as a deny", scope.name)
		require.Len(t, allowed, len(checks))

		verdicts = append(verdicts, allowed...)
	}

	return verdicts
}

// xparityDivergence names the direction of a mismatch for the failure message;
// only ever called when the two verdicts differ.
func xparityDivergence(goAllow, cerbosAllow bool) string {
	if cerbosAllow && !goAllow {
		return "MORE (over-grant: an escalation past the grant-guard)"
	}

	return "LESS (under-grant: a granted role under-functions)"
}

// TestGrantabilityCrossParity is the A16 deliverable: for every role, the
// generated Cerbos policy must grant a holder of that role EXACTLY the scopes
// the grant-guard (AllowRole) trusts it to — no more (the security-critical
// direction), no less.  Both engines evaluate the SAME roles over the SAME
// fixture data; any per-probe divergence is a grant-guard/enforcement split to
// escalate, not to special-case.
func TestGrantabilityCrossParity(t *testing.T) {
	t.Parallel()

	r, holders, roles := newXparityCrossParityFixture(t)

	vocabulary := xparityVocabulary(roles)
	require.NotEmpty(t, vocabulary)

	scopes := []xparityScope{
		{name: "global"},
		{name: "organization", organizationID: organizationID},
		{name: "project", organizationID: organizationID, projectID: projectID},
	}

	t.Logf("grantability cross-parity sweep: %d roles x %d (endpoint,operation) x %d scopes = %d probes; every role asserted in BOTH directions",
		len(holders), len(vocabulary), len(scopes), len(holders)*len(vocabulary)*len(scopes))

	for _, holder := range holders {
		t.Run(holder.roleName, func(t *testing.T) {
			t.Parallel()

			var roleAllow, roleDeny int

			for _, scope := range scopes {
				cerbos := xparityCerbosVerdicts(t, r, holder.info, vocabulary, scope)

				for i, pair := range vocabulary {
					goAllow := xparityGoVerdict(t, holder.acl, pair, scope)

					require.Equalf(t, goAllow, cerbos[i],
						"CROSS-PARITY VIOLATION: role %q endpoint %q op %q at %s scope: grant-guard(Go)=%v cerbos=%v — the generated policy grants this role %s than its declared scopes",
						holder.roleName, pair.endpoint, pair.operation, scope.name, goAllow, cerbos[i], xparityDivergence(goAllow, cerbos[i]))

					if goAllow {
						roleAllow++
					} else {
						roleDeny++
					}
				}
			}

			// Both directions must be exercised for THIS role or the parity is
			// vacuous: at least one grant it holds — a broken holder resolves no
			// bindings and would be granted nothing, so deny==deny would pass
			// while proving nothing — and at least one it does NOT hold, the
			// over-grant/escalation complement the sweep exists to catch.
			require.Positivef(t, roleAllow, "role %q was granted NOTHING across the sweep — the holder resolves no bindings (vacuous deny==deny parity)", holder.roleName)
			require.Positivef(t, roleDeny, "role %q was granted EVERYTHING across the sweep — the over-grant/escalation complement was never exercised", holder.roleName)

			t.Logf("role %q: %d allow, %d deny across %d probes", holder.roleName, roleAllow, roleDeny, len(scopes)*len(vocabulary))
		})
	}
}
