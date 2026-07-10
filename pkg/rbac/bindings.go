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

package rbac

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/authz/cerbos"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// This file is the Cerbos bindings resolver (migration task A5): it converts
// the authenticated subject's identity into the (role, scope) tuples the
// request builder (pkg/authz/cerbos/request.go) renders into the principal's
// bindings attribute.  Every branch deliberately mirrors a specific legacy
// ACL-accumulation path in this package — including the odd ones (silent
// unprovisioned-org skips, the service-account org-mismatch fallthrough, the
// error asymmetries) — because legacy/Cerbos DECISION PARITY is the M1
// cutover contract (the shadow-mode gate compares verdicts request by
// request).  Behavioural fixes belong after cutover, not here.

// ResolveBindings resolves the authenticated subject's role bindings across
// all of their organizations.  It mirrors the legacy ACL accumulation exactly
// (decision parity is the M1 contract; see the shadow-mode gate):
//
//   - bindings are resolved across EVERY organization in the subject's
//     claims, not just a request-scoped one, because the legacy Allow*
//     functions consult the plural acl.Organizations list built across all
//     organizations (handler.go:107/159/194).  A scoped-org optimization is
//     recorded for post-cutover (A15 decision caching);
//   - the resolver never reads Role.Spec.Scopes: the generated policies'
//     scope buckets decide what each binding level actually grants.
//
// The result is deduplicated and sorted, so semantically identical inputs
// yield identical slices.
func (r *RBAC) ResolveBindings(ctx context.Context, info *authorization.Info) ([]cerbos.RoleBinding, error) {
	// The legacy path dereferences Userinfo unconditionally (rbac.go GetACL);
	// fail loudly rather than replicating a panic.
	if info == nil || info.Userinfo == nil {
		return nil, fmt.Errorf("%w: no userinfo present", ErrNoAuthz)
	}

	subject := info.Userinfo.Sub

	// Actor-class dispatch, mirroring GetACL: the account type claim decides
	// the resolution path, defaulting to a user account when absent.
	authz := info.Userinfo.HttpsunikornCloudOrgauthz

	accountType := openapi.User
	if authz != nil {
		accountType = authz.Acctype
	}

	var bindings []cerbos.RoleBinding

	var err error

	switch accountType {
	case openapi.System:
		bindings, err = r.resolveSystemAccountBindings(ctx, subject)
	case openapi.Service:
		bindings, err = r.resolveServiceAccountBindings(ctx, subject, authz)
	case openapi.User:
		bindings, err = r.resolveUserBindings(ctx, subject, authz)
	default:
		bindings, err = r.resolveUserBindings(ctx, subject, authz)
	}

	if err != nil {
		return nil, err
	}

	return normalizeBindings(bindings), nil
}

// normalizeBindings sorts and deduplicates the resolved bindings: the same
// grant reached through two groups must appear once, and the deterministic
// order keeps requests, logs and test expectations stable (the request
// builder sorts the rendered strings again anyway).
func normalizeBindings(bindings []cerbos.RoleBinding) []cerbos.RoleBinding {
	slices.SortFunc(bindings, func(a, b cerbos.RoleBinding) int {
		return cmp.Or(
			strings.Compare(a.RoleID, b.RoleID),
			strings.Compare(a.OrganizationID, b.OrganizationID),
			strings.Compare(a.ProjectID, b.ProjectID),
		)
	})

	return slices.Compact(bindings)
}

// globalRoleBindings emits one global binding per role ID, validating each
// against the role catalogue exactly like the legacy global accumulation
// (accumulateGlobalPermissions): a configured role with no Role CR is a hard
// consistency error, never a silently missing grant.
func globalRoleBindings(roleIDs []string, roles map[string]*unikornv1.Role) ([]cerbos.RoleBinding, error) {
	bindings := make([]cerbos.RoleBinding, 0, len(roleIDs))

	for _, roleID := range roleIDs {
		if _, ok := roles[roleID]; !ok {
			return nil, fmt.Errorf("%w: role %s referenced by global subject", errors.ErrConsistency, roleID)
		}

		bindings = append(bindings, cerbos.RoleBinding{RoleID: roleID})
	}

	return bindings, nil
}

// resolveSystemAccountBindings mirrors processSystemAccountACL: the X.509
// common name maps to exactly one globally scoped role.  An unregistered
// common name is an ERROR (parity), never an empty grant set — an empty
// result would silently mask a configuration mistake.
func (r *RBAC) resolveSystemAccountBindings(ctx context.Context, subject string) ([]cerbos.RoleBinding, error) {
	roleID, ok := r.options.SystemAccountRoleIDs[subject]
	if !ok {
		return nil, fmt.Errorf("%w: system account '%s' not registered", errors.ErrConsistency, subject)
	}

	roles, err := r.getRoles(ctx)
	if err != nil {
		return nil, err
	}

	return globalRoleBindings([]string{roleID}, roles)
}

// resolveServiceAccountBindings mirrors processServiceAccountACL: membership
// comes from group.Spec.ServiceAccountIDs within the single organization the
// account is bound to.
func (r *RBAC) resolveServiceAccountBindings(ctx context.Context, subject string, authz *openapi.AuthClaims) ([]cerbos.RoleBinding, error) {
	// getServiceAccountContext parity: service accounts are bound to exactly
	// one organization.
	if authz == nil {
		return nil, ErrNoAuthz
	}

	if len(authz.OrgIds) != 1 {
		return nil, ErrWrongOrganizationCount
	}

	organizationID := authz.OrgIds[0]

	// ORG-MISMATCH FALLTHROUGH, PORTED AS-IS: a legacy request scoped to an
	// organization other than the service account's home organization does
	// NOT deny — processServiceAccountACL swallows ErrNotInOrganization and
	// falls through to the home-org unscoped resolution, leaving the
	// home-org permissions in the plural acl.Organizations list the Allow*
	// functions consult.  This resolver has no request-scope parameter at
	// all — the home-org bindings below are resolved unconditionally — so a
	// check against another organization simply matches no binding: the
	// same verdicts, fallthrough included.  The legacy code carries an
	// information-leak TODO about returning ErrNotInOrganization instead;
	// that fix is deliberately deferred to post-cutover so A7's shadow
	// comparison stays clean.
	//
	// An unprovisioned home organization is a hard error here, unlike the
	// user path's silent skip below — a legacy asymmetry replicated as-is.
	organizationNamespace, err := r.getOrganizationNamespace(ctx, organizationID)
	if err != nil {
		return nil, fmt.Errorf("%w, failed to get organization namespace %q", err, organizationID)
	}

	groups, err := r.getGroups(ctx, organizationNamespace, groupServiceAccountFilter(subject))
	if err != nil {
		return nil, err
	}

	// Membership in no groups short-circuits to an empty grant set before
	// the role catalogue is read (parity with the legacy early return).
	if len(groups) == 0 {
		return nil, nil
	}

	roles, err := r.getRoles(ctx)
	if err != nil {
		return nil, err
	}

	return r.groupBindings(ctx, organizationID, groups, roles)
}

// resolveUserBindings mirrors processUserAccountACL plus the unscoped
// accumulation it delegates to (accumulatePermissions).
func (r *RBAC) resolveUserBindings(ctx context.Context, subject string, authz *openapi.AuthClaims) ([]cerbos.RoleBinding, error) {
	// Checked BEFORE the platform-administrator short-circuit, so even an
	// administrator subject fails without claims (parity).
	if authz == nil {
		return nil, ErrNoAuthz
	}

	roles, err := r.getRoles(ctx)
	if err != nil {
		return nil, err
	}

	// Platform administrators EARLY RETURN with the configured global roles
	// only: group memberships are never consulted, even if the subject has
	// some (parity — and privilege containment: admin authority comes from
	// static configuration, not from mutable group state).
	if slices.Contains(r.options.PlatformAdministratorSubjects, subject) {
		return globalRoleBindings(r.options.PlatformAdministratorRoleIDs, roles)
	}

	var bindings []cerbos.RoleBinding

	for _, organizationID := range authz.OrgIds {
		organization := &unikornv1.Organization{}

		if err := r.client.Get(ctx, client.ObjectKey{Namespace: r.namespace, Name: organizationID}, organization); err != nil {
			return nil, err
		}

		// An organization without a provisioned namespace is SILENTLY
		// skipped (accumulatePermissions parity) — unlike the service
		// account path, where the equivalent condition is a hard error.
		if organization.Status.Namespace == "" {
			continue
		}

		groups, err := r.getGroups(ctx, organization.Status.Namespace, r.groupSubjectFilter(ctx, subject))
		if err != nil {
			return nil, err
		}

		organizationBindings, err := r.groupBindings(ctx, organizationID, groups, roles)
		if err != nil {
			return nil, err
		}

		bindings = append(bindings, organizationBindings...)
	}

	return bindings, nil
}

// groupBindings emits the bindings granted by a subject's member groups in
// one organization, mirroring the legacy accumulation:
//
//   - EVERY role granted by a member group yields an org-level binding — the
//     legacy code applies role.Spec.Scopes.Organization organization-wide
//     (accumulateOrganizationPermissions);
//   - ADDITIONALLY a project-level binding for each project whose
//     Spec.GroupIDs contains a member group (accumulateProjectPermissions).
//
// BOTH levels are emitted for a project-linked group: the generated policies'
// scope buckets decide what each binding level actually grants, so a role
// carrying only project scopes produces an org binding that activates nothing
// — exactly like the legacy accumulation adding an empty endpoint list.
//
// Reference-consistency parity is deliberately asymmetric, like the legacy
// code: a member group referencing a nonexistent role is a hard error, while
// a project referencing an unknown group is silently skipped.
//
// Groups NEVER yield global bindings: the legacy global accumulation
// deliberately does not accept groups, and neither does this.
func (r *RBAC) groupBindings(ctx context.Context, organizationID string, groups map[string]*unikornv1.Group, roles map[string]*unikornv1.Role) ([]cerbos.RoleBinding, error) {
	var bindings []cerbos.RoleBinding

	for groupID, group := range groups {
		for _, roleID := range group.Spec.RoleIDs {
			if _, ok := roles[roleID]; !ok {
				return nil, fmt.Errorf("%w: role %s referenced by group %s does not exist", errors.ErrConsistency, roleID, groupID)
			}

			bindings = append(bindings, cerbos.RoleBinding{RoleID: roleID, OrganizationID: organizationID})
		}
	}

	projects, err := r.getProjects(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	for i := range projects.Items {
		projectBindings, err := projectGroupBindings(organizationID, &projects.Items[i], groups, roles)
		if err != nil {
			return nil, err
		}

		bindings = append(bindings, projectBindings...)
	}

	return bindings, nil
}

// projectGroupBindings emits the project-level bindings for one project (see
// groupBindings for the parity contract).
func projectGroupBindings(organizationID string, project *unikornv1.Project, groups map[string]*unikornv1.Group, roles map[string]*unikornv1.Role) ([]cerbos.RoleBinding, error) {
	var bindings []cerbos.RoleBinding

	for _, groupID := range project.Spec.GroupIDs {
		group, ok := groups[groupID]
		if !ok {
			// An unknown (or non-member) group linked to a project is
			// silently skipped (parity with the legacy project accumulation).
			continue
		}

		for _, roleID := range group.Spec.RoleIDs {
			if _, ok := roles[roleID]; !ok {
				return nil, fmt.Errorf("%w: role %s referenced by group %s does not exist", errors.ErrConsistency, roleID, groupID)
			}

			bindings = append(bindings, cerbos.RoleBinding{RoleID: roleID, OrganizationID: organizationID, ProjectID: project.Name})
		}
	}

	return bindings, nil
}
