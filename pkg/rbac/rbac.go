/*
Copyright 2024-2025 the Unikorn Authors.
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
	"context"
	goerrors "errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrResourceReference      = goerrors.New("resource reference error")
	ErrNoAuthz                = goerrors.New("no authorization data in userinfo")
	ErrWrongOrganizationCount = goerrors.New("expected exactly one organization ID")
	ErrNotInOrganization      = goerrors.New("subject not a member of organization")
)

type Options struct {
	PlatformAdministratorRoleIDs  []string
	PlatformAdministratorSubjects []string
	SystemAccountRoleIDs          map[string]string
}

func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.StringSliceVar(&o.PlatformAdministratorRoleIDs, "platform-administrator-role-ids", nil, "Platform administrator role ID.")
	f.StringSliceVar(&o.PlatformAdministratorSubjects, "platform-administrator-subjects", nil, "Platform administrators.")
	f.StringToStringVar(&o.SystemAccountRoleIDs, "system-account-roles-ids", nil, "System accounts map the X.509 Common Name to a role ID.")
}

// RBAC contains all the scoping rules for services across the platform.
type RBAC struct {
	client    client.Client
	namespace string
	options   *Options
}

// New creates a new RBAC client.
func New(client client.Client, namespace string, options *Options) *RBAC {
	return &RBAC{
		client:    client,
		namespace: namespace,
		options:   options,
	}
}

type groupSubjectFilterGetter func(id string) func(unikornv1.Group) bool

// groupSubjectFilter checks if the group contains the user.
// It first checks the new Subjects field. If no match is found and the group
// still has the deprecated UserIDs field populated, it resolves the subject to
// an OrganizationUser resource name and checks UserIDs.
func (r *RBAC) groupSubjectFilter(ctx context.Context, subject string) func(unikornv1.Group) bool {
	return func(group unikornv1.Group) bool {
		if slices.ContainsFunc(group.Spec.Subjects, func(s unikornv1.GroupSubject) bool {
			// The issuer is not validated here. All subjects are expected to have an empty issuer.
			// See updateGroups in handler/users/client.go.
			return s.ID == subject
		}) {
			return false
		}

		// Deprecated: fall back to the legacy userIDs field for groups that have not
		// been migrated to subjects yet. UserIDs contain OrganizationUser resource
		// names (not email subjects), so we must resolve the subject first.
		if len(group.Spec.UserIDs) > 0 {
			if orgUserName, err := r.resolveOrganizationUserName(ctx, group.Namespace, subject); err == nil {
				if slices.Contains(group.Spec.UserIDs, orgUserName) {
					slog.Warn("group matched via deprecated userIDs field, migration to subjects required",
						"group", group.Name, "namespace", group.Namespace, "userID", orgUserName)

					return false
				}
			}
		}

		return true
	}
}

// groupServiceAccountFilter checks if the group contains a service account ID.
func groupServiceAccountFilter(id string) func(unikornv1.Group) bool {
	return func(group unikornv1.Group) bool {
		return !slices.Contains(group.Spec.ServiceAccountIDs, id)
	}
}

// getGroups returns a map of groups the user is a member of, indexed by ID.
func (r *RBAC) getGroups(ctx context.Context, namespace string, filter func(unikornv1.Group) bool) (map[string]*unikornv1.Group, error) {
	result := &unikornv1.GroupList{}

	if err := r.client.List(ctx, result, &client.ListOptions{Namespace: namespace}); err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, filter)

	out := map[string]*unikornv1.Group{}

	for i := range result.Items {
		out[result.Items[i].Name] = &result.Items[i]
	}

	return out, nil
}

// getRoles returns a map of roles in the system indexed by ID.
func (r *RBAC) getRoles(ctx context.Context) (map[string]*unikornv1.Role, error) {
	result := &unikornv1.RoleList{}

	if err := r.client.List(ctx, result, &client.ListOptions{Namespace: r.namespace}); err != nil {
		return nil, err
	}

	out := map[string]*unikornv1.Role{}

	for i := range result.Items {
		out[result.Items[i].Name] = &result.Items[i]
	}

	return out, nil
}

// getProjects grabs all projects for an organization.
func (r *RBAC) getProjects(ctx context.Context, organizationID string) (*unikornv1.ProjectList, error) {
	requirement, err := labels.NewRequirement(constants.OrganizationLabel, selection.Equals, []string{organizationID})
	if err != nil {
		return nil, err
	}

	selector := labels.NewSelector().Add(*requirement)

	result := &unikornv1.ProjectList{}

	if err := r.client.List(ctx, result, &client.ListOptions{LabelSelector: selector}); err != nil {
		return nil, err
	}

	return result, nil
}

func (r *RBAC) getOrganizationNamespace(ctx context.Context, orgID string) (string, error) {
	var org unikornv1.Organization
	if err := r.client.Get(ctx, client.ObjectKey{Namespace: r.namespace, Name: orgID}, &org); err != nil {
		return "", err
	}

	if org.Status.Namespace == "" {
		return "", fmt.Errorf("%w: organization %q has no namespace", ErrResourceReference, orgID)
	}

	return org.Status.Namespace, nil
}

// resolveOrganizationUserName maps a user subject (email) to the OrganizationUser
// resource name in the given namespace. This is only needed to support the
// legacy UserIDs field on groups during migration to the Subjects field.
func (r *RBAC) resolveOrganizationUserName(ctx context.Context, namespace, subject string) (string, error) {
	users := &unikornv1.UserList{}
	if err := r.client.List(ctx, users); err != nil {
		return "", err
	}

	idx := slices.IndexFunc(users.Items, func(u unikornv1.User) bool {
		return u.Spec.Subject == subject
	})

	if idx < 0 {
		return "", fmt.Errorf("%w: user not found for subject %q", ErrResourceReference, subject)
	}

	user := &users.Items[idx]

	selector := labels.SelectorFromSet(map[string]string{
		constants.UserLabel: user.Name,
	})

	orgUsers := &unikornv1.OrganizationUserList{}

	if err := r.client.List(ctx, orgUsers, &client.ListOptions{
		LabelSelector: selector,
		Namespace:     namespace,
	}); err != nil {
		return "", err
	}

	if len(orgUsers.Items) != 1 {
		return "", fmt.Errorf("%w: expected 1 organization user for subject %q in namespace %q, got %d",
			ErrResourceReference, subject, namespace, len(orgUsers.Items))
	}

	return orgUsers.Items[0].Name, nil
}

func convertOperation(in unikornv1.Operation) openapi.AclOperation {
	switch in {
	case unikornv1.Create:
		return openapi.Create
	case unikornv1.Read:
		return openapi.Read
	case unikornv1.Update:
		return openapi.Update
	case unikornv1.Delete:
		return openapi.Delete
	}

	return ""
}

func convertOperationList(in []unikornv1.Operation) openapi.AclOperations {
	out := make(openapi.AclOperations, len(in))

	for i := range in {
		out[i] = convertOperation(in[i])
	}

	return out
}

// addScopesToEndpointList adds a new scope to the existing list if it doesn't exist,
// or merges permissions with an existing entry.  If the endpoints pointer is uninitialized
// then one is allocated.  If the resulting endpoints list is empty, then nil is returned.
// This behavior is primarily to cater for OpenAPI's love of pointers to lists, and omitting
// empty lists from the final output.
func addScopesToEndpointList(e *openapi.AclEndpoints, scopes []unikornv1.RoleScope) *openapi.AclEndpoints {
	var endpoints openapi.AclEndpoints

	if e != nil {
		endpoints = *e
	}

	for _, scope := range scopes {
		operations := convertOperationList(scope.Operations)

		indexFunc := func(ep openapi.AclEndpoint) bool {
			return ep.Name == scope.Name
		}

		// If an existing entry exists, create a union of operations.
		if index := slices.IndexFunc(endpoints, indexFunc); index >= 0 {
			endpoint := &endpoints[index]

			endpoint.Operations = slices.Concat(endpoint.Operations, operations)
			slices.Sort(endpoint.Operations)

			endpoint.Operations = slices.Compact(endpoint.Operations)

			continue
		}

		// If not add a new entry.
		endpoints = append(endpoints, openapi.AclEndpoint{
			Name:       scope.Name,
			Operations: operations,
		})
	}

	if len(endpoints) == 0 {
		return nil
	}

	return &endpoints
}

// accumulateGlobalPermissions adds any global permissions referenced in roles by the
// supplied groups the subject is a member of to the ACL.
// NOTE: this deliberately doesn't accept groups, as standard users should never be
// granted global permissions.  If someone changes this interface alarm bells should
// start ringing.
func accumulateGlobalPermissions(acl *openapi.Acl, roleIDs []string, roles map[string]*unikornv1.Role) error {
	for _, roleID := range roleIDs {
		role, ok := roles[roleID]
		if !ok {
			return fmt.Errorf("%w: role %s referenced by global subject", errors.ErrConsistency, roleID)
		}

		acl.Global = addScopesToEndpointList(acl.Global, role.Spec.Scopes.Global)
	}

	return nil
}

// accumulateOrganizationPermissions adds any organization permissions referenced in roles
// by the supplied groups, and returns a new endpoint list if any permissions were added.
func accumulateOrganizationPermissions(groups map[string]*unikornv1.Group, roles map[string]*unikornv1.Role) (*openapi.AclEndpoints, error) {
	var endpoints *openapi.AclEndpoints

	for groupID, group := range groups {
		for _, roleID := range group.Spec.RoleIDs {
			role, ok := roles[roleID]
			if !ok {
				return nil, fmt.Errorf("%w: role %s referenced by group %s does not exist", errors.ErrConsistency, roleID, groupID)
			}

			endpoints = addScopesToEndpointList(endpoints, role.Spec.Scopes.Organization)
		}
	}

	return endpoints, nil
}

// accumulateProjectPermissions adds an project permissions referenced in roles by groups in
// the project, and returns a new endpoint list if any permissions were added.  Projects may
// contain groups that the subject is not a member of which can be safely ignored.
func accumulateProjectPermissions(groups map[string]*unikornv1.Group, roles map[string]*unikornv1.Role, project *unikornv1.Project) (*openapi.AclEndpoints, error) {
	var endpoints *openapi.AclEndpoints

	for _, groupID := range project.Spec.GroupIDs {
		group, ok := groups[groupID]
		if !ok {
			continue
		}

		for _, roleID := range group.Spec.RoleIDs {
			role, ok := roles[roleID]
			if !ok {
				return nil, fmt.Errorf("%w: role %s referenced by group %s does not exist", errors.ErrConsistency, roleID, groupID)
			}

			endpoints = addScopesToEndpointList(endpoints, role.Spec.Scopes.Project)
		}
	}

	return endpoints, nil
}

// accumulateOrganizationScopedProject looks at all groups linked to the project and accumulates
// any endpoint permissions that apply.  If there are any permissions, then return the
// scoped endpoints, otherwise nil.
func accumulateOrganizationScopedProject(groups map[string]*unikornv1.Group, roles map[string]*unikornv1.Role, project *unikornv1.Project) (*openapi.AclProject, error) {
	endpoints, err := accumulateProjectPermissions(groups, roles, project)
	if err != nil {
		return nil, err
	}

	if endpoints != nil && len(*endpoints) > 0 {
		acl := &openapi.AclProject{
			Id:        project.Name,
			Endpoints: *endpoints,
		}

		return acl, nil
	}

	//nolint:nilnil
	return nil, nil
}

// accumulateOrganizationScopedProjects iterates over all projects the subject has access to then
// accumulates any permissions that apply to each project.  If there are any permissions
// then add them to the ACL.
func accumulateOrganizationScopedProjects(acl *openapi.Acl, groups map[string]*unikornv1.Group, roles map[string]*unikornv1.Role, projects *unikornv1.ProjectList) error {
	aclProjects := make(openapi.AclProjectList, 0, len(projects.Items))

	for i := range projects.Items {
		project := &projects.Items[i]

		aclProject, err := accumulateOrganizationScopedProject(groups, roles, project)
		if err != nil {
			return err
		}

		if aclProject == nil {
			continue
		}

		aclProjects = append(aclProjects, *aclProject)
	}

	if len(aclProjects) > 0 {
		acl.Projects = &aclProjects
	}

	return nil
}

// accumulateOrganizationScopedPermissions are only applied for scoped ACL accesses.  This accepts
// a set of groups the subject is a member of, adds any organization scoped permissions,
// then adds any project scoped permissions.
func (r *RBAC) accumulateOrganizationScopedPermissions(ctx context.Context, acl *openapi.Acl, groups map[string]*unikornv1.Group, roles map[string]*unikornv1.Role, organizationID string) error {
	// No scope is asked for, so none shall be populated!
	if organizationID == "" {
		return nil
	}

	organizationEndpoints, err := accumulateOrganizationPermissions(groups, roles)
	if err != nil {
		return err
	}

	if organizationEndpoints != nil {
		acl.Organization = &openapi.AclOrganization{
			Id:        organizationID,
			Endpoints: organizationEndpoints,
		}
	}

	projects, err := r.getProjects(ctx, organizationID)
	if err != nil {
		return err
	}

	if err := accumulateOrganizationScopedProjects(acl, groups, roles, projects); err != nil {
		return err
	}

	return nil
}

// organizationToSubjectMap temporary mapping from an organization ID to a subject.
// This will cease to exist when groups have a consistent idea of a subject.
type organizationToSubjectMap map[string]string

// accumulatePermissions accumulates unscoped permissions across all organizations that the
// subject has access to.
//
//nolint:cyclop
func (r *RBAC) accumulatePermissions(ctx context.Context, acl *openapi.Acl, organizationMap organizationToSubjectMap, groupFilter groupSubjectFilterGetter) error {
	roles, err := r.getRoles(ctx)
	if err != nil {
		return err
	}

	organizations := make([]openapi.AclOrganization, 0, len(organizationMap))

	for organizationID, subjectID := range organizationMap {
		var organization unikornv1.Organization

		if err := r.client.Get(ctx, client.ObjectKey{Namespace: r.namespace, Name: organizationID}, &organization); err != nil {
			return err
		}

		if organization.Status.Namespace == "" {
			continue
		}

		groups, err := r.getGroups(ctx, organization.Status.Namespace, groupFilter(subjectID))
		if err != nil {
			return err
		}

		endpoints, err := accumulateOrganizationPermissions(groups, roles)
		if err != nil {
			return err
		}

		organizationACL := &openapi.AclOrganization{
			Id:        organizationID,
			Endpoints: endpoints,
		}

		projects, err := r.getProjects(ctx, organizationID)
		if err != nil {
			return err
		}

		aclProjects := make([]openapi.AclProject, 0, len(projects.Items))

		for j := range projects.Items {
			project := &projects.Items[j]

			endpoints, err := accumulateProjectPermissions(groups, roles, project)
			if err != nil {
				return err
			}

			if endpoints == nil || len(*endpoints) == 0 {
				continue
			}

			aclProjects = append(aclProjects, openapi.AclProject{
				Id:        project.Name,
				Endpoints: *endpoints,
			})
		}

		if len(aclProjects) > 0 {
			organizationACL.Projects = &aclProjects
		}

		organizations = append(organizations, *organizationACL)
	}

	if len(organizations) > 0 {
		acl.Organizations = &organizations
	}

	return nil
}

// processSystemAccountACL looks up the role assigned to a system account and adds
// the permissions to the ACL.  As system accounts operate on behalf of users, the
// assumption here is all roles are global and span all user organizations and projects.
// NOTE: the subject here should ultimately be a certificate's CN or a SPIFFE ID.
func (r *RBAC) processSystemAccountACL(ctx context.Context, subject string) (*openapi.Acl, error) {
	roleID, ok := r.options.SystemAccountRoleIDs[subject]
	if !ok {
		return nil, fmt.Errorf("%w: system account '%s' not registered", errors.ErrConsistency, subject)
	}

	roles, err := r.getRoles(ctx)
	if err != nil {
		return nil, err
	}

	acl := &openapi.Acl{}

	if err := accumulateGlobalPermissions(acl, []string{roleID}, roles); err != nil {
		return nil, err
	}

	return acl, nil
}

func (r *RBAC) getServiceAccountContext(ctx context.Context, organizationID string, authz *openapi.AuthClaims) (string, string, error) {
	if authz == nil {
		return "", "", ErrNoAuthz
	}

	if len(authz.OrgIds) != 1 {
		return "", "", ErrWrongOrganizationCount
	}

	subjectOrganizationID := authz.OrgIds[0]
	if organizationID != "" && subjectOrganizationID != organizationID {
		return "", "", ErrNotInOrganization
	}

	organizationNamespace, err := r.getOrganizationNamespace(ctx, subjectOrganizationID)
	if err != nil {
		return "", "", fmt.Errorf("%w, failed to get organization namespace %q", err, subjectOrganizationID)
	}

	return subjectOrganizationID, organizationNamespace, nil
}

// processServiceAccountACL looks up a service account, any groups it's a member of,
// then adds their permissions to the ACL.  As service accounts are bound to a specific
// organization we must check the scoped organization matches that of the service account.
//
//nolint:cyclop
func (r *RBAC) processServiceAccountACL(ctx context.Context, subject, organizationID string, authz *openapi.AuthClaims) (*openapi.Acl, error) {
	subjectOrganizationID, organizationNamespace, err := r.getServiceAccountContext(ctx, organizationID, authz)
	if err != nil {
		// TODO: same information leakage concern as processUserAccountACL — see
		// the TODO there for details. Once downstream consumers are audited we
		// should return ErrNotInOrganization here instead of falling through.
		if !goerrors.Is(err, ErrNotInOrganization) {
			return nil, err
		}

		// Org mismatch: skip scoped section, fall through to unscoped ACL
		// using the service account's home org.
		subjectOrganizationID = authz.OrgIds[0]

		organizationNamespace, err = r.getOrganizationNamespace(ctx, subjectOrganizationID)
		if err != nil {
			return nil, fmt.Errorf("%w, failed to get organization namespace %q", err, subjectOrganizationID)
		}
	}

	groups, err := r.getGroups(ctx, organizationNamespace, groupServiceAccountFilter(subject))
	if err != nil {
		return nil, err
	}

	acl := &openapi.Acl{}

	// Nothing to do.
	if len(groups) == 0 {
		return acl, nil
	}

	roles, err := r.getRoles(ctx)
	if err != nil {
		return nil, err
	}

	// Scoped ACL handling — only when the requested org matches the service account's org.
	if organizationID == "" || organizationID == subjectOrganizationID {
		if err := r.accumulateOrganizationScopedPermissions(ctx, acl, groups, roles, subjectOrganizationID); err != nil {
			return nil, err
		}
	}

	// Unscoped ACL handling.
	organizationSubjectMap := organizationToSubjectMap{
		subjectOrganizationID: subject,
	}

	if err := r.accumulatePermissions(ctx, acl, organizationSubjectMap, groupServiceAccountFilter); err != nil {
		return nil, err
	}

	return acl, nil
}

// processUserAccountACL ensures the user exists and is active, looks up any groups it's
// a member of and adds their permissions to the ACL.
//
//nolint:cyclop,nestif
func (r *RBAC) processUserAccountACL(ctx context.Context, subject, organizationID string, authz *openapi.AuthClaims) (*openapi.Acl, error) {
	if authz == nil {
		return nil, ErrNoAuthz
	}

	roles, err := r.getRoles(ctx)
	if err != nil {
		return nil, err
	}

	acl := &openapi.Acl{}

	if slices.Contains(r.options.PlatformAdministratorSubjects, subject) {
		if err := accumulateGlobalPermissions(acl, r.options.PlatformAdministratorRoleIDs, roles); err != nil {
			return nil, err
		}

		return acl, nil
	}

	if organizationID != "" {
		if !slices.Contains(authz.OrgIds, organizationID) {
			return nil, ErrNotInOrganization
		}

		organizationNamespace, err := r.getOrganizationNamespace(ctx, organizationID)
		if err != nil {
			return nil, fmt.Errorf("%w, failed to get organization namespace %q", err, organizationID)
		}

		groups, err := r.getGroups(ctx, organizationNamespace, r.groupSubjectFilter(ctx, subject))
		if err != nil {
			return nil, err
		}

		// Nothing to do.
		if len(groups) == 0 {
			return acl, nil
		}

		// Scoped ACL handling.
		if err := r.accumulateOrganizationScopedPermissions(ctx, acl, groups, roles, organizationID); err != nil {
			return nil, err
		}
	}

	if len(authz.OrgIds) == 0 {
		return acl, nil
	}

	// Unscoped ACL handling.
	organizationSubjectMap := make(organizationToSubjectMap, len(authz.OrgIds))

	for _, organizationID := range authz.OrgIds {
		organizationSubjectMap[organizationID] = subject
	}

	if err := r.accumulatePermissions(ctx, acl, organizationSubjectMap, func(id string) func(unikornv1.Group) bool {
		return r.groupSubjectFilter(ctx, id)
	}); err != nil {
		return nil, err
	}

	return acl, nil
}

// filterEndpoints returns a filtered copy of endpoints keeping only (name, operation)
// pairs that are permitted by serviceEndpoints. The bool return distinguishes two
// empty cases: false means nothing survived (either the service grants no access at
// all, or the intersection was empty), true means at least one operation was kept.
// Callers use the bool to decide whether to drop the enclosing resource entirely,
// rather than returning an ambiguous nil slice.
func filterEndpoints(endpoints openapi.AclEndpoints, serviceEndpoints *openapi.AclEndpoints) (openapi.AclEndpoints, bool) {
	if serviceEndpoints == nil {
		return nil, false
	}

	result := make(openapi.AclEndpoints, 0, len(endpoints))

	for _, ep := range endpoints {
		ops := make(openapi.AclOperations, 0, len(ep.Operations))

		for _, op := range ep.Operations {
			if operationAllowedByEndpoints(*serviceEndpoints, ep.Name, op) == nil {
				ops = append(ops, op)
			}
		}

		if len(ops) > 0 {
			result = append(result, openapi.AclEndpoint{Name: ep.Name, Operations: ops})
		}
	}

	if len(result) == 0 {
		return nil, false
	}

	return result, true
}

// filterEndpointsPtr is a pointer-friendly wrapper around filterEndpoints that
// returns nil when the input is nil or nothing survives the intersection.
func filterEndpointsPtr(endpoints *openapi.AclEndpoints, serviceEndpoints *openapi.AclEndpoints) *openapi.AclEndpoints {
	if endpoints == nil {
		return nil
	}

	result, ok := filterEndpoints(*endpoints, serviceEndpoints)
	if !ok {
		return nil
	}

	return &result
}

// filterProjects filters a project list, dropping any project whose endpoints are
// entirely outside the service allow set.
func filterProjects(projects *openapi.AclProjectList, serviceEndpoints *openapi.AclEndpoints) *openapi.AclProjectList {
	if projects == nil {
		return nil
	}

	result := make(openapi.AclProjectList, 0, len(*projects))

	for _, proj := range *projects {
		endpoints, ok := filterEndpoints(proj.Endpoints, serviceEndpoints)
		if ok {
			result = append(result, openapi.AclProject{Id: proj.Id, Endpoints: endpoints})
		}
	}

	if len(result) == 0 {
		return nil
	}

	return &result
}

// intersectACL returns a copy of userACL filtered so that only (resource, operation)
// tuples also permitted by serviceACL.Global are retained. Because system accounts
// accumulate permissions exclusively at global scope, the service's global endpoints
// act as the single allow-list for every scope level of the user's ACL — a service
// with global read on a resource type implicitly permits a user's project-scoped read
// on that same resource, but the reverse is not true.
func intersectACL(userACL *openapi.Acl, serviceACL *openapi.Acl) *openapi.Acl {
	svc := serviceACL.Global
	result := &openapi.Acl{}

	result.Global = filterEndpointsPtr(userACL.Global, svc)

	if userACL.Organization != nil {
		endpoints := filterEndpointsPtr(userACL.Organization.Endpoints, svc)
		projects := filterProjects(userACL.Organization.Projects, svc)

		if endpoints != nil || projects != nil {
			result.Organization = &openapi.AclOrganization{
				Id:        userACL.Organization.Id,
				Endpoints: endpoints,
				Projects:  projects,
			}
		}
	}

	if userACL.Organizations != nil {
		orgs := make(openapi.AclOrganizationList, 0, len(*userACL.Organizations))

		for _, org := range *userACL.Organizations {
			endpoints := filterEndpointsPtr(org.Endpoints, svc)
			projects := filterProjects(org.Projects, svc)

			if endpoints != nil || projects != nil {
				orgs = append(orgs, openapi.AclOrganization{
					Id:        org.Id,
					Endpoints: endpoints,
					Projects:  projects,
				})
			}
		}

		if len(orgs) > 0 {
			result.Organizations = &orgs
		}
	}

	result.Projects = filterProjects(userACL.Projects, svc)

	return result
}

// getSystemAccountACL returns the ACL for a system account, handling impersonation.
// If the service has signalled impersonation, the ACL is the intersection of the
// end-user's ACL and the service's own ACL (confused deputy prevention).
func (r *RBAC) getSystemAccountACL(ctx context.Context, subject, organizationID string) (*openapi.Acl, error) {
	p, err := principal.FromContext(ctx)
	if err != nil || !principal.ImpersonateFromContext(ctx) || p.Actor == "" {
		return r.processSystemAccountACL(ctx, subject)
	}

	// OrganizationIDs is populated by the identity middleware (generatePrincipal)
	// from the userinfo claims and propagated through the X-Principal header by
	// all current callers. The singular OrganizationID fallback is a defensive
	// safety net: if a caller only sets OrganizationID (e.g. a future service
	// that hasn't adopted the full principal propagation), the user still gets
	// permissions for at least the scoped organization rather than an empty ACL.
	organizationIDs := p.OrganizationIDs
	if len(organizationIDs) == 0 && p.OrganizationID != "" {
		organizationIDs = []string{p.OrganizationID}
	}

	userACL, err := r.processUserAccountACL(ctx, p.Actor, organizationID, &openapi.AuthClaims{
		Acctype: openapi.User,
		OrgIds:  organizationIDs,
	})
	if err != nil {
		return nil, err
	}

	serviceACL, err := r.processSystemAccountACL(ctx, subject)
	if err != nil {
		return nil, err
	}

	return intersectACL(userACL, serviceACL), nil
}

// GetACL returns a granular set of permissions for a user based on their scope.
// This is used for API level access control and UX.
func (r *RBAC) GetACL(ctx context.Context, organizationID string) (*openapi.Acl, error) {
	// All the tokens introspection info is in the context...
	info, err := authorization.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	var (
		userinfo    = info.Userinfo
		subject     = userinfo.Sub
		accountType = openapi.User
	)

	authz := userinfo.HttpsunikornCloudOrgauthz
	if authz != nil {
		accountType = authz.Acctype
	}

	if accountType == openapi.System {
		return r.getSystemAccountACL(ctx, subject, organizationID)
	}

	if accountType == openapi.Service {
		return r.processServiceAccountACL(ctx, subject, organizationID, authz)
	}

	return r.processUserAccountACL(ctx, subject, organizationID, authz)
}

func (r *RBAC) NewSuperContext(ctx context.Context) (context.Context, error) {
	roles, err := r.getRoles(ctx)
	if err != nil {
		return nil, err
	}

	var globalACL openapi.AclEndpoints

	for _, id := range r.options.PlatformAdministratorRoleIDs {
		if role, ok := roles[id]; ok {
			addScopesToEndpointList(&globalACL, role.Spec.Scopes.Global)
		}
	}

	acl := &openapi.Acl{}

	if len(globalACL) != 0 {
		acl.Global = &globalACL
	}

	return NewContext(ctx, acl), nil
}
