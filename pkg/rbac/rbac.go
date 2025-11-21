/*
Copyright 2024-2025 the Unikorn Authors.

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
	"maps"
	"slices"

	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrUserNotFound             = goerrors.New("user not found")
	ErrOrganizationUserNotFound = goerrors.New("organization user not found")
	ErrServiceAccountNotFound   = goerrors.New("service account not found")
	ErrInternal                 = goerrors.New("rbac")
)

func IsNotFoundError(err error) bool {
	return goerrors.Is(err, ErrUserNotFound) ||
		goerrors.Is(err, ErrOrganizationUserNotFound) ||
		goerrors.Is(err, ErrServiceAccountNotFound)
}

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

func (r *RBAC) GetUser(ctx context.Context, subject string) (*unikornv1.User, error) {
	var list unikornv1.UserList
	if err := r.client.List(ctx, &list); err != nil {
		return nil, err
	}

	isTargetUser := func(user unikornv1.User) bool {
		return user.Spec.Subject == subject
	}

	index := slices.IndexFunc(list.Items, isTargetUser)
	if index < 0 {
		return nil, ErrUserNotFound
	}

	return &list.Items[index], nil
}

// GetActiveUser returns a user that match the subject and is active.
func (r *RBAC) GetActiveUser(ctx context.Context, subject string) (*unikornv1.User, error) {
	user, err := r.GetUser(ctx, subject)
	if err != nil {
		return nil, err
	}

	if user.Spec.State != unikornv1.UserStateActive {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// GetActiveOrganizationUser gets an organization user that references the actual user.
func (r *RBAC) GetActiveOrganizationUser(ctx context.Context, organizationID string, user *unikornv1.User) (*unikornv1.OrganizationUser, error) {
	opts := []client.ListOption{
		&client.ListOptions{
			LabelSelector: labels.SelectorFromSet(labels.Set{
				constants.OrganizationLabel: organizationID,
				constants.UserLabel:         user.Name,
			}),
		},
	}

	var list unikornv1.OrganizationUserList
	if err := r.client.List(ctx, &list, opts...); err != nil {
		return nil, err
	}

	if len(list.Items) == 0 {
		return nil, ErrOrganizationUserNotFound
	}

	if len(list.Items) > 1 {
		err := fmt.Errorf("%w: expected 1 organization user but found multiple", ErrInternal)
		return nil, err
	}

	organizationUser := &list.Items[0]
	if organizationUser.Spec.State != unikornv1.UserStateActive {
		return nil, ErrOrganizationUserNotFound
	}

	return organizationUser, nil
}

// GetActiveOrganizationUsers returns all active organization users for a given subject.
func (r *RBAC) GetActiveOrganizationUsers(ctx context.Context, user *unikornv1.User) (*unikornv1.OrganizationUserList, error) {
	selector := labels.SelectorFromSet(map[string]string{
		constants.UserLabel: user.Name,
	})

	result := &unikornv1.OrganizationUserList{}

	if err := r.client.List(ctx, result, &client.ListOptions{LabelSelector: selector}); err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(organizationUser unikornv1.OrganizationUser) bool {
		return organizationUser.Spec.State != unikornv1.UserStateActive
	})

	return result, nil
}

// GetServiceAccount looks up a service account.
func (r *RBAC) GetServiceAccount(ctx context.Context, id string) (*unikornv1.ServiceAccount, error) {
	var result unikornv1.ServiceAccountList
	if err := r.client.List(ctx, &result); err != nil {
		return nil, err
	}

	isNotTargetServiceAccount := func(s unikornv1.ServiceAccount) bool {
		return s.Name != id
	}

	result.Items = slices.DeleteFunc(result.Items, isNotTargetServiceAccount)

	if len(result.Items) == 0 {
		return nil, ErrServiceAccountNotFound
	}

	if len(result.Items) > 1 {
		return nil, fmt.Errorf("%w: expected 1 service account but found multiple", ErrInternal)
	}

	return &result.Items[0], nil
}

type groupSubjectFilterGetter func(id string) func(unikornv1.Group) bool

// groupUserFilter checks if the group contains the user.
func groupUserFilter(id string) func(unikornv1.Group) bool {
	return func(group unikornv1.Group) bool {
		return !slices.Contains(group.Spec.UserIDs, id)
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
	opts := []client.ListOption{
		&client.ListOptions{Namespace: namespace},
	}

	var list unikornv1.GroupList
	if err := r.client.List(ctx, &list, opts...); err != nil {
		return nil, err
	}

	list.Items = slices.DeleteFunc(list.Items, filter)

	memo := make(map[string]*unikornv1.Group)
	for _, group := range list.Items {
		memo[group.Name] = &group
	}

	return memo, nil
}

// getRoles returns a map of roles in the system indexed by ID.
func (r *RBAC) getRoles(ctx context.Context) (map[string]*unikornv1.Role, error) {
	opts := []client.ListOption{
		&client.ListOptions{Namespace: r.namespace},
	}

	var list unikornv1.RoleList
	if err := r.client.List(ctx, &list, opts...); err != nil {
		return nil, err
	}

	memo := make(map[string]*unikornv1.Role)
	for _, role := range list.Items {
		memo[role.Name] = &role
	}

	return memo, nil
}

// getProjects grabs all projects for an organization.
func (r *RBAC) getProjects(ctx context.Context, organizationID string) (*unikornv1.ProjectList, error) {
	opts := []client.ListOption{
		&client.ListOptions{
			LabelSelector: labels.SelectorFromSet(labels.Set{
				constants.OrganizationLabel: organizationID,
			}),
		},
	}

	var list unikornv1.ProjectList
	if err := r.client.List(ctx, &list, opts...); err != nil {
		return nil, err
	}

	return &list, nil
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
	memo := make(map[string]map[openapi.AclOperation]struct{})

	if e != nil {
		for _, endpoint := range *e {
			memorizeACL(memo, endpoint.Name, endpoint.Operations)
		}
	}

	for _, scope := range scopes {
		operations := convertOperationList(scope.Operations)
		memorizeACL(memo, scope.Name, operations)
	}

	if len(memo) == 0 {
		return nil
	}

	endpoints := make([]openapi.AclEndpoint, 0, len(memo))
	for name, operationMemo := range memo {
		endpoints = append(endpoints, openapi.AclEndpoint{
			Name:       name,
			Operations: slices.Collect(maps.Keys(operationMemo)),
		})
	}

	return &endpoints
}

func memorizeACL(memo map[string]map[openapi.AclOperation]struct{}, name string, operations openapi.AclOperations) {
	if _, ok := memo[name]; !ok {
		memo[name] = make(map[openapi.AclOperation]struct{})
	}

	for _, operation := range operations {
		memo[name][operation] = struct{}{}
	}
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
			return fmt.Errorf("%w: role %s found in global subject but missing in store", ErrInternal, roleID)
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
				err := fmt.Errorf("%w: role %s found in group %s but missing in store", ErrInternal, roleID, groupID)
				return nil, err
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
				err := fmt.Errorf("%w: role %s found in group %s but missing in store", ErrInternal, roleID, groupID)
				return nil, err
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
// TODO: when groups reference subjects, not explicit resource IDs, then we can just pass in
// a subject and organization IDs to iterate over.
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
		return nil, fmt.Errorf("%w: system account %s is not registered", ErrInternal, subject)
	}

	roles, err := r.getRoles(ctx)
	if err != nil {
		return nil, err
	}

	roleIDs := []string{roleID}

	var acl openapi.Acl
	if err := accumulateGlobalPermissions(&acl, roleIDs, roles); err != nil {
		return nil, err
	}

	return &acl, nil
}

// processServiceAccountACL looks up a service account, any groups it's a member of,
// then adds their permissions to the ACL.  As service accounts are bound to a specific
// organization we must check the scoped organization matches that of the service account.
func (r *RBAC) processServiceAccountACL(ctx context.Context, subject, organizationID string) (*openapi.Acl, error) {
	serviceAccount, err := r.GetServiceAccount(ctx, subject)
	if err != nil {
		return nil, err
	}

	groupFilterFunc := groupServiceAccountFilter(serviceAccount.Name)

	subjectOrganizationID, ok := serviceAccount.Labels[constants.OrganizationLabel]
	if !ok {
		return nil, fmt.Errorf("%w: service account %s has no organization label", ErrInternal, serviceAccount.Name)
	}

	groups, err := r.getGroups(ctx, serviceAccount.Namespace, groupFilterFunc)
	if err != nil {
		return nil, err
	}

	var acl openapi.Acl

	// Nothing to do.
	if len(groups) == 0 {
		return &acl, nil
	}

	roles, err := r.getRoles(ctx)
	if err != nil {
		return nil, err
	}

	// Scoped ACL handling.
	if subjectOrganizationID == organizationID {
		if err := r.accumulateOrganizationScopedPermissions(ctx, &acl, groups, roles, organizationID); err != nil {
			return nil, err
		}
	}

	// Unscoped ACL handling.
	organizationSubjectMap := organizationToSubjectMap{
		subjectOrganizationID: serviceAccount.Name,
	}

	if err := r.accumulatePermissions(ctx, &acl, organizationSubjectMap, groupServiceAccountFilter); err != nil {
		return nil, err
	}

	return &acl, nil
}

// processUserAccountACL ensures the user exists and is active, looks up any groups it's
// a member of and adds their permissions to the ACL.
//
//nolint:cyclop
func (r *RBAC) processUserAccountACL(ctx context.Context, subject, organizationID string) (*openapi.Acl, error) {
	user, err := r.GetActiveUser(ctx, subject)
	if err != nil {
		return nil, err
	}

	roles, err := r.getRoles(ctx)
	if err != nil {
		return nil, err
	}

	var acl openapi.Acl

	if slices.Contains(r.options.PlatformAdministratorSubjects, user.Spec.Subject) {
		if err := accumulateGlobalPermissions(&acl, r.options.PlatformAdministratorRoleIDs, roles); err != nil {
			return nil, err
		}

		return &acl, nil
	}

	if organizationID != "" {
		organizationUser, err := r.GetActiveOrganizationUser(ctx, organizationID, user)
		if err != nil {
			return nil, err
		}

		groupFilterFunc := groupUserFilter(organizationUser.Name)

		groups, err := r.getGroups(ctx, organizationUser.Namespace, groupFilterFunc)
		if err != nil {
			return nil, err
		}

		// Nothing to do.
		if len(groups) == 0 {
			return &acl, nil
		}

		// Scoped ACL handling.
		if err := r.accumulateOrganizationScopedPermissions(ctx, &acl, groups, roles, organizationID); err != nil {
			return nil, err
		}
	}

	// Unscoped ACL handling.
	organizationUsers, err := r.GetActiveOrganizationUsers(ctx, user)
	if err != nil {
		return nil, err
	}

	organizationSubjectMap := organizationToSubjectMap{}

	for i := range organizationUsers.Items {
		organizationUser := &organizationUsers.Items[i]

		organizationSubjectMap[organizationUser.Labels[constants.OrganizationLabel]] = organizationUser.Name
	}

	if err := r.accumulatePermissions(ctx, &acl, organizationSubjectMap, groupUserFilter); err != nil {
		return nil, err
	}

	return &acl, nil
}

// GetACL returns a granular set of permissions for a user based on their scope.
// This is used for API level access control and UX.
func (r *RBAC) GetACL(ctx context.Context, organizationID string) (*openapi.Acl, error) {
	// All the tokens introspecition info is in the context...
	info, err := authorization.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	subject := info.Userinfo.Sub

	if info.SystemAccount {
		return r.processSystemAccountACL(ctx, subject)
	}

	if info.ServiceAccount {
		return r.processServiceAccountACL(ctx, subject, organizationID)
	}

	return r.processUserAccountACL(ctx, subject, organizationID)
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
