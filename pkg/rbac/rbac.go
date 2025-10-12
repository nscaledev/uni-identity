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
	"errors"
	"fmt"
	"slices"

	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrResourceReference                     = errors.New("resource reference error")
	ErrNotOrganizationMember                 = errors.New("subject is not a member of organization")
	ErrUnexpectedServiceAccountOrganisations = errors.New("unexpected orgs claims for service account, expected one")
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

func (r *RBAC) GetUser(ctx context.Context, subject string) (*unikornv1.User, error) {
	result := &unikornv1.UserList{}

	if err := r.client.List(ctx, result, &client.ListOptions{}); err != nil {
		return nil, err
	}

	index := slices.IndexFunc(result.Items, func(user unikornv1.User) bool {
		return user.Spec.Subject == subject
	})

	if index < 0 {
		return nil, fmt.Errorf("%w: user does not exist", ErrResourceReference)
	}

	return &result.Items[index], nil
}

// GetActiveUser returns a user that match the subject and is active.
func (r *RBAC) GetActiveUser(ctx context.Context, subject string) (*unikornv1.User, error) {
	user, err := r.GetUser(ctx, subject)
	if err != nil {
		return nil, err
	}

	if user.Spec.State != unikornv1.UserStateActive {
		return nil, fmt.Errorf("%w: user is not active", ErrResourceReference)
	}

	return user, nil
}

// GetServiceAccount looks up a service account.
func (r *RBAC) GetServiceAccount(ctx context.Context, id string) (*unikornv1.ServiceAccount, error) {
	result := &unikornv1.ServiceAccountList{}

	if err := r.client.List(ctx, result, &client.ListOptions{}); err != nil {
		return nil, err
	}

	predicate := func(s unikornv1.ServiceAccount) bool {
		return s.Name != id
	}

	result.Items = slices.DeleteFunc(result.Items, predicate)

	if len(result.Items) != 1 {
		return nil, fmt.Errorf("%w: expected 1 instance of service account ID %s", ErrResourceReference, id)
	}

	return &result.Items[0], nil
}

// groupSubjectFilter checks if the group contains the user by subject.
func groupSubjectFilter(subject string) func(unikornv1.Group) bool {
	return func(group unikornv1.Group) bool {
		return !slices.Contains(group.Spec.Subjects, subject)
	}
}

// groupServiceAccountFilter checks if the group contains a service acccount ID.
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
// or perges permissions with an existing entry.
func addScopesToEndpointList(e *openapi.AclEndpoints, scopes []unikornv1.RoleScope) {
	for _, scope := range scopes {
		operations := convertOperationList(scope.Operations)

		indexFunc := func(ep openapi.AclEndpoint) bool {
			return ep.Name == scope.Name
		}

		// If an existing entry exists, create a union of operations.
		if index := slices.IndexFunc(*e, indexFunc); index >= 0 {
			endpoint := &(*e)[index]

			endpoint.Operations = slices.Concat(endpoint.Operations, operations)
			slices.Sort(endpoint.Operations)

			endpoint.Operations = slices.Compact(endpoint.Operations)

			continue
		}

		// If not add a new entry.
		*e = append(*e, openapi.AclEndpoint{
			Name:       scope.Name,
			Operations: operations,
		})
	}
}

//nolint:cyclop,gocognit
func (r *RBAC) accumulatePermissions(groups map[string]*unikornv1.Group, roles map[string]*unikornv1.Role, projects *unikornv1.ProjectList, organizationID, subjectOrganiationID string, globalACL *openapi.AclEndpoints, organizationACL *openapi.AclScopedEndpoints, projectACLs *[]openapi.AclScopedEndpoints) error {
	// Pass 1: accumulate any global or organization scoped permissions.
	for groupID, group := range groups {
		for _, roleID := range group.Spec.RoleIDs {
			role, ok := roles[roleID]
			if !ok {
				return fmt.Errorf("%w: role %s referenced by group %s does not exist", ErrResourceReference, roleID, groupID)
			}

			addScopesToEndpointList(globalACL, role.Spec.Scopes.Global)

			if subjectOrganiationID == organizationID {
				addScopesToEndpointList(&organizationACL.Endpoints, role.Spec.Scopes.Organization)
			}
		}
	}

	// Pass 2: accumulate any project permissions.
	if subjectOrganiationID == organizationID {
		for _, project := range projects.Items {
			projectACL := openapi.AclScopedEndpoints{
				Id: project.Name,
			}

			for _, groupID := range project.Spec.GroupIDs {
				group, ok := groups[groupID]
				if !ok {
					// This is okay as projects may reference groups
					// we aren't a member of.
					continue
				}

				for _, roleID := range group.Spec.RoleIDs {
					role, ok := roles[roleID]
					if !ok {
						return fmt.Errorf("%w: role %s referenced by group %s does not exist", ErrResourceReference, roleID, groupID)
					}

					addScopesToEndpointList(&projectACL.Endpoints, role.Spec.Scopes.Project)
				}
			}

			if len(projectACL.Endpoints) != 0 {
				*projectACLs = append(*projectACLs, projectACL)
			}
		}
	}

	return nil
}

// GetACL returns a granular set of permissions for a user based on their scope.
// This is used for API level access control and UX.
//
//nolint:cyclop,gocognit
func (r *RBAC) GetACL(ctx context.Context, organizationID string) (*openapi.Acl, error) {
	// All the tokens introspecition info is in the context...
	info, err := authorization.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	// This is used as the key for looking up e.g., groups
	subject := info.Userinfo.Sub
	// This represents organization membership
	var orgIds []string
	if info.Userinfo.OrgIds != nil {
		orgIds = *info.Userinfo.OrgIds
	}

	roles, err := r.getRoles(ctx)
	if err != nil {
		return nil, err
	}

	var projects *unikornv1.ProjectList

	if organizationID != "" {
		p, err := r.getProjects(ctx, organizationID)
		if err != nil {
			return nil, err
		}

		projects = p
	}

	var globalACL openapi.AclEndpoints

	organizationACL := openapi.AclScopedEndpoints{
		Id: organizationID,
	}

	var projectACLs []openapi.AclScopedEndpoints

	switch {
	case info.SystemAccount:
		// System accounts act on behalf of users, so by definition need globally
		// scoped roles.  As such they are explcitly mapped by the operations team
		// when deploying.
		roleID, ok := r.options.SystemAccountRoleIDs[subject]
		if !ok {
			return nil, fmt.Errorf("%w: system account '%s' not registered", ErrResourceReference, subject)
		}

		role, ok := roles[roleID]
		if !ok {
			return nil, fmt.Errorf("%w: system account '%s' references undefined role ID", ErrResourceReference, subject)
		}

		addScopesToEndpointList(&globalACL, role.Spec.Scopes.Global)

	case info.ServiceAccount:
		if len(orgIds) != 1 {
			return nil, ErrUnexpectedServiceAccountOrganisations
		}

		if orgIds[0] != organizationID {
			return nil, ErrNotOrganizationMember
		}

		var org unikornv1.Organization
		if err := r.client.Get(ctx, client.ObjectKey{Namespace: r.namespace, Name: organizationID}, &org); err != nil {
			return nil, ErrResourceReference
		}

		groups, err := r.getGroups(ctx, org.Status.Namespace, groupServiceAccountFilter(subject))
		if err != nil {
			return nil, err
		}

		if err := r.accumulatePermissions(groups, roles, projects, organizationID, organizationID, &globalACL, &organizationACL, &projectACLs); err != nil {
			return nil, err
		}

	default:
		switch {
		case slices.Contains(r.options.PlatformAdministratorSubjects, subject):
			// Handle platform administrator accounts.
			// These purposefully cannot be granted via the API and must be
			// conferred by the operations team.
			for _, id := range r.options.PlatformAdministratorRoleIDs {
				if role, ok := roles[id]; ok {
					addScopesToEndpointList(&globalACL, role.Spec.Scopes.Global)
				}
			}
		case organizationID != "":
			if !slices.Contains(orgIds, organizationID) {
				return nil, ErrNotOrganizationMember
			}

			var org unikornv1.Organization
			if err := r.client.Get(ctx, client.ObjectKey{Namespace: r.namespace, Name: organizationID}, &org); err != nil {
				return nil, ErrResourceReference
			}

			groups, err := r.getGroups(ctx, org.Status.Namespace, groupSubjectFilter(subject))
			if err != nil {
				return nil, err
			}
			if err := r.accumulatePermissions(groups, roles, projects, organizationID, organizationID, &globalACL, &organizationACL, &projectACLs); err != nil {
				return nil, err
			}
		}
	}

	acl := &openapi.Acl{}

	if len(globalACL) != 0 {
		acl.Global = &globalACL
	}

	if len(organizationACL.Endpoints) != 0 {
		acl.Organization = &organizationACL
	}

	if len(projectACLs) != 0 {
		acl.Projects = &projectACLs
	}

	return acl, nil
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
