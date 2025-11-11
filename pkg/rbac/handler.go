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
	"slices"

	"github.com/spjmurray/go-util/pkg/set"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
)

// operationAllowedByEndpoints iterates through all endpoints and tries to match the required name and
// operation.
func operationAllowedByEndpoints(endpoints openapi.AclEndpoints, endpoint string, operation openapi.AclOperation) error {
	for _, e := range endpoints {
		if e.Name != endpoint {
			continue
		}

		if !slices.Contains(e.Operations, operation) {
			continue
		}

		return nil
	}

	return errors.HTTPForbidden("operation is not allowed by rbac (no matching endpoint)")
}

// AllowGlobalScope tries to allow the requested operation at the global scope.
func AllowGlobalScope(ctx context.Context, endpoint string, operation openapi.AclOperation) error {
	acl := FromContext(ctx)

	if acl.Global == nil {
		return errors.HTTPForbidden("operation is not allowed by rbac (no global endpoints)")
	}

	return operationAllowedByEndpoints(*acl.Global, endpoint, operation)
}

// AllowOrganizationScope tries to allow the requested operation at the global scope, then
// the organization scope.
func AllowOrganizationScope(ctx context.Context, endpoint string, operation openapi.AclOperation, organizationID string) error {
	if AllowGlobalScope(ctx, endpoint, operation) == nil {
		return nil
	}

	acl := FromContext(ctx)

	if acl.Organizations == nil {
		return errors.HTTPForbidden("operation is not allowed by rbac (no organizations defined)")
	}

	for _, organization := range *acl.Organizations {
		if organization.Id != organizationID {
			continue
		}

		if organization.Endpoints == nil {
			return errors.HTTPForbidden("operation is not allowed by rbac (no organizations endpoints)")
		}

		return operationAllowedByEndpoints(*organization.Endpoints, endpoint, operation)
	}

	return errors.HTTPForbidden("operation is not allowed by rbac (no matching organization endpoint)")
}

// AllowProjectScope tries to allow the requested operation at the global scope, then
// the organization scope, and finally at the project scope.
func AllowProjectScope(ctx context.Context, endpoint string, operation openapi.AclOperation, organizationID, projectID string) error {
	if AllowOrganizationScope(ctx, endpoint, operation, organizationID) == nil {
		return nil
	}

	acl := FromContext(ctx)

	if acl.Organizations == nil {
		return errors.HTTPForbidden("operation is not allowed by rbac (no organizations defined)")
	}

	for _, organization := range *acl.Organizations {
		if organization.Id != organizationID {
			continue
		}

		if organization.Endpoints != nil {
			if operationAllowedByEndpoints(*organization.Endpoints, endpoint, operation) == nil {
				return nil
			}
		}

		if organization.Projects != nil {
			for _, project := range *organization.Projects {
				if project.Id != projectID {
					continue
				}

				return operationAllowedByEndpoints(project.Endpoints, endpoint, operation)
			}
		}
	}

	return errors.HTTPForbidden("operation is not allowed by rbac (no matching project endpoints)")
}

// AllowRole determines whether your ACL contains the same or higher privileges than
// the role, which is then used to determine role visibility and limit privilege
// escalation.
func AllowRole(ctx context.Context, role *unikornv1.Role, organizationID string) error {
	for _, endpoint := range role.Spec.Scopes.Global {
		for _, operation := range endpoint.Operations {
			if err := AllowGlobalScope(ctx, endpoint.Name, convertOperation(operation)); err != nil {
				return err
			}
		}
	}

	for _, endpoint := range role.Spec.Scopes.Organization {
		for _, operation := range endpoint.Operations {
			if err := AllowOrganizationScope(ctx, endpoint.Name, convertOperation(operation), organizationID); err != nil {
				return err
			}
		}
	}

	for _, endpoint := range role.Spec.Scopes.Project {
		for _, operation := range endpoint.Operations {
			if err := AllowOrganizationScope(ctx, endpoint.Name, convertOperation(operation), organizationID); err != nil {
				return err
			}
		}
	}

	return nil
}

// OrganizationIDs returns a list of all organization IDs from the ACL for the purposes
// of limiting list type API operations.
func OrganizationIDs(ctx context.Context) []string {
	acl := FromContext(ctx)

	if acl.Organizations == nil {
		return nil
	}

	organizations := *acl.Organizations

	if len(organizations) == 0 {
		return nil
	}

	organizationIDs := make([]string, len(organizations))

	for i := range organizations {
		organizationIDs[i] = organizations[i].Id
	}

	return organizationIDs
}

// ProjectIDs returns a list of all projects from a single organization in the ACL for
// the purposes of limiting list type API operations.
func ProjectIDs(ctx context.Context, organizationID string) []string {
	acl := FromContext(ctx)

	if acl.Organizations == nil {
		return nil
	}

	organizations := *acl.Organizations

	if len(organizations) == 0 {
		return nil
	}

	index := slices.IndexFunc(organizations, func(o openapi.AclOrganization) bool {
		return o.Id == organizationID
	})

	if index < 0 {
		return nil
	}

	organization := organizations[index]

	if organization.Projects == nil {
		return nil
	}

	projects := *organization.Projects

	if len(projects) == 0 {
		return nil
	}

	projectIDs := make([]string, len(projects))

	for i := range projects {
		projectIDs[i] = projects[i].Id
	}

	return projectIDs
}

// AddQuery adds a set of query values to a label selector.
func AddQuery(selector labels.Selector, label string, vals []string) (labels.Selector, error) {
	if len(vals) == 0 {
		return selector, nil
	}

	if len(vals) == 1 {
		req, err := labels.NewRequirement(label, selection.Equals, vals)
		if err != nil {
			return nil, err
		}

		return selector.Add(*req), nil
	}

	req, err := labels.NewRequirement(label, selection.In, vals)
	if err != nil {
		return nil, err
	}

	return selector.Add(*req), nil
}

// AddOrganizationIDQuery adds an organizational query selector that limits resources to
// be listed to those available in the ACL and optionally constrained to those in the
// request query using a boolean intersection.
func AddOrganizationIDQuery(ctx context.Context, selector labels.Selector, query []string) (labels.Selector, error) {
	// NOTE: super-admin accounts and system accounts will not have any organizations
	// defined in the ACL, so we let this slide, and trust they will add a query to limit
	// the scope.  It should not be possible for a user to get here without being a
	// member of an organization, but ReBAC will prevent any unintended reads.
	organizationIDs := OrganizationIDs(ctx)
	if len(organizationIDs) == 0 {
		return AddQuery(selector, constants.OrganizationLabel, query)
	}

	if len(query) > 0 {
		organizationIDs = slices.Collect(set.New(organizationIDs...).Intersection(set.New(query...)).All())
	}

	return AddQuery(selector, constants.OrganizationLabel, organizationIDs)
}

// AddOrganizationAndProjectIDQuery gets all organizationIDs the user can access (or has requested
// explicit and has access to), then selects all projects that can be accessed.  If en explicit
// project query has been provided, then constrain the accessible project set.
func AddOrganizationAndProjectIDQuery(ctx context.Context, selector labels.Selector, organizationQuery []string, projectQuery []string) (labels.Selector, error) {
	// NOTE: super-admin accounts and system accounts will not have any organizations
	// defined in the ACL, so we let this slide, and trust they will add a query to limit
	// the scope.  It should not be possible for a user to get here without being a
	// member of an organization, but ReBAC will prevent any unintended reads.
	organizationIDs := OrganizationIDs(ctx)
	if len(organizationIDs) == 0 {
		selector, err := AddQuery(selector, constants.OrganizationLabel, organizationQuery)
		if err != nil {
			return nil, err
		}

		return AddQuery(selector, constants.ProjectLabel, projectQuery)
	}

	if len(organizationQuery) > 0 {
		organizationIDs = slices.Collect(set.New(organizationIDs...).Intersection(set.New(organizationQuery...)).All())
	}

	// Create a set of all projects that the user can access across the selected
	// organizations.
	projectIDSet := set.New[string]()

	for _, organizationID := range organizationIDs {
		projectIDSet = projectIDSet.Union(set.New(ProjectIDs(ctx, organizationID)...))
	}

	if len(projectQuery) > 0 {
		projectIDSet = projectIDSet.Intersection(set.New(projectQuery...))
	}

	projectIDs := slices.Collect(projectIDSet.All())

	var err error

	selector, err = AddQuery(selector, constants.OrganizationLabel, organizationIDs)
	if err != nil {
		return nil, err
	}

	selector, err = AddQuery(selector, constants.ProjectLabel, projectIDs)
	if err != nil {
		return nil, err
	}

	return selector, nil
}
