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

	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/openapi"
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
