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
	"iter"
	"slices"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Lister[T metav1.Object] interface {
	metav1.ListInterface
	All() iter.Seq[T]
}

// NOTE: this should be flexible enough to interact with any RBAC solution.
type PolicyDecisionPoint interface {
	// Allow grants access to a single resource.
	// TODO: we can actually infer the "endpoint" from the resource type using the
	// apimachinery scheme.
	Allow(ctx context.Context, endpoint string, operation openapi.AclOperation, resource metav1.Object) error
}

func AllowBulk[T metav1.Object, L Lister[T]](ctx context.Context, pdp PolicyDecisionPoint, endpoint string, operation openapi.AclOperation, resources L) []error {
	//nolint:prealloc
	var allowed []error

	for resource := range resources.All() {
		allowed = append(allowed, pdp.Allow(ctx, endpoint, operation, resource))
	}

	return allowed
}

func FilterAllowed[T any](in []T, allowed []error) []T {
	out := make([]T, 0, len(in))

	for i := range in {
		if allowed[i] == nil {
			out = append(out, in[i])
		}
	}

	return out
}

type LocalPDP struct {
	rbac *RBAC
}

func NewLocalPDP(rbac *RBAC) *LocalPDP {
	return &LocalPDP{
		rbac: rbac,
	}
}

func (r *LocalPDP) Allow(ctx context.Context, endpoint string, operation openapi.AclOperation, resource metav1.Object) error {
	// TODO: This is going to suck for bulk operations...
	acl, err := r.rbac.GetACL(ctx, "")
	if err != nil {
		return err
	}

	labels := resource.GetLabels()

	if _, ok := labels[constants.OrganizationLabel]; ok {
		if _, ok := labels[constants.ProjectLabel]; ok {
			return AllowProjectScope(acl, endpoint, operation, labels[constants.OrganizationLabel], labels[constants.ProjectLabel])
		}

		return AllowOrganizationScope(acl, endpoint, operation, labels[constants.OrganizationLabel])
	}

	return AllowGlobalScope(acl, endpoint, operation)
}

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
func AllowGlobalScope(acl *openapi.Acl, endpoint string, operation openapi.AclOperation) error {
	if acl.Global == nil {
		return errors.HTTPForbidden("operation is not allowed by rbac (no global endpoints)")
	}

	return operationAllowedByEndpoints(*acl.Global, endpoint, operation)
}

// AllowOrganizationScope tries to allow the requested operation at the global scope, then
// the organization scope.
func AllowOrganizationScope(acl *openapi.Acl, endpoint string, operation openapi.AclOperation, organizationID string) error {
	if AllowGlobalScope(acl, endpoint, operation) == nil {
		return nil
	}

	if acl.Organization == nil || acl.Organization.Id != organizationID {
		return errors.HTTPForbidden("operation is not allowed by rbac (no matching organization endpoints)")
	}

	return operationAllowedByEndpoints(acl.Organization.Endpoints, endpoint, operation)
}

// AllowProjectScope tries to allow the requested operation at the global scope, then
// the organization scope, and finally at the project scope.
func AllowProjectScope(acl *openapi.Acl, endpoint string, operation openapi.AclOperation, organizationID, projectID string) error {
	if AllowOrganizationScope(acl, endpoint, operation, organizationID) == nil {
		return nil
	}

	if acl.Projects == nil {
		return errors.HTTPForbidden("operation is not allowed by rbac (no project endpoints)")
	}

	for _, project := range *acl.Projects {
		if project.Id != projectID {
			continue
		}

		if err := operationAllowedByEndpoints(project.Endpoints, endpoint, operation); err == nil {
			return nil
		}
	}

	return errors.HTTPForbidden("operation is not allowed by rbac (no matching project endpoints)")
}

// AllowRole determines whether your ACL contains the same or higher privileges than
// the role, which is then used to determine role visibility and limit privilege
// escalation.
func AllowRole(ctx context.Context, role *unikornv1.Role, organizationID string) error {
	/*
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
	*/

	return nil
}
