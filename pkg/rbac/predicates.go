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
	"context"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// The Permits family answers "may this principal do this?" as a question, where
// the Allow family asserts it as a requirement.
//
// They are the same check, and the predicates are defined in terms of the gates
// so the two cannot drift.  What differs is the meaning of a negative answer,
// and that difference matters outside this package:
//
//   - A gate refusing is a refused request.  The principal asked for something
//     and was told no, which is a reportable security event.
//   - A predicate refusing is a resource being left out of a list because it
//     was never the principal's to see.  That is access control working
//     normally, it happens on every list, and it MUST NOT be reported as a
//     refusal.  Doing so would bury real refusals and tell a monitoring system
//     an attack was underway every time somebody listed a shared organization.
//
// Use a predicate when filtering candidates.  Use a gate when the answer
// decides whether the request proceeds.  See the README.

// PermitsGlobalScope reports whether the operation is permitted at global scope.
func PermitsGlobalScope(ctx context.Context, endpoint string, operation openapi.AclOperation) bool {
	return AllowGlobalScope(ctx, endpoint, operation) == nil
}

// PermitsOrganizationScopeID reports whether the operation is permitted on the
// organization.
func PermitsOrganizationScopeID(ctx context.Context, endpoint string, operation openapi.AclOperation, organizationID ids.OrganizationID) bool {
	return AllowOrganizationScopeID(ctx, endpoint, operation, organizationID) == nil
}

// PermitsOrganizationScopeReader reports whether the operation is permitted on
// the resource's organization.
func PermitsOrganizationScopeReader(ctx context.Context, endpoint string, operation openapi.AclOperation, scope ids.OrganizationScopeReader) bool {
	return AllowOrganizationScopeReader(ctx, endpoint, operation, scope) == nil
}

// PermitsProjectScopeID reports whether the operation is permitted on the project.
func PermitsProjectScopeID(ctx context.Context, endpoint string, operation openapi.AclOperation, organizationID ids.OrganizationID, projectID ids.ProjectID) bool {
	return AllowProjectScopeID(ctx, endpoint, operation, organizationID, projectID) == nil
}

// PermitsProjectScopeReader reports whether the operation is permitted on the
// resource's project.
func PermitsProjectScopeReader(ctx context.Context, endpoint string, operation openapi.AclOperation, scope ids.ProjectScopeReader) bool {
	return AllowProjectScopeReader(ctx, endpoint, operation, scope) == nil
}

// PermitsRole reports whether the principal may grant the role.
func PermitsRole(ctx context.Context, role *unikornv1.Role, organizationID ids.OrganizationID) bool {
	return AllowRole(ctx, role, organizationID) == nil
}
