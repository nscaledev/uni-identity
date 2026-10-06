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

	"github.com/unikorn-cloud/identity/pkg/authz"
	"github.com/unikorn-cloud/identity/pkg/ids"
)

// The On family states what the check is about rather than leaving it to be
// inferred later from the request's URL.
//
// A target names the resource type, the resource itself, the access required,
// the action performed, and whether this is the operation the request is or a
// precondition of it. None of that is reliably recoverable afterwards:
//
//   - v2 APIs carry no organization or project in the path.
//   - An action sub-resource such as starting an instance is a POST, exactly
//     like creating one, so the method says nothing about what happened.
//   - A path ending in a sub-resource, such as a reference on a network, names
//     the sub-resource rather than the thing being changed.
//
// The older gates remain and keep working. They record the scope, which is the
// part that matters most, but cannot name an object or an action, and their
// decisions count as preconditions rather than the request's own operation.
// Migrating a call site is what fills those in. See the README.

// AllowGlobalScopeOn tries to allow the target at the global scope.
func AllowGlobalScopeOn(ctx context.Context, target authz.Target) error {
	return record(ctx, target, authz.Scope{},
		checkGlobalScope(ctx, target.Endpoint, target.Operation.Access))
}

// AllowOrganizationScopeOn tries to allow the target at the global scope, then
// the organization scope.
func AllowOrganizationScopeOn(ctx context.Context, target authz.Target, organizationID ids.OrganizationID) error {
	scope := authz.Scope{
		OrganizationID: organizationID,
	}

	return record(ctx, target, scope,
		checkOrganizationScope(ctx, target.Endpoint, target.Operation.Access, organizationID.String()))
}

// AllowProjectScopeOn tries to allow the target at the global scope, then the
// organization scope, and finally the project scope.
func AllowProjectScopeOn(ctx context.Context, target authz.Target, organizationID ids.OrganizationID, projectID ids.ProjectID) error {
	scope := authz.Scope{
		OrganizationID: organizationID,
		ProjectID:      projectID,
	}

	return record(ctx, target, scope,
		checkProjectScope(ctx, target.Endpoint, target.Operation.Access, organizationID.String(), projectID.String()))
}

// AllowProjectScopeReaderOn is the variant for callers holding a resource that
// reports its own scope.
func AllowProjectScopeReaderOn(ctx context.Context, target authz.Target, scope ids.ProjectScopeReader) error {
	organizationID, projectID, err := scope.OrganizationAndProjectID()
	if err != nil {
		return err
	}

	return AllowProjectScopeOn(ctx, target, organizationID, projectID)
}
