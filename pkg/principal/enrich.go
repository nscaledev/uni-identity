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

package principal

import (
	"context"

	"github.com/unikorn-cloud/identity/pkg/ids"
)

// EnrichUserPrincipalOrganizationScopeID fills the context principal's organization
// (attribution) from a typed ID, but ONLY if it is not already set.
//
// In the common v2 path the organization comes from the request body or a parent
// resource (i.e. a path parameter), so the principal arrives without an organization and
// is filled here. When a principal was propagated from an upstream system service (mTLS,
// X-Principal) it may already carry the originating organization; the guard preserves that
// attribution rather than overwriting it with the resource's placement organization.
// Attribution and placement are distinct concerns and must not be collapsed.
//
// Mirroring the rbac scope helpers, the ID variant is for callers holding a typed ID (e.g. a
// decoded path parameter); the Reader variant is for callers holding a resource.
func EnrichUserPrincipalOrganizationScopeID(ctx context.Context, organizationID ids.OrganizationID) error {
	p, err := FromContext(ctx)
	if err != nil {
		return err
	}

	if p.OrganizationID != "" {
		return nil
	}

	p.OrganizationID = organizationID.String()

	return nil
}

// EnrichUserPrincipalProjectScopeID fills the context principal's organization and project
// (attribution) from typed IDs, with the same "enrich only when unset" guard as
// EnrichUserPrincipalOrganizationScopeID; see that function for the attribution-vs-placement
// rationale.
func EnrichUserPrincipalProjectScopeID(ctx context.Context, organizationID ids.OrganizationID, projectID ids.ProjectID) error {
	p, err := FromContext(ctx)
	if err != nil {
		return err
	}

	if p.OrganizationID != "" {
		return nil
	}

	p.OrganizationID = organizationID.String()
	p.ProjectID = projectID.String()

	return nil
}

// EnrichUserPrincipalOrganizationScopeReader recovers the organization ID from a resource
// implementing ids.OrganizationScopeReader (e.g. a region CRD) and delegates to
// EnrichUserPrincipalOrganizationScopeID. Callers holding a typed path-parameter ID should use
// the ID variant instead.
func EnrichUserPrincipalOrganizationScopeReader(ctx context.Context, scope ids.OrganizationScopeReader) error {
	organizationID, err := scope.OrganizationID()
	if err != nil {
		return err
	}

	return EnrichUserPrincipalOrganizationScopeID(ctx, organizationID)
}

// EnrichUserPrincipalProjectScopeReader recovers the organization and project IDs from a
// resource implementing ids.ProjectScopeReader and delegates to
// EnrichUserPrincipalProjectScopeID.
func EnrichUserPrincipalProjectScopeReader(ctx context.Context, scope ids.ProjectScopeReader) error {
	organizationID, projectID, err := scope.OrganizationAndProjectID()
	if err != nil {
		return err
	}

	return EnrichUserPrincipalProjectScopeID(ctx, organizationID, projectID)
}
