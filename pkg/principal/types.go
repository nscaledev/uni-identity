/*
Copyright 2025 the Unikorn Authors.
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
	"slices"

	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// Principal records information about what user insigated a request.
type Principal struct {
	// OrganizationID of the originating request (optional).
	OrganizationID string `json:"organizationId,omitempty"`
	// OrganizationIDs records the full set of organizations the actor can access.
	OrganizationIDs []string `json:"organizationIds,omitempty"`
	// ProjectID of the originating request (optional).
	ProjectID string `json:"projectId,omitempty"`
	// Type of the originating actor. This reuses the OpenAPI auth claim values.
	Type openapi.AuthClaimsAcctype `json:"type,omitempty"`
	// Actor of the originating request, this may be an email address
	// for an end-user, a service identifier for a system service, or
	// the service account name.
	Actor string `json:"actor,omitempty"`
}

// ResolvedOrganizationIDs returns the organization set the actor's bindings are
// resolved from: OrganizationIDs when populated, otherwise the singular
// OrganizationID as a one-element set (the defensive fallback for a caller that
// only sets OrganizationID — e.g. a service that has not adopted full principal
// propagation), otherwise empty.
//
// This is the SINGLE definition of that fallback. Binding resolution
// (rbac.impersonatedInfo and rbac.getSystemAccountACL) AND every cache key that
// must mirror the resolution input (rbac.decisionCacheKey, the middleware's
// aclCacheKey) derive the org set from here, so a key can never silently
// disagree with the org set the decision actually resolves against. A fresh
// slice is returned so callers may sort it in place without aliasing the
// principal's own field.
func (p *Principal) ResolvedOrganizationIDs() []string {
	if len(p.OrganizationIDs) > 0 {
		return slices.Clone(p.OrganizationIDs)
	}

	if p.OrganizationID != "" {
		return []string{p.OrganizationID}
	}

	return nil
}
