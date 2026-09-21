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

package ids

// OrganizationScopeReader is implemented by resources that can report the typed
// organization ID that owns them, recovered from their Kubernetes labels. It lets
// scope-aware code (RBAC checks, principal enrichment, reference management) accept
// a resource directly and perform the label-read-and-parse step in one place.
type OrganizationScopeReader interface {
	OrganizationID() (OrganizationID, error)
}

// ProjectScopeReader is implemented by resources that can report the typed
// organization and project IDs that own them. It embeds OrganizationScopeReader
// because every project-scoped resource necessarily belongs to an organization, so
// anything that knows its project also knows its organization.
type ProjectScopeReader interface {
	OrganizationScopeReader
	OrganizationAndProjectID() (OrganizationID, ProjectID, error)
}

// SameProject reports whether a and b are owned by the same organization and project.
// It returns an error if either resource's owning scope cannot be determined (e.g. missing
// or malformed labels).
//
// Use this before establishing a relationship between two project-scoped resources — for
// example, ensuring a server and the SSH certificate authority it references live in the
// same project. Callers decide how to treat a false result (typically a forbidden/bad-request
// response); this package stays free of transport-error concerns.
func SameProject(a, b ProjectScopeReader) (bool, error) {
	aOrganizationID, aProjectID, err := a.OrganizationAndProjectID()
	if err != nil {
		return false, err
	}

	bOrganizationID, bProjectID, err := b.OrganizationAndProjectID()
	if err != nil {
		return false, err
	}

	return aOrganizationID == bOrganizationID && aProjectID == bProjectID, nil
}

// OwnedByOrganization reports whether scope is owned by the given organization. It returns
// an error if the resource's owning scope cannot be determined (e.g. a missing or malformed
// label).
//
// This is a referential-integrity check — does this resource live in the expected
// organization — and is the typed equivalent of core's AssertOrganizationOwnership. It is
// deliberately NOT an RBAC check: RBAC asks whether the caller may act in an organization,
// whereas this asks whether a specific resource belongs to one. Using an RBAC scope check
// here would let a caller authorized for several organizations relate resources across
// tenancy boundaries. Callers map a false result to their own transport error (the convention
// is 404, so resource existence is not leaked); this package stays free of transport-error
// concerns.
func OwnedByOrganization(scope OrganizationScopeReader, organizationID OrganizationID) (bool, error) {
	resourceOrganizationID, err := scope.OrganizationID()
	if err != nil {
		return false, err
	}

	return resourceOrganizationID == organizationID, nil
}

// OwnedByProject reports whether scope is owned by the given organization and project. It
// returns an error if the resource's owning scope cannot be determined. It is the typed
// equivalent of core's AssertProjectOwnership; see OwnedByOrganization for why this is an
// ownership-equality check rather than an RBAC check.
func OwnedByProject(scope ProjectScopeReader, organizationID OrganizationID, projectID ProjectID) (bool, error) {
	resourceOrganizationID, resourceProjectID, err := scope.OrganizationAndProjectID()
	if err != nil {
		return false, err
	}

	return resourceOrganizationID == organizationID && resourceProjectID == projectID, nil
}
