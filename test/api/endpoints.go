/*
Copyright 2026 the Unikorn Authors.
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

package api

import (
	"fmt"
	"net/url"
)

// Endpoints contains API endpoint patterns.
// Add endpoint methods here as you write tests for them.
type Endpoints struct{}

// NewEndpoints creates a new Endpoints instance.
func NewEndpoints() *Endpoints {
	return &Endpoints{}
}

// ListOrganizations returns the endpoint for listing all organizations.
func (e *Endpoints) ListOrganizations() string {
	return "/api/v1/organizations"
}

// GetOrganization returns the endpoint for getting a specific organization.
func (e *Endpoints) GetOrganization(orgID string) string {
	return fmt.Sprintf("/api/v1/organizations/%s",
		url.PathEscape(orgID))
}

// ListProjects returns the endpoint for listing all projects in an organization.
func (e *Endpoints) ListProjects(orgID string) string {
	return fmt.Sprintf("/api/v1/organizations/%s/projects",
		url.PathEscape(orgID))
}

// GetProject returns the endpoint for getting a specific project.
func (e *Endpoints) GetProject(orgID, projectID string) string {
	return fmt.Sprintf("/api/v1/organizations/%s/projects/%s",
		url.PathEscape(orgID), url.PathEscape(projectID))
}

// ListGroups returns the endpoint for listing all groups in an organization.
func (e *Endpoints) ListGroups(orgID string) string {
	return fmt.Sprintf("/api/v1/organizations/%s/groups",
		url.PathEscape(orgID))
}

// GetGroup returns the endpoint for getting a specific group.
func (e *Endpoints) GetGroup(orgID, groupID string) string {
	return fmt.Sprintf("/api/v1/organizations/%s/groups/%s",
		url.PathEscape(orgID), url.PathEscape(groupID))
}

// GetGlobalACL returns the endpoint for getting global ACL.
func (e *Endpoints) GetGlobalACL() string {
	return "/api/v1/acl"
}

// GetOrganizationACL returns the endpoint for getting organization ACL.
func (e *Endpoints) GetOrganizationACL(orgID string) string {
	return fmt.Sprintf("/api/v1/organizations/%s/acl",
		url.PathEscape(orgID))
}

// ListUsers returns the endpoint for listing all users in an organization.
func (e *Endpoints) ListUsers(orgID string) string {
	return fmt.Sprintf("/api/v1/organizations/%s/users",
		url.PathEscape(orgID))
}

// ListRoles returns the endpoint for listing all roles in an organization.
func (e *Endpoints) ListRoles(orgID string) string {
	return fmt.Sprintf("/api/v1/organizations/%s/roles",
		url.PathEscape(orgID))
}

// ListServiceAccounts returns the endpoint for listing all service accounts in an organization.
func (e *Endpoints) ListServiceAccounts(orgID string) string {
	return fmt.Sprintf("/api/v1/organizations/%s/serviceaccounts",
		url.PathEscape(orgID))
}

// GetQuotas returns the endpoint for getting quotas for an organization.
func (e *Endpoints) GetQuotas(orgID string) string {
	return fmt.Sprintf("/api/v1/organizations/%s/quotas",
		url.PathEscape(orgID))
}
