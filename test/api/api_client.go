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

//nolint:revive // naming conventions acceptable in test code
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/onsi/ginkgo/v2"

	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

// GinkgoLogger implements the Logger interface for Ginkgo tests.
type GinkgoLogger struct{}

func (g *GinkgoLogger) Printf(format string, args ...interface{}) {
	ginkgo.GinkgoWriter.Printf(format, args...)
}

// APIClient wraps the core API client with identity-specific methods.
// Add methods here as you write tests for specific endpoints.
type APIClient struct {
	*coreclient.APIClient
	config    *TestConfig
	endpoints *Endpoints
}

// GetListOrganizationsPath returns the path for listing organizations.
// This is useful for tests that need direct access to the endpoint path.
func (c *APIClient) GetListOrganizationsPath() string {
	return c.endpoints.ListOrganizations()
}

// NewAPIClient creates a new Identity API client.
func NewAPIClient(baseURL string) (*APIClient, error) {
	config, err := LoadTestConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load test configuration: %w", err)
	}

	if baseURL == "" {
		baseURL = config.BaseURL
	}

	return newAPIClientWithConfig(config, baseURL), nil
}

// NewAPIClientWithConfig creates a new Identity API client with the given config.
func NewAPIClientWithConfig(config *TestConfig) *APIClient {
	return newAPIClientWithConfig(config, config.BaseURL)
}

// common constructor logic.
func newAPIClientWithConfig(config *TestConfig, baseURL string) *APIClient {
	coreClient := coreclient.NewAPIClient(baseURL, config.AuthToken, config.RequestTimeout, &GinkgoLogger{})
	coreClient.SetLogRequests(config.LogRequests)
	coreClient.SetLogResponses(config.LogResponses)

	return &APIClient{
		APIClient: coreClient,
		config:    config,
		endpoints: NewEndpoints(),
	}
}

// ListOrganizations lists all organizations.
func (c *APIClient) ListOrganizations(ctx context.Context) (identityopenapi.Organizations, error) {
	path := c.endpoints.ListOrganizations()

	return coreclient.ListResource[identityopenapi.OrganizationRead](
		ctx,
		c.APIClient,
		path,
		coreclient.ResponseHandlerConfig{
			ResourceType:   "organizations",
			ResourceID:     "",
			ResourceIDType: "",
		},
	)
}

// GetOrganization gets detailed information about a specific organization.
func (c *APIClient) GetOrganization(ctx context.Context, orgID string) (*identityopenapi.OrganizationRead, error) {
	path := c.endpoints.GetOrganization(orgID)

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, respBody, err := c.DoRequest(ctx, http.MethodGet, path, nil, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("getting organization: %w", err)
	}

	var organization identityopenapi.OrganizationRead
	if err := json.Unmarshal(respBody, &organization); err != nil {
		return nil, fmt.Errorf("unmarshaling organization: %w", err)
	}

	return &organization, nil
}

// ListProjects lists all projects in an organization.
func (c *APIClient) ListProjects(ctx context.Context, orgID string) (identityopenapi.Projects, error) {
	path := c.endpoints.ListProjects(orgID)

	return coreclient.ListResource[identityopenapi.ProjectRead](
		ctx,
		c.APIClient,
		path,
		coreclient.ResponseHandlerConfig{
			ResourceType:   "projects",
			ResourceID:     orgID,
			ResourceIDType: "organization",
		},
	)
}

// GetProject gets detailed information about a specific project.
func (c *APIClient) GetProject(ctx context.Context, orgID, projectID string) (*identityopenapi.ProjectRead, error) {
	path := c.endpoints.GetProject(orgID, projectID)

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, respBody, err := c.DoRequest(ctx, http.MethodGet, path, nil, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("getting project: %w", err)
	}

	var project identityopenapi.ProjectRead
	if err := json.Unmarshal(respBody, &project); err != nil {
		return nil, fmt.Errorf("unmarshaling project: %w", err)
	}

	return &project, nil
}

// ListGroups lists all groups in an organization.
func (c *APIClient) ListGroups(ctx context.Context, orgID string) (identityopenapi.Groups, error) {
	path := c.endpoints.ListGroups(orgID)

	return coreclient.ListResource[identityopenapi.GroupRead](
		ctx,
		c.APIClient,
		path,
		coreclient.ResponseHandlerConfig{
			ResourceType:   "groups",
			ResourceID:     orgID,
			ResourceIDType: "organization",
		},
	)
}

// GetGroup gets detailed information about a specific group.
func (c *APIClient) GetGroup(ctx context.Context, orgID, groupID string) (*identityopenapi.GroupRead, error) {
	path := c.endpoints.GetGroup(orgID, groupID)

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, respBody, err := c.DoRequest(ctx, http.MethodGet, path, nil, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("getting group: %w", err)
	}

	var group identityopenapi.GroupRead
	if err := json.Unmarshal(respBody, &group); err != nil {
		return nil, fmt.Errorf("unmarshaling group: %w", err)
	}

	return &group, nil
}

// CreateGroup creates a new group in an organization.
func (c *APIClient) CreateGroup(ctx context.Context, orgID string, group identityopenapi.GroupWrite) (*identityopenapi.GroupRead, error) {
	path := c.endpoints.ListGroups(orgID)

	body, err := json.Marshal(group)
	if err != nil {
		return nil, fmt.Errorf("marshaling group: %w", err)
	}

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, respBody, err := c.DoRequest(ctx, http.MethodPost, path, bytes.NewReader(body), http.StatusCreated)
	if err != nil {
		return nil, fmt.Errorf("creating group: %w", err)
	}

	var created identityopenapi.GroupRead
	if err := json.Unmarshal(respBody, &created); err != nil {
		return nil, fmt.Errorf("unmarshaling created group: %w", err)
	}

	return &created, nil
}

// DeleteGroup deletes a group from an organization.
func (c *APIClient) DeleteGroup(ctx context.Context, orgID, groupID string) error {
	path := c.endpoints.GetGroup(orgID, groupID)

	//nolint:bodyclose // DoRequest handles response body closing internally
	// API returns 200 for synchronous deletes
	_, _, err := c.DoRequest(ctx, http.MethodDelete, path, nil, http.StatusOK)
	if err != nil {
		return fmt.Errorf("deleting group: %w", err)
	}

	return nil
}

// GetGlobalACL gets the global ACL for the current user.
func (c *APIClient) GetGlobalACL(ctx context.Context) (*identityopenapi.Acl, error) {
	path := c.endpoints.GetGlobalACL()

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, respBody, err := c.DoRequest(ctx, http.MethodGet, path, nil, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("getting global ACL: %w", err)
	}

	var acl identityopenapi.Acl
	if err := json.Unmarshal(respBody, &acl); err != nil {
		return nil, fmt.Errorf("unmarshaling ACL: %w", err)
	}

	return &acl, nil
}

// GetOrganizationACL gets the ACL for a specific organization.
func (c *APIClient) GetOrganizationACL(ctx context.Context, orgID string) (*identityopenapi.Acl, error) {
	path := c.endpoints.GetOrganizationACL(orgID)

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, respBody, err := c.DoRequest(ctx, http.MethodGet, path, nil, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("getting organization ACL: %w", err)
	}

	var acl identityopenapi.Acl
	if err := json.Unmarshal(respBody, &acl); err != nil {
		return nil, fmt.Errorf("unmarshaling ACL: %w", err)
	}

	return &acl, nil
}

// ListUsers lists all users in an organization.
func (c *APIClient) ListUsers(ctx context.Context, orgID string) (identityopenapi.Users, error) {
	path := c.endpoints.ListUsers(orgID)

	return coreclient.ListResource[identityopenapi.UserRead](
		ctx,
		c.APIClient,
		path,
		coreclient.ResponseHandlerConfig{
			ResourceType:   "users",
			ResourceID:     orgID,
			ResourceIDType: "organization",
		},
	)
}

// ListRoles lists all roles in an organization.
func (c *APIClient) ListRoles(ctx context.Context, orgID string) (identityopenapi.Roles, error) {
	path := c.endpoints.ListRoles(orgID)

	return coreclient.ListResource[identityopenapi.RoleRead](
		ctx,
		c.APIClient,
		path,
		coreclient.ResponseHandlerConfig{
			ResourceType:   "roles",
			ResourceID:     orgID,
			ResourceIDType: "organization",
		},
	)
}

// ListServiceAccounts lists all service accounts in an organization.
func (c *APIClient) ListServiceAccounts(ctx context.Context, orgID string) (identityopenapi.ServiceAccounts, error) {
	path := c.endpoints.ListServiceAccounts(orgID)

	return coreclient.ListResource[identityopenapi.ServiceAccountRead](
		ctx,
		c.APIClient,
		path,
		coreclient.ResponseHandlerConfig{
			ResourceType:   "serviceAccounts",
			ResourceID:     orgID,
			ResourceIDType: "organization",
		},
	)
}

// GetQuotas gets the quotas for an organization.
func (c *APIClient) GetQuotas(ctx context.Context, orgID string) (*identityopenapi.QuotasRead, error) {
	path := c.endpoints.GetQuotas(orgID)

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, respBody, err := c.DoRequest(ctx, http.MethodGet, path, nil, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("getting quotas: %w", err)
	}

	var quotas identityopenapi.QuotasRead
	if err := json.Unmarshal(respBody, &quotas); err != nil {
		return nil, fmt.Errorf("unmarshaling quotas: %w", err)
	}

	return &quotas, nil
}

// ListAllocations lists all allocations in an organization.
func (c *APIClient) ListAllocations(ctx context.Context, orgID string) (identityopenapi.Allocations, error) {
	path := c.endpoints.ListAllocations(orgID)

	return coreclient.ListResource[identityopenapi.AllocationRead](
		ctx,
		c.APIClient,
		path,
		coreclient.ResponseHandlerConfig{
			ResourceType:   "allocations",
			ResourceID:     orgID,
			ResourceIDType: "organization",
		},
	)
}
