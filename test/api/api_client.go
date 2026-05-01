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

//nolint:revive // naming conventions acceptable in test code
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

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

// GetEndpoints returns the endpoints helper for direct path access in tests.
func (c *APIClient) GetEndpoints() *Endpoints {
	return c.endpoints
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
	resp, respBody, err := c.DoRequest(ctx, http.MethodGet, path, nil, http.StatusOK)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("project %s: %w", projectID, coreclient.ErrResourceNotFound)
		}

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
	resp, respBody, err := c.DoRequest(ctx, http.MethodGet, path, nil, http.StatusOK)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("group %s: %w", groupID, coreclient.ErrResourceNotFound)
		}

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

// UpdateGroup updates an existing group in an organization.
// Returns the updated group when the API includes a body in the 200 response
// (Phase 1 behaviour), or nil when the body is empty (pre-Phase-1 behaviour).
// Callers that need to assert the body is present should check the returned
// pointer is non-nil.
func (c *APIClient) UpdateGroup(ctx context.Context, orgID, groupID string, group identityopenapi.GroupWrite) (*identityopenapi.GroupRead, error) {
	path := c.endpoints.GetGroup(orgID, groupID)

	body, err := json.Marshal(group)
	if err != nil {
		return nil, fmt.Errorf("marshaling group: %w", err)
	}

	//nolint:bodyclose // DoRequest handles response body closing internally
	resp, respBody, err := c.DoRequest(ctx, http.MethodPut, path, bytes.NewReader(body), http.StatusOK)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("group %s: %w", groupID, coreclient.ErrResourceNotFound)
		}

		return nil, fmt.Errorf("updating group: %w", err)
	}

	// Pre-Phase-1 the API returned 200 with an empty body; tolerate that here
	// so existing tests continue to pass. Phase-1 returns the updated group JSON.
	if len(respBody) == 0 {
		return nil, nil //nolint:nilnil // intentional: empty body is valid pre-Phase-1
	}

	var updated identityopenapi.GroupRead
	if err := json.Unmarshal(respBody, &updated); err != nil {
		return nil, fmt.Errorf("unmarshaling updated group: %w", err)
	}

	return &updated, nil
}

// GetUserinfo returns userinfo claims for the current token.
func (c *APIClient) GetUserinfo(ctx context.Context) (*identityopenapi.Userinfo, error) {
	path := c.endpoints.GetUserinfo()

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, respBody, err := c.DoRequest(ctx, http.MethodGet, path, nil, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("getting userinfo: %w", err)
	}

	var userinfo identityopenapi.Userinfo
	if err := json.Unmarshal(respBody, &userinfo); err != nil {
		return nil, fmt.Errorf("unmarshaling userinfo: %w", err)
	}

	return &userinfo, nil
}

// DeleteGroup deletes a group from an organization.
func (c *APIClient) DeleteGroup(ctx context.Context, orgID, groupID string) error {
	path := c.endpoints.GetGroup(orgID, groupID)

	//nolint:bodyclose // DoRequest handles response body closing internally
	// API returns 200 for synchronous deletes
	resp, _, err := c.DoRequest(ctx, http.MethodDelete, path, nil, http.StatusOK)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("group %s: %w", groupID, coreclient.ErrResourceNotFound)
		}

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

// SetQuotas updates the quotas for an organization.
func (c *APIClient) SetQuotas(ctx context.Context, orgID string, quotas identityopenapi.QuotasWrite) (*identityopenapi.QuotasRead, error) {
	path := c.endpoints.GetQuotas(orgID)

	body, err := json.Marshal(quotas)
	if err != nil {
		return nil, fmt.Errorf("marshaling quotas: %w", err)
	}

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, respBody, err := c.DoRequest(ctx, http.MethodPut, path, bytes.NewReader(body), http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("setting quotas: %w", err)
	}

	var updated identityopenapi.QuotasRead
	if err := json.Unmarshal(respBody, &updated); err != nil {
		return nil, fmt.Errorf("unmarshaling updated quotas: %w", err)
	}

	return &updated, nil
}

// UpdateOrganization updates an organization.
func (c *APIClient) UpdateOrganization(ctx context.Context, orgID string, org identityopenapi.OrganizationWrite) error {
	return putResourceVoid(c, ctx, c.endpoints.GetOrganization(orgID), orgID, "organization", org)
}

// CreateProject creates a new project in an organization.
func (c *APIClient) CreateProject(ctx context.Context, orgID string, project identityopenapi.ProjectWrite) (*identityopenapi.ProjectRead, error) {
	path := c.endpoints.ListProjects(orgID)

	body, err := json.Marshal(project)
	if err != nil {
		return nil, fmt.Errorf("marshaling project: %w", err)
	}

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, respBody, err := c.DoRequest(ctx, http.MethodPost, path, bytes.NewReader(body), http.StatusAccepted)
	if err != nil {
		return nil, fmt.Errorf("creating project: %w", err)
	}

	var created identityopenapi.ProjectRead
	if err := json.Unmarshal(respBody, &created); err != nil {
		return nil, fmt.Errorf("unmarshaling created project: %w", err)
	}

	return &created, nil
}

// UpdateProject updates an existing project.
func (c *APIClient) UpdateProject(ctx context.Context, orgID, projectID string, project identityopenapi.ProjectWrite) error {
	return putResourceVoid(c, ctx, c.endpoints.GetProject(orgID, projectID), projectID, "project", project)
}

// DeleteProject deletes a project from an organization.
func (c *APIClient) DeleteProject(ctx context.Context, orgID, projectID string) error {
	path := c.endpoints.GetProject(orgID, projectID)

	//nolint:bodyclose // DoRequest handles response body closing internally
	resp, _, err := c.DoRequest(ctx, http.MethodDelete, path, nil, http.StatusAccepted)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("project %s: %w", projectID, coreclient.ErrResourceNotFound)
		}

		return fmt.Errorf("deleting project: %w", err)
	}

	return nil
}

// CreateServiceAccount creates a new service account in an organization.
// The returned ServiceAccountCreate.Status.AccessToken is non-nil and contains
// the one-time access token — it is only present on create and rotate responses.
func (c *APIClient) CreateServiceAccount(ctx context.Context, orgID string, sa identityopenapi.ServiceAccountWrite) (*identityopenapi.ServiceAccountCreate, error) {
	path := c.endpoints.ListServiceAccounts(orgID)

	body, err := json.Marshal(sa)
	if err != nil {
		return nil, fmt.Errorf("marshaling service account: %w", err)
	}

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, respBody, err := c.DoRequest(ctx, http.MethodPost, path, bytes.NewReader(body), http.StatusCreated)
	if err != nil {
		return nil, fmt.Errorf("creating service account: %w", err)
	}

	var created identityopenapi.ServiceAccountCreate
	if err := json.Unmarshal(respBody, &created); err != nil {
		return nil, fmt.Errorf("unmarshaling created service account: %w", err)
	}

	return &created, nil
}

// putResourceVoid marshals req and PUTs it to path, discarding the response body.
// It maps 404 responses to coreclient.ErrResourceNotFound.
func putResourceVoid[Req any](c *APIClient, ctx context.Context, path, resourceID, resourceKind string, req Req) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshaling %s: %w", resourceKind, err)
	}

	//nolint:bodyclose // DoRequest handles response body closing internally
	resp, _, err := c.DoRequest(ctx, http.MethodPut, path, bytes.NewReader(body), http.StatusOK)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("%s %s: %w", resourceKind, resourceID, coreclient.ErrResourceNotFound)
		}

		return fmt.Errorf("updating %s: %w", resourceKind, err)
	}

	return nil
}

// putResource marshals req, PUTs it to path, and unmarshals the response into R.
// It maps 404 responses to coreclient.ErrResourceNotFound using resourceKind and resourceID in error messages.
func putResource[Req, R any](c *APIClient, ctx context.Context, path, resourceID, resourceKind string, req Req) (*R, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling %s: %w", resourceKind, err)
	}

	//nolint:bodyclose // DoRequest handles response body closing internally
	resp, respBody, err := c.DoRequest(ctx, http.MethodPut, path, bytes.NewReader(body), http.StatusOK)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%s %s: %w", resourceKind, resourceID, coreclient.ErrResourceNotFound)
		}

		return nil, fmt.Errorf("updating %s: %w", resourceKind, err)
	}

	var result R
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshaling updated %s: %w", resourceKind, err)
	}

	return &result, nil
}

// UpdateServiceAccount updates an existing service account.
func (c *APIClient) UpdateServiceAccount(ctx context.Context, orgID, saID string, sa identityopenapi.ServiceAccountWrite) (*identityopenapi.ServiceAccountRead, error) {
	return putResource[identityopenapi.ServiceAccountWrite, identityopenapi.ServiceAccountRead](
		c, ctx, c.endpoints.GetServiceAccount(orgID, saID), saID, "service account", sa)
}

// DeleteServiceAccount deletes a service account from an organization.
func (c *APIClient) DeleteServiceAccount(ctx context.Context, orgID, saID string) error {
	path := c.endpoints.GetServiceAccount(orgID, saID)

	//nolint:bodyclose // DoRequest handles response body closing internally
	resp, _, err := c.DoRequest(ctx, http.MethodDelete, path, nil, http.StatusOK)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("service account %s: %w", saID, coreclient.ErrResourceNotFound)
		}

		return fmt.Errorf("deleting service account: %w", err)
	}

	return nil
}

// RotateServiceAccount rotates the access token for a service account.
// The returned ServiceAccountCreate.Status.AccessToken contains the new one-time token.
func (c *APIClient) RotateServiceAccount(ctx context.Context, orgID, saID string) (*identityopenapi.ServiceAccountCreate, error) {
	path := c.endpoints.RotateServiceAccount(orgID, saID)

	//nolint:bodyclose // DoRequest handles response body closing internally
	resp, respBody, err := c.DoRequest(ctx, http.MethodPost, path, nil, http.StatusOK)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("service account %s: %w", saID, coreclient.ErrResourceNotFound)
		}

		return nil, fmt.Errorf("rotating service account: %w", err)
	}

	var rotated identityopenapi.ServiceAccountCreate
	if err := json.Unmarshal(respBody, &rotated); err != nil {
		return nil, fmt.Errorf("unmarshaling rotated service account: %w", err)
	}

	return &rotated, nil
}

// CreateUser creates a new user in an organization.
func (c *APIClient) CreateUser(ctx context.Context, orgID string, user identityopenapi.UserWrite) (*identityopenapi.UserRead, error) {
	path := c.endpoints.ListUsers(orgID)

	body, err := json.Marshal(user)
	if err != nil {
		return nil, fmt.Errorf("marshaling user: %w", err)
	}

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, respBody, err := c.DoRequest(ctx, http.MethodPost, path, bytes.NewReader(body), http.StatusCreated)
	if err != nil {
		return nil, fmt.Errorf("creating user: %w", err)
	}

	var created identityopenapi.UserRead
	if err := json.Unmarshal(respBody, &created); err != nil {
		return nil, fmt.Errorf("unmarshaling created user: %w", err)
	}

	return &created, nil
}

// UpdateUser updates an existing user.
func (c *APIClient) UpdateUser(ctx context.Context, orgID, userID string, user identityopenapi.UserWrite) (*identityopenapi.UserRead, error) {
	return putResource[identityopenapi.UserWrite, identityopenapi.UserRead](
		c, ctx, c.endpoints.GetUser(orgID, userID), userID, "user", user)
}

// DeleteUser deletes a user from an organization.
func (c *APIClient) DeleteUser(ctx context.Context, orgID, userID string) error {
	path := c.endpoints.GetUser(orgID, userID)

	//nolint:bodyclose // DoRequest handles response body closing internally
	resp, _, err := c.DoRequest(ctx, http.MethodDelete, path, nil, http.StatusOK)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("user %s: %w", userID, coreclient.ErrResourceNotFound)
		}

		return fmt.Errorf("deleting user: %w", err)
	}

	return nil
}

// ListGlobalOauth2Providers lists platform-level OAuth2 providers (not scoped to an organization).
func (c *APIClient) ListGlobalOauth2Providers(ctx context.Context) (identityopenapi.Oauth2Providers, error) {
	path := c.endpoints.ListGlobalOauth2Providers()

	return coreclient.ListResource[identityopenapi.Oauth2ProviderRead](
		ctx,
		c.APIClient,
		path,
		coreclient.ResponseHandlerConfig{
			ResourceType:   "oauth2providers",
			ResourceID:     "",
			ResourceIDType: "",
		},
	)
}

// ListOauth2Providers lists all OAuth2 providers in an organization.
func (c *APIClient) ListOauth2Providers(ctx context.Context, orgID string) (identityopenapi.Oauth2Providers, error) {
	path := c.endpoints.ListOauth2Providers(orgID)

	return coreclient.ListResource[identityopenapi.Oauth2ProviderRead](
		ctx,
		c.APIClient,
		path,
		coreclient.ResponseHandlerConfig{
			ResourceType:   "oauth2providers",
			ResourceID:     orgID,
			ResourceIDType: "organization",
		},
	)
}

// CreateOauth2Provider creates a new OAuth2 provider in an organization.
func (c *APIClient) CreateOauth2Provider(ctx context.Context, orgID string, provider identityopenapi.Oauth2ProviderWrite) (*identityopenapi.Oauth2ProviderRead, error) {
	path := c.endpoints.ListOauth2Providers(orgID)

	body, err := json.Marshal(provider)
	if err != nil {
		return nil, fmt.Errorf("marshaling oauth2provider: %w", err)
	}

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, respBody, err := c.DoRequest(ctx, http.MethodPost, path, bytes.NewReader(body), http.StatusCreated)
	if err != nil {
		return nil, fmt.Errorf("creating oauth2provider: %w", err)
	}

	var created identityopenapi.Oauth2ProviderRead
	if err := json.Unmarshal(respBody, &created); err != nil {
		return nil, fmt.Errorf("unmarshaling created oauth2provider: %w", err)
	}

	return &created, nil
}

// UpdateOauth2Provider updates an existing OAuth2 provider. Returns nil on success.
func (c *APIClient) UpdateOauth2Provider(ctx context.Context, orgID, providerID string, provider identityopenapi.Oauth2ProviderWrite) error {
	return putResourceVoid(c, ctx, c.endpoints.GetOauth2Provider(orgID, providerID), providerID, "oauth2provider", provider)
}

// DeleteOauth2Provider deletes an OAuth2 provider from an organization.
func (c *APIClient) DeleteOauth2Provider(ctx context.Context, orgID, providerID string) error {
	path := c.endpoints.GetOauth2Provider(orgID, providerID)

	//nolint:bodyclose // DoRequest handles response body closing internally
	resp, _, err := c.DoRequest(ctx, http.MethodDelete, path, nil, http.StatusOK)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("oauth2provider %s: %w", providerID, coreclient.ErrResourceNotFound)
		}

		return fmt.Errorf("deleting oauth2provider: %w", err)
	}

	return nil
}

// PassportExchangeResponse is the response body from POST /oauth2/v2/exchange.
type PassportExchangeResponse struct {
	Passport  string `json:"passport"`
	ExpiresIn int    `json:"expires_in"`
	Error     string `json:"error,omitempty"`
}

// JWKS represents the JSON Web Key Set returned by GET /oauth2/v2/jwks.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a single JSON Web Key.
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// WithToken returns a copy of this client using the provided auth token.
// Useful for testing with specific token values (empty, invalid, etc.).
func (c *APIClient) WithToken(token string) *APIClient {
	newConfig := *c.config
	newConfig.AuthToken = token

	return NewAPIClientWithConfig(&newConfig)
}

// ExchangePassport exchanges the current client's token for a passport JWT.
// scopeParams may include "organizationId" and/or "projectId" keys.
// Returns an error if the server does not return 200.
func (c *APIClient) ExchangePassport(ctx context.Context, scopeParams map[string]string) (*PassportExchangeResponse, error) {
	statusCode, body, err := c.ExchangePassportRaw(ctx, scopeParams)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("exchange returned %d: %s", statusCode, string(body))
	}

	var result PassportExchangeResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshaling exchange response: %w", err)
	}

	return &result, nil
}

// ExchangePassportRaw posts to the passport exchange endpoint with form-encoded body,
// returning the raw HTTP status code and response body without asserting success.
// Use this for testing rejection cases where a non-200 response is expected.
func (c *APIClient) ExchangePassportRaw(ctx context.Context, scopeParams map[string]string) (int, []byte, error) {
	form := url.Values{}
	for k, v := range scopeParams {
		form.Set(k, v)
	}

	fullURL := c.config.BaseURL + c.endpoints.ExchangePassport()

	reqCtx, cancel := context.WithTimeout(ctx, c.config.RequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, fullURL, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, fmt.Errorf("creating exchange request: %w", err)
	}

	if c.config.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.AuthToken)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Use http.DefaultClient so it picks up the TLS transport patched in tls_darwin_test.go.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("executing exchange request: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("reading exchange response: %w", err)
	}

	return resp.StatusCode, body, nil
}

// GetJWKS fetches the public JWKS from the identity service.
func (c *APIClient) GetJWKS(ctx context.Context) (*JWKS, error) {
	path := c.endpoints.GetJWKS()

	//nolint:bodyclose // DoRequest handles response body closing internally
	_, respBody, err := c.DoRequest(ctx, http.MethodGet, path, nil, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("getting JWKS: %w", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(respBody, &jwks); err != nil {
		return nil, fmt.Errorf("unmarshaling JWKS: %w", err)
	}

	return &jwks, nil
}
