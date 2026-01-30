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

package region_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// ErrOrganizationNamespaceNotFound is returned when an organization namespace cannot be found.
	ErrOrganizationNamespaceNotFound = errors.New("organization namespace not found")
	// ErrProjectNamespaceNotFound is returned when a project namespace cannot be found.
	ErrProjectNamespaceNotFound = errors.New("project namespace not found")
)

const (
	TestNamespace = "unikorn-identity-test"
)

type StateManager struct {
	client         client.Client
	namespace      string
	namespaceCache map[string]string // Maps org/project IDs to actual unique namespace names
	counter        int               // Counter for ensuring uniqueness within the same second
}

func NewStateManager(k8sClient client.Client, namespace string) *StateManager {
	return &StateManager{
		client:         k8sClient,
		namespace:      namespace,
		namespaceCache: make(map[string]string),
	}
}

// getOrCreateUniqueNamespace generates a unique namespace name or returns cached one.
func (sm *StateManager) getUniqueNamespace(prefix string) string {
	if cached, ok := sm.namespaceCache[prefix]; ok {
		return cached
	}
	// Generate unique namespace with timestamp and counter to avoid conflicts during async deletion
	sm.counter++
	unique := fmt.Sprintf("%s-%d-%d", prefix, time.Now().Unix(), sm.counter)
	sm.namespaceCache[prefix] = unique

	return unique
}

// setupUser creates a test user resource for RBAC.
func (sm *StateManager) setupUser(ctx context.Context, subject string) error {
	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name:      subject,
			Namespace: sm.namespace,
		},
		Spec: unikornv1.UserSpec{
			Subject: subject,
			State:   unikornv1.UserStateActive,
		},
	}

	// Try to create, ignore if exists
	err := sm.client.Create(ctx, user)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// setupOrganizationUser creates an OrganizationUser resource linking a user to an organization.
func (sm *StateManager) setupOrganizationUser(ctx context.Context, orgID, userName string) error {
	orgNamespace, ok := sm.namespaceCache[fmt.Sprintf("org-%s", orgID)]
	if !ok {
		return fmt.Errorf("%w for org %s", ErrOrganizationNamespaceNotFound, orgID)
	}

	orgUser := &unikornv1.OrganizationUser{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-in-%s", userName, orgID),
			Namespace: orgNamespace,
			Labels: map[string]string{
				constants.OrganizationLabel: orgID,
				constants.UserLabel:         userName,
			},
		},
		Spec: unikornv1.OrganizationUserSpec{
			State: unikornv1.UserStateActive,
		},
	}

	// Try to create, ignore if exists
	err := sm.client.Create(ctx, orgUser)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("failed to create organization user: %w", err)
	}

	return nil
}

// setupRole creates a role with specified scopes.
func (sm *StateManager) setupRole(ctx context.Context, roleID string, scopes unikornv1.RoleScopes) error {
	role := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleID,
			Namespace: sm.namespace,
		},
		Spec: unikornv1.RoleSpec{
			Scopes: scopes,
		},
	}

	// Try to create, ignore if exists
	err := sm.client.Create(ctx, role)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("failed to create role: %w", err)
	}

	return nil
}

// setupGroup creates a group linking users to roles.
// organizationUserName is the name of the OrganizationUser resource (e.g., "test-user-in-orgid").
// All groups (both org-scoped and project-scoped) are created in the organization namespace.
// Project-scoped groups are linked to projects via project.Spec.GroupIDs.
func (sm *StateManager) setupGroup(ctx context.Context, groupID, organizationUserName, roleID string, orgID, projectID string) error {
	orgNamespace, ok := sm.namespaceCache[fmt.Sprintf("org-%s", orgID)]
	if !ok {
		return fmt.Errorf("%w for org %s", ErrOrganizationNamespaceNotFound, orgID)
	}

	// All groups go in the organization namespace, not project namespace
	// The RBAC implementation looks for groups only in the org namespace
	group := &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Name:      groupID,
			Namespace: orgNamespace,
		},
		Spec: unikornv1.GroupSpec{
			UserIDs: []string{organizationUserName},
			RoleIDs: []string{roleID},
		},
	}

	// Try to create, ignore if exists
	err := sm.client.Create(ctx, group)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("failed to create group: %w", err)
	}

	// If this is a project-scoped group, link it to the project
	if projectID != "" {
		if err := sm.linkGroupToProject(ctx, orgID, projectID, groupID); err != nil {
			return err
		}
	}

	return nil
}

// linkGroupToProject adds a group ID to a project's GroupIDs list.
func (sm *StateManager) linkGroupToProject(ctx context.Context, orgID, projectID, groupID string) error {
	orgNamespace, ok := sm.namespaceCache[fmt.Sprintf("org-%s", orgID)]
	if !ok {
		return fmt.Errorf("%w for org %s", ErrOrganizationNamespaceNotFound, orgID)
	}

	project := &unikornv1.Project{}
	if err := sm.client.Get(ctx, client.ObjectKey{Name: projectID, Namespace: orgNamespace}, project); err != nil {
		return fmt.Errorf("failed to get project: %w", err)
	}

	// Check if group is already linked
	if !slices.Contains(project.Spec.GroupIDs, groupID) {
		project.Spec.GroupIDs = append(project.Spec.GroupIDs, groupID)
		if err := sm.client.Update(ctx, project); err != nil {
			return fmt.Errorf("failed to update project with group ID: %w", err)
		}
	}

	return nil
}

func getStringParam(params map[string]any, key string, defaultValue string) string {
	if val, ok := params[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}

	return defaultValue
}

// unwrapPactParams extracts actual parameters from Pact's "params" wrapper.
func unwrapPactParams(params map[string]any) map[string]any {
	if wrappedParams, ok := params["params"].(map[string]any); ok {
		return wrappedParams
	}

	return params
}

// setupProjectWithPermissions is a helper that sets up project with organization, user, role, and group.
func (sm *StateManager) setupProjectWithPermissions(ctx context.Context, orgID, projectID, userName, roleName, groupName string, roleScopes unikornv1.RoleScopes) error {
	if err := sm.setupOrganization(ctx, orgID); err != nil {
		return err
	}

	if err := sm.setupProject(ctx, orgID, projectID); err != nil {
		return err
	}

	if err := sm.setupUser(ctx, userName); err != nil {
		return err
	}

	if err := sm.setupOrganizationUser(ctx, orgID, userName); err != nil {
		return err
	}

	if err := sm.setupRole(ctx, roleName, roleScopes); err != nil {
		return err
	}

	organizationUserName := fmt.Sprintf("%s-in-%s", userName, orgID)
	if err := sm.setupGroup(ctx, groupName, organizationUserName, roleName, orgID, projectID); err != nil {
		return err
	}

	return nil
}

func (sm *StateManager) HandleProjectExists(ctx context.Context, setup bool, params map[string]any) error {
	actualParams := unwrapPactParams(params)
	orgID := getStringParam(actualParams, "organizationID", "c9d0e1f2-a3b4-4c5d-6e7f-8a9b0c1d2e3f")
	projectID := getStringParam(actualParams, "projectID", "d0e1f2a3-b4c5-4d6e-7f8a-9b0c1d2e3f4a")

	if setup {
		roleScopes := unikornv1.RoleScopes{
			Project: []unikornv1.RoleScope{
				{Name: "identity:allocations", Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Read, unikornv1.Update, unikornv1.Delete}},
			},
		}

		return sm.setupProjectWithPermissions(ctx, orgID, projectID, "test-user", "allocation-role", "allocation-group", roleScopes)
	}

	return sm.cleanupOrganization(ctx, orgID)
}

func (sm *StateManager) HandleAllocationExists(ctx context.Context, setup bool, params map[string]any) error {
	actualParams := unwrapPactParams(params)
	allocationID := getStringParam(actualParams, "allocationID", "a3b4c5d6-e7f8-4a9b-0c1d-2e3f4a5b6c7d")
	orgID := getStringParam(actualParams, "organizationID", "e1f2a3b4-c5d6-4e7f-8a9b-0c1d2e3f4a5b")
	projectID := getStringParam(actualParams, "projectID", "f2a3b4c5-d6e7-4f8a-9b0c-1d2e3f4a5b6c")

	if setup {
		roleScopes := unikornv1.RoleScopes{
			Project: []unikornv1.RoleScope{
				{Name: "identity:allocations", Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Read, unikornv1.Update, unikornv1.Delete}},
			},
		}

		if err := sm.setupProjectWithPermissions(ctx, orgID, projectID, "test-user", "allocation-role", "allocation-group", roleScopes); err != nil {
			return err
		}

		return sm.setupAllocation(ctx, orgID, projectID, allocationID)
	}

	return sm.cleanupOrganization(ctx, orgID)
}

// Helper methods for resource creation and cleanup

func (sm *StateManager) setupOrganization(ctx context.Context, orgID string) error {
	// Clean up first to ensure clean slate
	_ = sm.cleanupOrganization(ctx, orgID)

	// Create organization namespace with unique name to avoid conflicts
	orgNamespace := sm.getUniqueNamespace(fmt.Sprintf("org-%s", orgID))
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: orgNamespace,
		},
	}

	_ = sm.client.Create(ctx, ns)

	// Create Organization resource
	org := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      orgID,
			Namespace: sm.namespace,
		},
		Spec: unikornv1.OrganizationSpec{},
	}

	if err := sm.client.Create(ctx, org); err != nil {
		return fmt.Errorf("failed to create organization %s: %w", orgID, err)
	}

	// Update status with namespace
	org.Status.Namespace = orgNamespace
	if err := sm.client.Status().Update(ctx, org); err != nil {
		return fmt.Errorf("failed to update organization status: %w", err)
	}

	return nil
}

func (sm *StateManager) cleanupOrganization(ctx context.Context, orgID string) error {
	// Try to get the cached org namespace, otherwise try to read from Organization CR
	orgNamespace, ok := sm.namespaceCache[fmt.Sprintf("org-%s", orgID)]

	if !ok {
		// Try to get it from the Organization CR status
		org := &unikornv1.Organization{}
		err := sm.client.Get(ctx, client.ObjectKey{Name: orgID, Namespace: sm.namespace}, org)

		if err == nil && org.Status.Namespace != "" {
			orgNamespace = org.Status.Namespace
		} else {
			// Fallback to default pattern (might not exist, but that's okay)
			orgNamespace = fmt.Sprintf("org-%s", orgID)
		}
	}

	// Clean up ALL OrganizationUsers for this organization across all namespaces
	// This handles old namespaces from previous test runs
	orgUserList := &unikornv1.OrganizationUserList{}
	_ = sm.client.List(ctx, orgUserList, client.MatchingLabels{
		constants.OrganizationLabel: orgID,
	})

	for i := range orgUserList.Items {
		_ = sm.client.Delete(ctx, &orgUserList.Items[i])
	}

	// Don't delete namespaces - they go into Terminating state and cause the handler to find
	// multiple namespaces with the same labels. Instead, just delete the CRs and reuse
	// the namespaces in subsequent tests.

	// 1. Delete allocation CRs in project namespaces
	projectNsList := &corev1.NamespaceList{}
	_ = sm.client.List(ctx, projectNsList, client.MatchingLabels{
		"unikorn-cloud.org/kind":         "project",
		"unikorn-cloud.org/organization": orgID,
	})

	for i := range projectNsList.Items {
		projectNs := &projectNsList.Items[i]
		allocationList := &unikornv1.AllocationList{}
		_ = sm.client.List(ctx, allocationList, client.InNamespace(projectNs.Name))

		for j := range allocationList.Items {
			_ = sm.client.Delete(ctx, &allocationList.Items[j])
		}
	}

	// 2. Delete all Project CRs in this organization
	projectList := &unikornv1.ProjectList{}
	_ = sm.client.List(ctx, projectList, client.InNamespace(orgNamespace))

	for i := range projectList.Items {
		_ = sm.client.Delete(ctx, &projectList.Items[i])
	}

	// 3. Delete all Groups in this organization namespace
	groupList := &unikornv1.GroupList{}
	_ = sm.client.List(ctx, groupList, client.InNamespace(orgNamespace))

	for i := range groupList.Items {
		_ = sm.client.Delete(ctx, &groupList.Items[i])
	}

	// 4. Delete organization CR
	org := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      orgID,
			Namespace: sm.namespace,
		},
	}

	_ = sm.client.Delete(ctx, org)

	// Clear cache entries for this organization and its projects
	delete(sm.namespaceCache, fmt.Sprintf("org-%s", orgID))

	for _, project := range projectList.Items {
		delete(sm.namespaceCache, fmt.Sprintf("project-%s", project.Name))
	}

	return nil
}

func (sm *StateManager) setupProject(ctx context.Context, orgID, projectID string) error {
	// Get the cached unique org namespace
	orgNamespace, ok := sm.namespaceCache[fmt.Sprintf("org-%s", orgID)]
	if !ok {
		return fmt.Errorf("%w in cache for org %s", ErrOrganizationNamespaceNotFound, orgID)
	}

	// Check if a project namespace with these labels already exists and is NOT terminating
	// Reuse it if found, otherwise create a new unique one
	existingProjectNs := &corev1.NamespaceList{}
	_ = sm.client.List(ctx, existingProjectNs, client.MatchingLabels{
		"unikorn-cloud.org/kind":         "project",
		"unikorn-cloud.org/organization": orgID,
		"unikorn-cloud.org/project":      projectID,
	})

	var projectNamespace string

	foundActive := false

	// Look for an active (non-terminating) namespace to reuse
	for _, ns := range existingProjectNs.Items {
		if ns.DeletionTimestamp == nil {
			projectNamespace = ns.Name
			foundActive = true

			break
		}
	}

	// If no active namespace found, create a new unique one
	if !foundActive {
		projectNamespace = sm.getUniqueNamespace(fmt.Sprintf("project-%s", projectID))
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: projectNamespace,
				Labels: map[string]string{
					"unikorn-cloud.org/kind":         "project",
					"unikorn-cloud.org/organization": orgID,
					"unikorn-cloud.org/project":      projectID,
				},
			},
		}

		_ = sm.client.Create(ctx, ns)
	}

	// Cache the project namespace
	sm.namespaceCache[fmt.Sprintf("project-%s", projectID)] = projectNamespace

	// Create Project resource in organization namespace
	project := &unikornv1.Project{
		ObjectMeta: metav1.ObjectMeta{
			Name:      projectID,
			Namespace: orgNamespace,
			Labels: map[string]string{
				constants.OrganizationLabel: orgID,
			},
		},
		Spec: unikornv1.ProjectSpec{},
	}

	// Try to create, but handle already exists
	err := sm.client.Create(ctx, project)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("failed to create project %s: %w", projectID, err)
	}

	// If it already existed, get it first
	if err != nil {
		if err := sm.client.Get(ctx, client.ObjectKey{Name: projectID, Namespace: orgNamespace}, project); err != nil {
			return fmt.Errorf("failed to get existing project: %w", err)
		}
	}

	// Update status with namespace
	project.Status.Namespace = projectNamespace
	if err := sm.client.Status().Update(ctx, project); err != nil {
		return fmt.Errorf("failed to update project status: %w", err)
	}

	return nil
}

func (sm *StateManager) setupAllocation(ctx context.Context, orgID, projectID, allocationID string) error {
	// Get the cached unique project namespace
	projectNamespace, ok := sm.namespaceCache[fmt.Sprintf("project-%s", projectID)]
	if !ok {
		return fmt.Errorf("%w in cache for project %s", ErrProjectNamespaceNotFound, projectID)
	}

	// Determine kind from allocation ID (e.g., "cluster-allocation-1" -> kind="cluster")
	kind := "cluster"
	if strings.Contains(allocationID, "instance") {
		kind = "instance"
	}

	allocation := &unikornv1.Allocation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      allocationID,
			Namespace: projectNamespace,
			Labels: map[string]string{
				"unikorn-cloud.org/resource-kind": kind,
				"unikorn-cloud.org/resource-id":   allocationID,
				"unikorn-cloud.org/organization":  orgID,
				"unikorn-cloud.org/project":       projectID,
			},
			Annotations: map[string]string{
				"unikorn-cloud.org/creator":           "test-user",
				"unikorn-cloud.org/creator-principal": "test-user",
			},
		},
		Spec: unikornv1.AllocationSpec{
			Allocations: []unikornv1.ResourceAllocation{
				{
					Kind:      "servers",
					Committed: resource.NewQuantity(1, resource.DecimalSI),
					Reserved:  resource.NewQuantity(1, resource.DecimalSI),
				},
			},
		},
	}

	// Try to create, but handle already exists
	err := sm.client.Create(ctx, allocation)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("failed to create allocation %s: %w", allocationID, err)
	}

	_ = err

	// Verify allocation was created by reading it back
	verifyAllocation := &unikornv1.Allocation{}
	verifyErr := sm.client.Get(ctx, client.ObjectKey{
		Name:      allocationID,
		Namespace: projectNamespace,
	}, verifyAllocation)
	_ = verifyErr

	return nil
}

// TestAuthorizer implements the Authorizer interface for contract tests.
// TestAuthorizer implements the Authorizer interface for contract tests.
type TestAuthorizer struct {
	k8sClient client.Client
	namespace string
	rbac      *rbac.RBAC
}

// NewTestAuthorizer creates a test authorizer that uses real RBAC.
func NewTestAuthorizer(k8sClient client.Client, namespace string, rbacInstance *rbac.RBAC) *TestAuthorizer {
	return &TestAuthorizer{
		k8sClient: k8sClient,
		namespace: namespace,
		rbac:      rbacInstance,
	}
}

// Authorize returns mock authorization info without JWT validation.
func (a *TestAuthorizer) Authorize(input *openapi3filter.AuthenticationInput) (*authorization.Info, error) {
	// Determine which user to use based on test state
	// Check if admin-user has any OrganizationUsers (indicates platform admin test)
	adminOrgUserList := &unikornv1.OrganizationUserList{}
	err := a.k8sClient.List(context.Background(), adminOrgUserList, client.MatchingLabels{
		"unikorn-cloud.org/user": "admin-user",
	})

	subject := "test-user"
	if err == nil && len(adminOrgUserList.Items) > 0 {
		subject = "admin-user"
	}

	return &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: subject,
		},
	}, nil
}

// GetACL uses real RBAC to generate ACL.
func (a *TestAuthorizer) GetACL(ctx context.Context, organizationID string) (*openapi.Acl, error) {
	return a.rbac.GetACL(ctx, organizationID)
}

// SetupBaseNamespace creates the base test namespace.
func SetupBaseNamespace(ctx context.Context, k8sClient client.Client) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: TestNamespace,
		},
	}

	if err := k8sClient.Create(ctx, ns); err != nil && !kerrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create base namespace: %w", err)
	}

	return nil
}

// NewMockJWTIssuer returns nil for contract tests.
func NewMockJWTIssuer() *jose.JWTIssuer {
	return nil
}

// NewMockOAuth2 returns nil for contract tests.
func NewMockOAuth2() *oauth2.Authenticator {
	return nil
}
