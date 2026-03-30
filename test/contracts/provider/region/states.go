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
	"log"
	"strings"
	"time"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

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

func (sm *StateManager) HandleProjectExists(ctx context.Context, setup bool, params map[string]any) error {
	actualParams := unwrapPactParams(params)
	orgID := getStringParam(actualParams, "organizationID", "c9d0e1f2-a3b4-4c5d-6e7f-8a9b0c1d2e3f")
	projectID := getStringParam(actualParams, "projectID", "d0e1f2a3-b4c5-4d6e-7f8a-9b0c1d2e3f4a")

	if setup {
		// Only create org and project - MockACLMiddleware provides all auth context
		if err := sm.setupOrganization(ctx, orgID); err != nil {
			return err
		}

		return sm.setupProject(ctx, orgID, projectID)
	}

	return sm.cleanupOrganization(ctx, orgID)
}

func (sm *StateManager) HandleAllocationExists(ctx context.Context, setup bool, params map[string]any) error {
	actualParams := unwrapPactParams(params)
	allocationID := getStringParam(actualParams, "allocationID", "a3b4c5d6-e7f8-4a9b-0c1d-2e3f4a5b6c7d")
	orgID := getStringParam(actualParams, "organizationID", "e1f2a3b4-c5d6-4e7f-8a9b-0c1d2e3f4a5b")
	projectID := getStringParam(actualParams, "projectID", "f2a3b4c5-d6e7-4f8a-9b0c-1d2e3f4a5b6c")

	if setup {
		// Only create org, project, and allocation - MockACLMiddleware provides all auth context
		if err := sm.setupOrganization(ctx, orgID); err != nil {
			return err
		}

		if err := sm.setupProject(ctx, orgID, projectID); err != nil {
			return err
		}

		return sm.setupAllocation(ctx, orgID, projectID, allocationID)
	}

	return sm.cleanupOrganization(ctx, orgID)
}

// Helper methods for resource creation and cleanup

func (sm *StateManager) setupOrganization(ctx context.Context, orgID string) error {
	// Clean up first to ensure clean slate
	if err := sm.cleanupOrganization(ctx, orgID); err != nil {
		log.Printf("warning: cleanup before setup failed for org %s: %v", orgID, err)
	}

	// Create organization namespace with unique name to avoid conflicts
	orgNamespace := sm.getUniqueNamespace(fmt.Sprintf("org-%s", orgID))
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: orgNamespace,
		},
	}

	if err := sm.client.Create(ctx, ns); err != nil && !kerrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create namespace %s: %w", orgNamespace, err)
	}

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

// getOrganizationNamespace gets the organization namespace from cache or Organization CR.
func (sm *StateManager) getOrganizationNamespace(ctx context.Context, orgID string) string {
	// Try to get the cached org namespace
	orgNamespace, ok := sm.namespaceCache[fmt.Sprintf("org-%s", orgID)]
	if ok {
		return orgNamespace
	}

	// Try to get it from the Organization CR status
	org := &unikornv1.Organization{}
	err := sm.client.Get(ctx, client.ObjectKey{Name: orgID, Namespace: sm.namespace}, org)

	if err == nil && org.Status.Namespace != "" {
		return org.Status.Namespace
	}

	// Fallback to default pattern (might not exist, but that's okay)
	return fmt.Sprintf("org-%s", orgID)
}

// cleanupAllocationsInProjectNamespaces deletes all allocations in project namespaces for the given organization.
func (sm *StateManager) cleanupAllocationsInProjectNamespaces(ctx context.Context, orgID string) {
	projectNsList := &corev1.NamespaceList{}
	if err := sm.client.List(ctx, projectNsList, client.MatchingLabels{
		"unikorn-cloud.org/kind":         "project",
		"unikorn-cloud.org/organization": orgID,
	}); err != nil {
		log.Printf("warning: failed to list project namespaces during cleanup for org %s: %v", orgID, err)
		return
	}

	for i := range projectNsList.Items {
		projectNs := &projectNsList.Items[i]
		allocationList := &unikornv1.AllocationList{}

		if err := sm.client.List(ctx, allocationList, client.InNamespace(projectNs.Name)); err != nil {
			log.Printf("warning: failed to list allocations in namespace %s during cleanup: %v", projectNs.Name, err)
			continue
		}

		for j := range allocationList.Items {
			if err := sm.client.Delete(ctx, &allocationList.Items[j]); err != nil {
				log.Printf("warning: failed to delete allocation %s during cleanup: %v", allocationList.Items[j].Name, err)
			}
		}
	}
}

// cleanupProjectsInNamespace deletes all projects in the given namespace and returns the project list for cache cleanup.
func (sm *StateManager) cleanupProjectsInNamespace(ctx context.Context, orgNamespace string) *unikornv1.ProjectList {
	projectList := &unikornv1.ProjectList{}
	if err := sm.client.List(ctx, projectList, client.InNamespace(orgNamespace)); err != nil {
		log.Printf("warning: failed to list projects in namespace %s during cleanup: %v", orgNamespace, err)
		return projectList
	}

	for i := range projectList.Items {
		if err := sm.client.Delete(ctx, &projectList.Items[i]); err != nil {
			log.Printf("warning: failed to delete project %s during cleanup: %v", projectList.Items[i].Name, err)
		}
	}

	return projectList
}

// deleteOrganizationCR deletes the organization custom resource.
func (sm *StateManager) deleteOrganizationCR(ctx context.Context, orgID string) {
	org := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      orgID,
			Namespace: sm.namespace,
		},
	}

	if err := sm.client.Delete(ctx, org); err != nil {
		log.Printf("warning: failed to delete organization %s during cleanup: %v", orgID, err)
	}
}

func (sm *StateManager) cleanupOrganization(ctx context.Context, orgID string) error {
	orgNamespace := sm.getOrganizationNamespace(ctx, orgID)

	// Don't delete namespaces - they go into Terminating state and cause the handler to find
	// multiple namespaces with the same labels. Instead, just delete the CRs and reuse
	// the namespaces in subsequent tests.

	// Delete allocation CRs in project namespaces
	sm.cleanupAllocationsInProjectNamespaces(ctx, orgID)

	// Delete all Project CRs in this organization
	projectList := sm.cleanupProjectsInNamespace(ctx, orgNamespace)

	// Delete organization CR
	sm.deleteOrganizationCR(ctx, orgID)

	// Clear cache entries for this organization and its projects
	delete(sm.namespaceCache, fmt.Sprintf("org-%s", orgID))

	for _, project := range projectList.Items {
		delete(sm.namespaceCache, fmt.Sprintf("project-%s", project.Name))
	}

	return nil
}

// findOrCreateProjectNamespace finds an existing active project namespace or creates a new one.
func (sm *StateManager) findOrCreateProjectNamespace(ctx context.Context, orgID, projectID string) (string, error) {
	// Check if a project namespace with these labels already exists and is NOT terminating
	existingProjectNs := &corev1.NamespaceList{}
	if err := sm.client.List(ctx, existingProjectNs, client.MatchingLabels{
		"unikorn-cloud.org/kind":         "project",
		"unikorn-cloud.org/organization": orgID,
		"unikorn-cloud.org/project":      projectID,
	}); err != nil {
		return "", fmt.Errorf("failed to list existing project namespaces: %w", err)
	}

	// Look for an active (non-terminating) namespace to reuse
	for _, ns := range existingProjectNs.Items {
		if ns.DeletionTimestamp == nil {
			return ns.Name, nil
		}
	}

	// No active namespace found, create a new unique one
	projectNamespace := sm.getUniqueNamespace(fmt.Sprintf("project-%s", projectID))
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

	if err := sm.client.Create(ctx, ns); err != nil && !kerrors.IsAlreadyExists(err) {
		return "", fmt.Errorf("failed to create namespace %s: %w", projectNamespace, err)
	}

	return projectNamespace, nil
}

// createOrGetProjectCR creates a new project CR or retrieves an existing one.
func (sm *StateManager) createOrGetProjectCR(ctx context.Context, orgID, projectID, orgNamespace string) (*unikornv1.Project, error) {
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
	if err != nil && !kerrors.IsAlreadyExists(err) {
		return nil, fmt.Errorf("failed to create project %s: %w", projectID, err)
	}

	// If it already existed, get it first
	if err != nil {
		if err := sm.client.Get(ctx, client.ObjectKey{Name: projectID, Namespace: orgNamespace}, project); err != nil {
			return nil, fmt.Errorf("failed to get existing project: %w", err)
		}
	}

	return project, nil
}

func (sm *StateManager) setupProject(ctx context.Context, orgID, projectID string) error {
	// Get the cached unique org namespace
	orgNamespace, ok := sm.namespaceCache[fmt.Sprintf("org-%s", orgID)]
	if !ok {
		return fmt.Errorf("%w in cache for org %s", ErrOrganizationNamespaceNotFound, orgID)
	}

	// Find or create project namespace
	projectNamespace, err := sm.findOrCreateProjectNamespace(ctx, orgID, projectID)
	if err != nil {
		return err
	}

	// Cache the project namespace
	sm.namespaceCache[fmt.Sprintf("project-%s", projectID)] = projectNamespace

	// Create or get Project resource in organization namespace
	project, err := sm.createOrGetProjectCR(ctx, orgID, projectID, orgNamespace)
	if err != nil {
		return err
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
	if err != nil && !kerrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create allocation %s: %w", allocationID, err)
	}

	// Verify allocation was created by reading it back
	verifyAllocation := &unikornv1.Allocation{}
	if err := sm.client.Get(ctx, client.ObjectKey{
		Name:      allocationID,
		Namespace: projectNamespace,
	}, verifyAllocation); err != nil {
		return fmt.Errorf("failed to verify allocation %s: %w", allocationID, err)
	}

	return nil
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
