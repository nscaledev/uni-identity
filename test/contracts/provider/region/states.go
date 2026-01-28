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
	"fmt"
)

type StateManager struct {
	organizationStates map[string]OrganizationState
}

type OrganizationState struct {
	ID              string
	HasGlobal       bool
	HasOrganization bool
	HasProject      bool
	ProjectID       string
}

func NewStateManager() *StateManager {
	return &StateManager{
		organizationStates: make(map[string]OrganizationState),
	}
}

func getStringParam(params map[string]interface{}, key string, defaultValue string) string {
	if val, ok := params[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}

	return defaultValue
}

// unwrapPactParams extracts actual parameters from Pact's "params" wrapper.
func unwrapPactParams(params map[string]interface{}) map[string]interface{} {
	if wrappedParams, ok := params["params"].(map[string]interface{}); ok {
		return wrappedParams
	}

	return params
}

func (sm *StateManager) HandleOrganizationWithGlobalPermission(ctx context.Context, setup bool, params map[string]interface{}) error {
	actualParams := unwrapPactParams(params)
	orgID := getStringParam(actualParams, "organizationID", "test-org-123")

	fmt.Printf(">>> State handler: HandleOrganizationWithGlobalPermission(setup=%v, orgID=%s)\n", setup, orgID)

	if setup {
		sm.organizationStates[orgID] = OrganizationState{
			ID:        orgID,
			HasGlobal: true,
		}

		fmt.Printf("Set up organization %s with global permissions\n", orgID)
	} else {
		delete(sm.organizationStates, orgID)

		fmt.Printf("Cleaned up organization %s\n", orgID)
	}

	return nil
}

func (sm *StateManager) HandleOrganizationWithoutGlobalPermission(ctx context.Context, setup bool, params map[string]interface{}) error {
	actualParams := unwrapPactParams(params)
	orgID := getStringParam(actualParams, "organizationID", "test-org-456")

	fmt.Printf(">>> State handler: HandleOrganizationWithoutGlobalPermission(setup=%v, orgID=%s)\n", setup, orgID)

	if setup {
		sm.organizationStates[orgID] = OrganizationState{
			ID:              orgID,
			HasGlobal:       false,
			HasOrganization: true,
		}

		fmt.Printf("Set up organization %s with organization-level permissions\n", orgID)
	} else {
		delete(sm.organizationStates, orgID)

		fmt.Printf("Cleaned up organization %s\n", orgID)
	}

	return nil
}

func (sm *StateManager) HandleOrganizationScopePermission(ctx context.Context, setup bool, params map[string]interface{}) error {
	actualParams := unwrapPactParams(params)
	orgID := getStringParam(actualParams, "organizationID", "test-org-789")

	fmt.Printf(">>> State handler: HandleOrganizationScopePermission(setup=%v, orgID=%s)\n", setup, orgID)

	if setup {
		sm.organizationStates[orgID] = OrganizationState{
			ID:              orgID,
			HasGlobal:       false,
			HasOrganization: true,
		}

		fmt.Printf("Set up organization %s with organization scope permissions\n", orgID)
	} else {
		delete(sm.organizationStates, orgID)

		fmt.Printf("Cleaned up organization %s\n", orgID)
	}

	return nil
}

func (sm *StateManager) HandleProjectScopePermission(ctx context.Context, setup bool, params map[string]interface{}) error {
	actualParams := unwrapPactParams(params)
	orgID := getStringParam(actualParams, "organizationID", "test-org-101")
	projectID := getStringParam(actualParams, "projectID", "test-project-202")

	fmt.Printf(">>> State handler: HandleProjectScopePermission(setup=%v, orgID=%s, projectID=%s)\n", setup, orgID, projectID)

	if setup {
		sm.organizationStates[orgID] = OrganizationState{
			ID:         orgID,
			HasGlobal:  false,
			HasProject: true,
			ProjectID:  projectID,
		}

		fmt.Printf("Set up project %s in organization %s with project scope permissions\n", projectID, orgID)
	} else {
		delete(sm.organizationStates, orgID)

		fmt.Printf("Cleaned up organization %s and project %s\n", orgID, projectID)
	}

	return nil
}

func (sm *StateManager) HandleNonExistentOrganization(ctx context.Context, setup bool, params map[string]interface{}) error {
	actualParams := unwrapPactParams(params)
	orgID := getStringParam(actualParams, "organizationID", "non-existent-org")

	fmt.Printf(">>> State handler: HandleNonExistentOrganization(setup=%v, orgID=%s)\n", setup, orgID)

	if setup {
		delete(sm.organizationStates, orgID)

		fmt.Printf("Ensured organization %s does not exist\n", orgID)
	} else {
		fmt.Printf("Cleanup for non-existent organization %s\n", orgID)
	}

	return nil
}
