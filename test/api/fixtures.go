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

//nolint:revive,staticcheck // dot imports are standard for Ginkgo/Gomega test code
package api

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

// GroupPayloadBuilder builds group payloads for testing using type-safe OpenAPI structs.
type GroupPayloadBuilder struct {
	group  identityopenapi.GroupWrite
	config *TestConfig
}

// NewGroupPayload creates a new group payload builder with defaults from config.
func NewGroupPayload() *GroupPayloadBuilder {
	config, err := LoadTestConfig()
	Expect(err).NotTo(HaveOccurred(), "Failed to load test configuration")

	timestamp := time.Now().Format("20060102-150405")
	uniqueName := fmt.Sprintf("test-group-%s", timestamp)

	return &GroupPayloadBuilder{
		config: config,
		group: identityopenapi.GroupWrite{
			Metadata: coreopenapi.ResourceWriteMetadata{
				Name: uniqueName,
			},
			Spec: identityopenapi.GroupSpec{
				RoleIDs:           []string{},
				ServiceAccountIDs: []string{},
			},
		},
	}
}

// WithName sets the group name.
func (b *GroupPayloadBuilder) WithName(name string) *GroupPayloadBuilder {
	b.group.Metadata.Name = name
	return b
}

// WithRoleIDs sets the role IDs for the group.
func (b *GroupPayloadBuilder) WithRoleIDs(roleIDs []string) *GroupPayloadBuilder {
	b.group.Spec.RoleIDs = roleIDs
	return b
}

// WithServiceAccountIDs sets the service account IDs for the group.
func (b *GroupPayloadBuilder) WithServiceAccountIDs(serviceAccountIDs []string) *GroupPayloadBuilder {
	b.group.Spec.ServiceAccountIDs = serviceAccountIDs
	return b
}

// BuildTyped returns the typed group struct directly.
func (b *GroupPayloadBuilder) BuildTyped() identityopenapi.GroupWrite {
	return b.group
}

// findOrphanedGroupID attempts to find a group by name when the ID wasn't captured during creation.
// Returns empty string if not found.
func findOrphanedGroupID(ctx context.Context, client *APIClient, config *TestConfig, groupName string) string {
	GinkgoWriter.Printf("No group ID available, attempting to find group by name: %s\n", groupName)

	groups, listErr := client.ListGroups(ctx, config.OrgID)
	if listErr != nil {
		GinkgoWriter.Printf("Warning: Could not list groups for cleanup: %v\n", listErr)
		return ""
	}

	for _, group := range groups {
		if group.Metadata.Name == groupName {
			GinkgoWriter.Printf("Found orphaned group by name: %s (ID: %s)\n", groupName, group.Metadata.Id)
			return group.Metadata.Id
		}
	}

	GinkgoWriter.Printf("Skipping cleanup: group not found by name\n")

	return ""
}

// CreateGroupWithCleanup creates a group and schedules automatic cleanup.
// Accepts a typed struct for type safety (or use BuildTyped() from the builder).
func CreateGroupWithCleanup(client *APIClient, ctx context.Context, config *TestConfig, payload identityopenapi.GroupWrite) (identityopenapi.GroupRead, string) {
	var groupID string

	groupName := payload.Metadata.Name

	// Schedule cleanup FIRST - ensures cleanup runs even if creation fails
	DeferCleanup(func() {
		if groupID == "" {
			groupID = findOrphanedGroupID(ctx, client, config, groupName)
			if groupID == "" {
				return
			}
		}

		GinkgoWriter.Printf("Cleaning up group: %s\n", groupID)

		deleteErr := client.DeleteGroup(ctx, config.OrgID, groupID)
		if deleteErr != nil {
			GinkgoWriter.Printf("Warning: Failed to delete group %s: %v\n", groupID, deleteErr)
		} else {
			GinkgoWriter.Printf("Successfully deleted group: %s\n", groupID)
		}
	})

	group, err := client.CreateGroup(ctx, config.OrgID, payload)
	if err != nil {
		Fail(fmt.Sprintf("Failed to create group: %v", err))
	}

	groupID = group.Metadata.Id

	GinkgoWriter.Printf("Created group with ID: %s\n", groupID)

	return *group, groupID
}
