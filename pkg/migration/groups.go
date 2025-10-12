/*
Copyright 2025 the Unikorn Authors.

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

package migration

import (
	"context"
	"fmt"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// MigrateGroupsToSubjects migrates all groups from using UserIDs (OrganizationUser resource names)
// to using Subjects (user email addresses). This should be run once on server startup before
// the new authorization code runs.
//
// The migration:
// 1. Lists all groups in all namespaces
// 2. For each group with UserIDs but no Subjects:
//   - Resolves each UserID to find the OrganizationUser resource
//   - Looks up the global User resource to get the subject (email)
//   - Populates the Subjects field with the resolved email addresses
//   - Clears the UserIDs field (deprecated)
//   - Updates the group
//
// 3. Skips groups that already have Subjects (already migrated or newly created)
// 4. Logs warnings for UserIDs that cannot be resolved (deleted users)
func MigrateGroupsToSubjects(ctx context.Context, c client.Client, namespace string) error {
	logger := log.FromContext(ctx).WithName("migration").WithValues("migration", "groups-to-subjects")

	logger.Info("starting group migration from UserIDs to Subjects")

	// List all groups across all namespaces
	groups := &unikornv1.GroupList{}
	if err := c.List(ctx, groups); err != nil {
		return fmt.Errorf("failed to list groups: %w", err)
	}

	logger.Info("found groups to process", "count", len(groups.Items))

	migratedCount := 0
	skippedCount := 0
	errorCount := 0

	for i := range groups.Items {
		group := &groups.Items[i]

		// Skip if already migrated (has Subjects populated)
		if len(group.Spec.Subjects) > 0 {
			logger.V(1).Info("skipping group - already has subjects",
				"namespace", group.Namespace,
				"name", group.Name,
				"subjects", len(group.Spec.Subjects))
			skippedCount++
			continue
		}

		// Skip if no UserIDs to migrate
		if len(group.Spec.UserIDs) == 0 {
			logger.V(1).Info("skipping group - no UserIDs to migrate",
				"namespace", group.Namespace,
				"name", group.Name)
			skippedCount++
			continue
		}

		logger.Info("migrating group",
			"namespace", group.Namespace,
			"name", group.Name,
			"userIDs", len(group.Spec.UserIDs))

		subjects := make([]string, 0, len(group.Spec.UserIDs))

		// Resolve each UserID to a subject
		for _, userID := range group.Spec.UserIDs {
			subject, err := resolveUserIDToSubject(ctx, c, namespace, group.Namespace, userID)
			if err != nil {
				logger.Error(err, "failed to resolve UserID - skipping",
					"namespace", group.Namespace,
					"group", group.Name,
					"userID", userID)
				errorCount++
				continue
			}

			subjects = append(subjects, subject)
			logger.V(1).Info("resolved user",
				"userID", userID,
				"subject", subject)
		}

		// Update the group with subjects
		updated := group.DeepCopy()
		updated.Spec.Subjects = subjects
		updated.Spec.UserIDs = nil // Clear deprecated field

		if err := c.Update(ctx, updated); err != nil {
			logger.Error(err, "failed to update group",
				"namespace", group.Namespace,
				"name", group.Name)
			errorCount++
			continue
		}

		logger.Info("migrated group successfully",
			"namespace", group.Namespace,
			"name", group.Name,
			"subjects", len(subjects))
		migratedCount++
	}

	logger.Info("group migration completed",
		"migrated", migratedCount,
		"skipped", skippedCount,
		"errors", errorCount)

	if errorCount > 0 {
		return fmt.Errorf("migration completed with %d errors", errorCount)
	}

	return nil
}

// resolveUserIDToSubject resolves an OrganizationUser resource name to the user's subject (email).
func resolveUserIDToSubject(ctx context.Context, c client.Client, globalNamespace, groupNamespace, userID string) (string, error) {
	// Get the OrganizationUser resource
	orgUser := &unikornv1.OrganizationUser{}
	orgUserKey := client.ObjectKey{
		Namespace: groupNamespace,
		Name:      userID,
	}
	if err := c.Get(ctx, orgUserKey, orgUser); err != nil {
		return "", fmt.Errorf("OrganizationUser not found: %w", err)
	}

	// Get the user label that references the global User resource
	globalUserID, ok := orgUser.Labels[constants.UserLabel]
	if !ok {
		return "", fmt.Errorf("OrganizationUser missing user label")
	}

	// Get the global User resource
	user := &unikornv1.User{}
	userKey := client.ObjectKey{
		Namespace: globalNamespace,
		Name:      globalUserID,
	}
	if err := c.Get(ctx, userKey, user); err != nil {
		return "", fmt.Errorf("User not found: %w", err)
	}

	return user.Spec.Subject, nil
}
