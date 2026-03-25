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

package migration

import (
	"context"
	"fmt"
	"slices"

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	identityv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Result struct {
	GroupNamespace string  `json:"namespace"`
	GroupName      string  `json:"name"`
	Success        bool    `json:"success"`
	ErrorMessage   *string `json:"error_message"`
}

type ResourceMemo struct {
	OrganizationUsers map[string]*identityv1.OrganizationUser
	Users             map[string]*identityv1.User
}

func resourceKey(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}

func subjectKey(issuer, email string) string {
	return fmt.Sprintf("%s/%s", issuer, email)
}

type GroupMigrationManager struct {
	kubeClient        client.Client
	identityNamespace string
	// selector restricts migration to a specific subset of groups, identified by
	// "namespace/name" keys. When empty, all groups are eligible for migration.
	selector map[string]struct{}
}

func NewGroupMigrationManager(kubeClient client.Client, identityNamespace string, selector map[string]struct{}) *GroupMigrationManager {
	return &GroupMigrationManager{
		kubeClient:        kubeClient,
		identityNamespace: identityNamespace,
		selector:          selector,
	}
}

func (m *GroupMigrationManager) Run(ctx context.Context) ([]Result, error) {
	var groupList identityv1.GroupList
	if err := m.kubeClient.List(ctx, &groupList); err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}

	var organizationUserList identityv1.OrganizationUserList
	if err := m.kubeClient.List(ctx, &organizationUserList); err != nil {
		return nil, fmt.Errorf("failed to list organization users: %w", err)
	}

	var userList identityv1.UserList
	if err := m.kubeClient.List(ctx, &userList); err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	resourceMemo := ResourceMemo{
		OrganizationUsers: make(map[string]*identityv1.OrganizationUser, len(organizationUserList.Items)),
		Users:             make(map[string]*identityv1.User, len(userList.Items)),
	}

	for i := 0; i < len(organizationUserList.Items); i++ {
		organizationUser := &organizationUserList.Items[i]
		key := resourceKey(organizationUser.Namespace, organizationUser.Name)
		resourceMemo.OrganizationUsers[key] = organizationUser
	}

	for i := 0; i < len(userList.Items); i++ {
		user := &userList.Items[i]
		key := resourceKey(user.Namespace, user.Name)
		resourceMemo.Users[key] = user
	}

	groups := groupList.Items
	if len(m.selector) > 0 {
		groups = slices.DeleteFunc(groups, func(group identityv1.Group) bool {
			key := resourceKey(group.Namespace, group.Name)
			_, ok := m.selector[key]
			return !ok
		})
	}

	var (
		semaphore = make(chan struct{}, 10)
		completed = make(chan Result)
		results   = make([]Result, 0, len(groups))
	)

	go m.dispatch(ctx, groups, resourceMemo, semaphore, completed)

	for i := 0; i < len(groups); i++ {
		results = append(results, <-completed)
		<-semaphore
	}

	return results, nil
}

func (m *GroupMigrationManager) dispatch(ctx context.Context, groups []identityv1.Group, resourceMemo ResourceMemo, semaphore chan<- struct{}, completed chan<- Result) {
	for i := 0; i < len(groups); i++ {
		semaphore <- struct{}{}

		go func(group *identityv1.Group) {
			result := Result{
				GroupNamespace: group.Namespace,
				GroupName:      group.Name,
				Success:        true,
				ErrorMessage:   nil,
			}

			if err := m.migrate(ctx, group, resourceMemo); err != nil {
				errorMessage := err.Error()

				result.Success = false
				result.ErrorMessage = &errorMessage
			}

			completed <- result
		}(&groups[i])
	}
}

func (m *GroupMigrationManager) migrate(ctx context.Context, group *identityv1.Group, resourceMemo ResourceMemo) error {
	subjectMemo := make(map[string]struct{}, len(group.Spec.Subjects))
	for _, subject := range group.Spec.Subjects {
		key := subjectKey(subject.Issuer, subject.Email)
		subjectMemo[key] = struct{}{}
	}

	updated := group.DeepCopy()

	for _, organizationUserID := range group.Spec.UserIDs {
		organizationUserKey := resourceKey(group.Namespace, organizationUserID)

		organizationUser, ok := resourceMemo.OrganizationUsers[organizationUserKey]
		if !ok {
			return fmt.Errorf("organization user %q not found", organizationUserKey)
		}

		userID, ok := organizationUser.Labels[coreconstants.UserLabel]
		if !ok {
			return fmt.Errorf("organization user %q has no user label", organizationUserKey)
		}

		userKey := resourceKey(m.identityNamespace, userID)

		user, ok := resourceMemo.Users[userKey]
		if !ok {
			return fmt.Errorf("user %q not found for organization user %q", userKey, organizationUserKey)
		}

		subjectKey := subjectKey("", user.Spec.Subject)
		if _, exists := subjectMemo[subjectKey]; exists {
			continue
		}

		subjectMemo[subjectKey] = struct{}{}

		updated.Spec.Subjects = append(updated.Spec.Subjects, identityv1.GroupSubject{
			ID:     user.Spec.Subject,
			Issuer: "",
			Email:  user.Spec.Subject,
		})
	}

	if len(group.Spec.Subjects) == len(updated.Spec.Subjects) {
		return nil
	}

	return m.kubeClient.Patch(ctx, updated, client.MergeFromWithOptions(group, client.MergeFromWithOptimisticLock{}))
}
