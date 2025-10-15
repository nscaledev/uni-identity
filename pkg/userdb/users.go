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

package userdb

import (
	"context"
	"fmt"
	"slices"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// ErrResourceReference is raised when a resource cannot be looked up.
	ErrResourceReference = fmt.Errorf("resource reference error")
)

type UserDatabase struct {
	client    client.Client
	namespace string
}

func NewUserDatabase(client client.Client, namespace string) *UserDatabase {
	return &UserDatabase{
		client:    client,
		namespace: namespace,
	}
}

func (d *UserDatabase) GetUser(ctx context.Context, subject string) (*unikornv1.User, error) {
	result := &unikornv1.UserList{}

	if err := d.client.List(ctx, result, &client.ListOptions{}); err != nil {
		return nil, err
	}

	index := slices.IndexFunc(result.Items, func(user unikornv1.User) bool {
		return user.Spec.Subject == subject
	})

	if index < 0 {
		return nil, fmt.Errorf("%w: user does not exist", ErrResourceReference)
	}

	return &result.Items[index], nil
}

// GetActiveUser returns a user that match the subject and is active.
func (d *UserDatabase) GetActiveUser(ctx context.Context, subject string) (*unikornv1.User, error) {
	user, err := d.GetUser(ctx, subject)
	if err != nil {
		return nil, err
	}

	if user.Spec.State != unikornv1.UserStateActive {
		return nil, fmt.Errorf("%w: user is not active", ErrResourceReference)
	}

	return user, nil
}

// GetActiveOrganizationUser gets an organization user that references the actual user.
func (d *UserDatabase) GetActiveOrganizationUser(ctx context.Context, organizationID string, user *unikornv1.User) (*unikornv1.OrganizationUser, error) {
	selector := labels.SelectorFromSet(map[string]string{
		constants.OrganizationLabel: organizationID,
		constants.UserLabel:         user.Name,
	})

	result := &unikornv1.OrganizationUserList{}

	if err := d.client.List(ctx, result, &client.ListOptions{LabelSelector: selector}); err != nil {
		return nil, err
	}

	if len(result.Items) != 1 {
		return nil, fmt.Errorf("%w: user does not exist in organization or exists multiple times", ErrResourceReference)
	}

	organizationUser := &result.Items[0]

	if organizationUser.Spec.State != unikornv1.UserStateActive {
		return nil, fmt.Errorf("%w: user is not active", ErrResourceReference)
	}

	return organizationUser, nil
}

// GetServiceAccount looks up a service account.
func (d *UserDatabase) GetServiceAccount(ctx context.Context, id string) (*unikornv1.ServiceAccount, error) {
	result := &unikornv1.ServiceAccountList{}

	if err := d.client.List(ctx, result, &client.ListOptions{}); err != nil {
		return nil, err
	}

	predicate := func(s unikornv1.ServiceAccount) bool {
		return s.Name != id
	}

	result.Items = slices.DeleteFunc(result.Items, predicate)

	if len(result.Items) != 1 {
		return nil, fmt.Errorf("%w: expected 1 instance of service account ID %s", ErrResourceReference, id)
	}

	return &result.Items[0], nil
}

// getOrgIDs returns the organization IDs for a user.
func (d *UserDatabase) GetOrganizationIDs(ctx context.Context, subject string) ([]string, error) {
	user, err := d.GetActiveUser(ctx, subject)
	if err != nil {
		return nil, err
	}

	selector := labels.SelectorFromSet(map[string]string{
		constants.UserLabel: user.Name,
	})

	organizationUsers := &unikornv1.OrganizationUserList{}
	if err := d.client.List(ctx, organizationUsers, &client.ListOptions{LabelSelector: selector}); err != nil {
		return nil, err
	}

	result := make([]string, len(organizationUsers.Items))
	for i := range organizationUsers.Items {
		result[i] = organizationUsers.Items[i].Labels[constants.OrganizationLabel]
	}

	return result, nil
}
