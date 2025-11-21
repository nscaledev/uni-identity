/*
Copyright 2024-2025 the Unikorn Authors.

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

package organizations

import (
	"context"
	goerrors "errors"
	"slices"
	"strings"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	errorsv2 "github.com/unikorn-cloud/core/pkg/server/v2/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Client struct {
	client    client.Client
	namespace string
}

func New(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

// Meta describes the organization.
type Meta struct {
	// ID is the organization's Kubernetes name, so a higher level resource
	// can reference it.
	ID string

	// Namespace is the namespace that is provisioned by the organization.
	// Should be usable set when the organization is active.
	Namespace string
}

// GetMetadata retrieves the organization metadata.
// Clients should consult at least the Active status before doing anything
// with the organization.
func (c *Client) GetMetadata(ctx context.Context, organizationID string) (*Meta, error) {
	result, err := c.get(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	metadata := &Meta{
		ID:        organizationID,
		Namespace: result.Status.Namespace,
	}

	return metadata, nil
}

func convertOrganizationType(in *unikornv1.Organization) openapi.OrganizationType {
	if in.Spec.Domain != nil {
		return openapi.Domain
	}

	return openapi.Adhoc
}

func convert(in *unikornv1.Organization) *openapi.OrganizationRead {
	out := &openapi.OrganizationRead{
		Metadata: conversion.ResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.OrganizationSpec{
			OrganizationType: convertOrganizationType(in),
		},
	}

	if in.Spec.Domain != nil {
		out.Spec.Domain = in.Spec.Domain
		out.Spec.ProviderScope = ptr.To(openapi.ProviderScope(*in.Spec.ProviderScope))
		out.Spec.ProviderID = in.Spec.ProviderID
	}

	// TODO: We should cross reference with the provider type and
	// only emit what's allowed.
	if in.Spec.ProviderOptions != nil {
		if in.Spec.ProviderOptions.Google != nil {
			out.Spec.GoogleCustomerID = in.Spec.ProviderOptions.Google.CustomerID
		}
	}

	return out
}

func convertList(in *unikornv1.OrganizationList) openapi.Organizations {
	slices.SortStableFunc(in.Items, func(a, b unikornv1.Organization) int {
		return strings.Compare(a.Name, b.Name)
	})

	out := make(openapi.Organizations, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i])
	}

	return out
}

func (c *Client) get(ctx context.Context, organizationID string) (*unikornv1.Organization, error) {
	key := client.ObjectKey{
		Namespace: c.namespace,
		Name:      organizationID,
	}

	var organization unikornv1.Organization
	if err := c.client.Get(ctx, key, &organization); err != nil {
		if kerrors.IsNotFound(err) {
			err = errorsv2.NewResourceMissingError("organization").
				WithCause(err).
				Prefixed()

			return nil, err
		}

		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve organization: %w", err).
			Prefixed()

		return nil, err
	}

	return &organization, nil
}

func (c *Client) list(ctx context.Context) (*unikornv1.OrganizationList, error) {
	opts := []client.ListOption{
		&client.ListOptions{Namespace: c.namespace},
	}

	var list unikornv1.OrganizationList
	if err := c.client.List(ctx, &list, opts...); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve organizations: %w", err).
			Prefixed()

		return nil, err
	}

	return &list, nil
}

func (c *Client) getActiveUser(ctx context.Context, subject string, client *rbac.RBAC) (*unikornv1.User, error) {
	user, err := client.GetActiveUser(ctx, subject)
	if err != nil {
		if goerrors.Is(err, rbac.ErrUserNotFound) {
			err = errorsv2.NewResourceMissingError("user").
				WithCause(err).
				Prefixed()

			return nil, err
		}

		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve user: %w", err).
			Prefixed()

		return nil, err
	}

	return user, nil
}

func (c *Client) getUserByEmail(ctx context.Context, rbacClient *rbac.RBAC, info *authorization.Info, email string) (*unikornv1.User, error) {
	// If you aren't looking at yourself, then you need global read permissions, you cannot
	// go probing for other users or organizations, massive data breach!
	if info.Userinfo == nil || info.Userinfo.Email == nil || *info.Userinfo.Email != email {
		if err := rbac.AllowGlobalScope(ctx, "identity:users", openapi.Read); err != nil {
			return nil, err
		}
	}

	return c.getActiveUser(ctx, email, rbacClient)
}

func (c *Client) organizationIDs(ctx context.Context, rbacClient *rbac.RBAC, email *string) ([]string, error) {
	info, err := authorization.FromContext(ctx)
	if err != nil {
		err = errorsv2.NewInternalError().WithCause(err).Prefixed()
		return nil, err
	}

	if info.ServiceAccount {
		account, err := rbacClient.GetServiceAccount(ctx, info.Userinfo.Sub)
		if err != nil {
			if goerrors.Is(err, rbac.ErrServiceAccountNotFound) {
				err = errorsv2.NewResourceMissingError("service account").
					WithCause(err).
					Prefixed()

				return nil, err
			}

			err = errorsv2.NewInternalError().
				WithCausef("failed to retrieve service account: %w", err).
				Prefixed()

			return nil, err
		}

		return []string{account.Labels[constants.OrganizationLabel]}, nil
	}

	var user *unikornv1.User

	if email != nil {
		user, err = c.getUserByEmail(ctx, rbacClient, info, *email)
	} else {
		user, err = c.getActiveUser(ctx, info.Userinfo.Sub, rbacClient)
	}

	if err != nil {
		return nil, err
	}

	opts := []client.ListOption{
		&client.ListOptions{
			LabelSelector: labels.SelectorFromSet(labels.Set{
				constants.UserLabel: user.Name,
			}),
		},
	}

	var list unikornv1.OrganizationUserList
	if err := c.client.List(ctx, &list, opts...); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve organization users: %w", err).
			Prefixed()

		return nil, err
	}

	// REVIEW_ME: Is it possible to have duplicate IDs here, and do we need to de-duplicate them?
	organizationIDs := make([]string, 0, len(list.Items))
	for _, organizationUser := range list.Items {
		organizationIDs = append(organizationIDs, organizationUser.Labels[constants.OrganizationLabel])
	}

	return organizationIDs, nil
}

func (c *Client) List(ctx context.Context, rbacClient *rbac.RBAC, email *string) (openapi.Organizations, error) {
	// This is the only special case in the system.  When requesting organizations we
	// will have an unscoped ACL, so can check for global access to all organizations.
	// If we don't have that then we need to use RBAC to get a list of organizations we are
	// members of and return only them.
	if err := rbac.AllowGlobalScope(ctx, "identity:organizations", openapi.Read); err == nil && email == nil {
		list, err := c.list(ctx)
		if err != nil {
			return nil, err
		}

		return convertList(list), nil
	}

	list, err := c.list(ctx)
	if err != nil {
		return nil, err
	}

	organizationIDs, err := c.organizationIDs(ctx, rbacClient, email)
	if err != nil {
		return nil, err
	}

	memo := make(map[string]unikornv1.Organization, len(list.Items))
	for _, organization := range list.Items {
		memo[organization.Name] = organization
	}

	list.Items = list.Items[:0]

	for _, organizationID := range organizationIDs {
		organization, ok := memo[organizationID]
		if !ok {
			err = errorsv2.NewInternalError().
				WithSimpleCausef("organization %s found in RBAC but missing in store", organizationID).
				Prefixed()

			return nil, err
		}

		list.Items = append(list.Items, organization)
	}

	return convertList(list), nil
}

func (c *Client) Get(ctx context.Context, organizationID string) (*openapi.OrganizationRead, error) {
	result, err := c.get(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	return convert(result), nil
}

func (c *Client) generate(ctx context.Context, in *openapi.OrganizationWrite) (*unikornv1.Organization, error) {
	out := &unikornv1.Organization{
		ObjectMeta: conversion.NewObjectMetadata(&in.Metadata, c.namespace).Get(),
		Spec: unikornv1.OrganizationSpec{
			Tags: conversion.GenerateTagList(in.Metadata.Tags),
		},
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, err
	}

	if in.Spec.OrganizationType == openapi.Domain {
		// TODO: Validate the providerID exists.
		out.Spec.Domain = in.Spec.Domain
		out.Spec.ProviderScope = ptr.To(unikornv1.ProviderScope(*in.Spec.ProviderScope))
		out.Spec.ProviderID = in.Spec.ProviderID

		// TODO: we should cross reference with the provider type and do only
		// what must be done.
		if in.Spec.GoogleCustomerID != nil {
			out.Spec.ProviderOptions = &unikornv1.OrganizationProviderOptions{
				Google: &unikornv1.OrganizationProviderGoogleSpec{
					CustomerID: in.Spec.GoogleCustomerID,
				},
			}
		}
	}

	return out, nil
}

func (c *Client) Update(ctx context.Context, organizationID string, request *openapi.OrganizationWrite) error {
	current, err := c.get(ctx, organizationID)
	if err != nil {
		return err
	}

	required, err := c.generate(ctx, request)
	if err != nil {
		return err
	}

	if err := conversion.UpdateObjectMetadata(required, current, common.IdentityMetadataMutator); err != nil {
		return err
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return errorsv2.NewInternalError().
			WithCausef("failed to patch organization: %w", err).
			Prefixed()
	}

	return nil
}

func (c *Client) Create(ctx context.Context, request *openapi.OrganizationWrite) (*openapi.OrganizationRead, error) {
	org, err := c.generate(ctx, request)
	if err != nil {
		return nil, err
	}

	if err := c.client.Create(ctx, org); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to create organization: %w", err).
			Prefixed()

		return nil, err
	}

	return convert(org), nil
}

func (c *Client) Delete(ctx context.Context, organizationID string) error {
	resource := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      organizationID,
			Namespace: c.namespace,
		},
	}

	if err := c.client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errorsv2.NewResourceMissingError("organization").
				WithCause(err).
				Prefixed()
		}

		return errorsv2.NewInternalError().
			WithCausef("failed to delete organization: %w", err).
			Prefixed()
	}

	return nil
}
