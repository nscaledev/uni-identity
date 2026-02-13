/*
Copyright 2024-2025 the Unikorn Authors.
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

package organizations

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
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

// get returns the implicit organization identified by the JWT claims.
func (c *Client) get(ctx context.Context, organizationID string) (*unikornv1.Organization, error) {
	result := &unikornv1.Organization{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: organizationID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, fmt.Errorf("%w: failed to get organization", err)
	}

	return result, nil
}

func (c *Client) list(ctx context.Context) (map[string]*unikornv1.Organization, error) {
	result := &unikornv1.OrganizationList{}

	if err := c.client.List(ctx, result, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return nil, err
	}

	out := map[string]*unikornv1.Organization{}

	for i := range result.Items {
		out[result.Items[i].Name] = &result.Items[i]
	}

	return out, nil
}

func (c *Client) getUserbyEmail(ctx context.Context, rbacClient *rbac.RBAC, info *authorization.Info, email string) (*unikornv1.User, error) {
	// If you aren't looking at yourself, then you need global read permissions, you cannot
	// go probing for other users or organizations, massive data breach!
	if info.Userinfo == nil || info.Userinfo.Email == nil || *info.Userinfo.Email != email {
		if err := rbac.AllowGlobalScope(ctx, "identity:users", openapi.Read); err != nil {
			return nil, errors.HTTPForbidden("user not permitted to read users globally").WithError(err)
		}
	}

	user, err := rbacClient.GetActiveUser(ctx, email)
	if err != nil {
		return nil, errors.HTTPNotFound().WithError(err)
	}

	return user, nil
}

func (c *Client) organizationIDs(ctx context.Context, rbacClient *rbac.RBAC, email *string) ([]string, error) {
	info, err := authorization.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: userinfo is not set", err)
	}

	if info.ServiceAccount {
		account, err := rbacClient.GetServiceAccount(ctx, info.Userinfo.Sub)
		if err != nil {
			return nil, errors.HTTPForbidden("service account not found").WithError(err)
		}

		return []string{account.Labels[constants.OrganizationLabel]}, nil
	}

	var user *unikornv1.User

	if email != nil {
		user, err = c.getUserbyEmail(ctx, rbacClient, info, *email)
		if err != nil {
			return nil, err
		}
	} else {
		user, err = rbacClient.GetActiveUser(ctx, info.Userinfo.Sub)
		if err != nil {
			return nil, errors.HTTPNotFound().WithError(err)
		}
	}

	selector := labels.SelectorFromSet(map[string]string{
		constants.UserLabel: user.Name,
	})

	organizationUsers := &unikornv1.OrganizationUserList{}

	if err := c.client.List(ctx, organizationUsers, &client.ListOptions{LabelSelector: selector}); err != nil {
		return nil, err
	}

	result := make([]string, len(organizationUsers.Items))

	for i := range organizationUsers.Items {
		result[i] = organizationUsers.Items[i].Labels[constants.OrganizationLabel]
	}

	return result, nil
}

func (c *Client) List(ctx context.Context, rbacClient *rbac.RBAC, email *string) (openapi.Organizations, error) {
	// This is the only special case in the system.  When requesting organizations we
	// will have an unscoped ACL, so can check for global access to all organizations.
	// If we don't have that then we need to use RBAC to get a list of organizations we are
	// members of and return only them.
	if err := rbac.AllowGlobalScope(ctx, "identity:organizations", openapi.Read); err == nil && email == nil {
		var result unikornv1.OrganizationList

		if err := c.client.List(ctx, &result, &client.ListOptions{Namespace: c.namespace}); err != nil {
			return nil, err
		}

		return convertList(&result), nil
	}

	organizations, err := c.list(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to list organizations", err)
	}

	organizationIDs, err := c.organizationIDs(ctx, rbacClient, email)
	if err != nil {
		return nil, err
	}

	result := unikornv1.OrganizationList{
		Items: make([]unikornv1.Organization, len(organizationIDs)),
	}

	for i := range organizationIDs {
		organization, ok := organizations[organizationIDs[i]]
		if !ok {
			return nil, fmt.Errorf("%w: failed to find organization for user", coreerrors.ErrConsistency)
		}

		result.Items[i] = *organization
	}

	return convertList(&result), nil
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
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, fmt.Errorf("%w: failed to set identity metadata", err)
	}

	out.Spec.Tags = conversion.GenerateTagList(in.Metadata.Tags)

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, fmt.Errorf("%w: failed to set identity metadata", err)
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
		return fmt.Errorf("%w: failed to merge metadata", err)
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := c.client.Patch(ctx, updated, client.MergeFromWithOptions(current, &client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("%w: failed to patch organization", err)
	}

	return nil
}

func (c *Client) Create(ctx context.Context, request *openapi.OrganizationWrite) (*openapi.OrganizationRead, error) {
	org, err := c.generate(ctx, request)
	if err != nil {
		return nil, err
	}

	if err := c.client.Create(ctx, org); err != nil {
		return nil, fmt.Errorf("%w: failed to create organization", err)
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
			return errors.HTTPNotFound().WithError(err)
		}

		return fmt.Errorf("%w: failed to delete organization", err)
	}

	return nil
}
