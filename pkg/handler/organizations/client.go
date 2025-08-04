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
	"slices"
	"strings"

	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Client struct {
	client    client.Client
	namespace string
	pdp       rbac.PolicyDecisionPoint
}

func New(client client.Client, namespace string, pdp rbac.PolicyDecisionPoint) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
		pdp:       pdp,
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

		return nil, errors.OAuth2ServerError("failed to get organization").WithError(err)
	}

	return result, nil
}

func (c *Client) list(ctx context.Context) (*unikornv1.OrganizationList, error) {
	result := &unikornv1.OrganizationList{}

	if err := c.client.List(ctx, result, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Client) List(ctx context.Context, email *string) (openapi.Organizations, error) {
	organizations, err := c.list(ctx)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to list organizations").WithError(err)
	}

	// Apply RNAC.
	allowed := rbac.AllowBulk(ctx, c.pdp, "identity:organizations", openapi.Read, organizations)

	result := &unikornv1.OrganizationList{
		Items: rbac.FilterAllowed(organizations.Items, allowed),
	}

	return convertList(result), nil
}

func (c *Client) Get(ctx context.Context, organizationID string) (*openapi.OrganizationRead, error) {
	result, err := c.get(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	if err := c.pdp.Allow(ctx, "identity:organizations", openapi.Read, result); err != nil {
		return nil, err
	}

	return convert(result), nil
}

func (c *Client) generate(ctx context.Context, in *openapi.OrganizationWrite) (*unikornv1.Organization, error) {
	out := &unikornv1.Organization{
		ObjectMeta: conversion.NewObjectMetadata(&in.Metadata, c.namespace).Get(),
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	out.Spec.Tags = conversion.GenerateTagList(in.Metadata.Tags)

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
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

	if err := c.pdp.Allow(ctx, "identity:organizations", openapi.Update, current); err != nil {
		return err
	}

	required, err := c.generate(ctx, request)
	if err != nil {
		return err
	}

	if err := conversion.UpdateObjectMetadata(required, current, common.IdentityMetadataMutator); err != nil {
		return errors.OAuth2ServerError("failed to merge metadata").WithError(err)
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return errors.OAuth2ServerError("failed to patch organization").WithError(err)
	}

	return nil
}

func (c *Client) Create(ctx context.Context, request *openapi.OrganizationWrite) (*openapi.OrganizationRead, error) {
	org, err := c.generate(ctx, request)
	if err != nil {
		return nil, err
	}

	if err := c.pdp.Allow(ctx, "identity:organizations", openapi.Create, org); err != nil {
		return nil, err
	}

	if err := c.client.Create(ctx, org); err != nil {
		return nil, errors.OAuth2ServerError("failed to create organization").WithError(err)
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

	if err := c.pdp.Allow(ctx, "identity:organizations", openapi.Delete, resource); err != nil {
		return err
	}

	if err := c.client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("failed to delete organization").WithError(err)
	}

	return nil
}
