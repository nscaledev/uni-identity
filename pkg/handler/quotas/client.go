/*
Copyright 2025 the Unikorn Authors.
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

package quotas

import (
	"context"
	goerrors "errors"
	"fmt"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrConsistency = goerrors.New("consistency error")
)

// Client is responsible for user management.
type Client struct {
	// client is the Kubernetes client.
	client client.Client
	// namespace is the namespace the identity service is running in.
	namespace string
}

// New creates a new user client.
func New(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

func generateQuota(in *openapi.QuotaWrite) *unikornv1.ResourceQuota {
	out := &unikornv1.ResourceQuota{
		Kind:     in.Kind,
		Quantity: resource.NewQuantity(int64(in.Quantity), resource.DecimalSI),
	}

	return out
}

func generateQuotaList(in openapi.QuotaWriteList) []unikornv1.ResourceQuota {
	out := make([]unikornv1.ResourceQuota, len(in))

	for i := range in {
		out[i] = *generateQuota(&in[i])
	}

	return out
}

func generate(ctx context.Context, organization *organizations.Meta, in *openapi.QuotasWrite) (*unikornv1.Quota, error) {
	metadata := &coreopenapi.ResourceWriteMetadata{
		Name: constants.UndefinedName,
	}

	out := &unikornv1.Quota{
		ObjectMeta: conversion.NewObjectMetadata(metadata, organization.Namespace).Get(),
		Spec: unikornv1.QuotaSpec{
			Quotas: generateQuotaList(in.Quotas),
		},
	}

	if err := common.SetIdentityMetadataOrganizationScope(ctx, &out.ObjectMeta, organization.ID); err != nil {
		return nil, fmt.Errorf("%w: failed to set identity metadata", err)
	}

	return out, nil
}

// render lists the organization's allocations and renders quotas with them.
func (c *Client) render(ctx context.Context, organizationID ids.OrganizationID, quotas []unikornv1.ResourceQuota, metadata []unikornv1.QuotaMetadata) (*openapi.QuotasRead, error) {
	allocations, err := common.New(c.client).GetAllocations(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	items := make([]*unikornv1.Allocation, len(allocations.Items))

	for i := range allocations.Items {
		items[i] = &allocations.Items[i]
	}

	list, err := Convert(quotas, metadata, items)
	if err != nil {
		return nil, err
	}

	return &openapi.QuotasRead{Quotas: list}, nil
}

func (c *Client) Get(ctx context.Context, organizationID ids.OrganizationID) (*openapi.QuotasRead, error) {
	commonClient := common.New(c.client)

	metadata, err := commonClient.QuotaMetadata(ctx, c.namespace)
	if err != nil {
		return nil, err
	}

	result, _, err := commonClient.GetQuota(ctx, organizationID, metadata)
	if err != nil {
		return nil, err
	}

	return c.render(ctx, organizationID, result.Spec.Quotas, metadata)
}

func (c *Client) Update(ctx context.Context, organizationID ids.OrganizationID, request *openapi.QuotasWrite) (*openapi.QuotasRead, error) {
	commonClient := common.New(c.client)

	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	metadata, err := commonClient.QuotaMetadata(ctx, c.namespace)
	if err != nil {
		return nil, errors.OAuth2InvalidRequest("unable to read quota").WithError(err)
	}

	// PUT replaces the stored list, so it reads the quota as stored.  A fault
	// in the stored list does not block the write that repairs it.
	current, virtual, err := commonClient.StoredQuota(ctx, organizationID)
	if err != nil {
		return nil, errors.OAuth2InvalidRequest("unable to read quota").WithError(err)
	}

	required, err := generate(ctx, organization, request)
	if err != nil {
		return nil, err
	}

	if virtual {
		if err := c.client.Create(ctx, required); err != nil {
			return nil, errors.OAuth2InvalidRequest("unable to create quota").WithError(err)
		}

		return c.render(ctx, organizationID, required.Spec.Quotas, metadata)
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := commonClient.CheckQuotaConsistency(ctx, organizationID, metadata, updated, nil); err != nil {
		return nil, err
	}

	if err := c.client.Patch(ctx, updated, client.MergeFromWithOptions(current, &client.MergeFromWithOptimisticLock{})); err != nil {
		if kerrors.IsConflict(err) {
			return nil, errors.HTTPConflict().WithError(err)
		}

		return nil, fmt.Errorf("%w: failed to patch quotas", err)
	}

	return c.render(ctx, organizationID, updated.Spec.Quotas, metadata)
}
