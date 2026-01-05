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
	"slices"
	"strings"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/openapi"

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
		ObjectMeta: conversion.NewObjectMetadata(metadata, organization.Namespace).WithOrganization(organization.ID).Get(),
		Spec: unikornv1.QuotaSpec{
			Quotas: generateQuotaList(in.Quotas),
		},
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	return out, nil
}

type allocation struct {
	committed int64
	reserved  int64
}

func (c *Client) convert(ctx context.Context, in *unikornv1.Quota, organizationID string) (*openapi.QuotasRead, error) {
	metadata := &unikornv1.QuotaMetadataList{}

	if err := c.client.List(ctx, metadata, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return nil, err
	}

	// Grab the totals across all allocations.
	allocations, err := common.New(c.client).GetAllocations(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	allocated := map[string]allocation{}

	for i := range allocations.Items {
		allocation := &allocations.Items[i]

		for j := range allocation.Spec.Allocations {
			resource := &allocation.Spec.Allocations[j]

			allocation := allocated[resource.Kind]
			allocation.committed += resource.Committed.Value()
			allocation.reserved += resource.Reserved.Value()

			allocated[resource.Kind] = allocation
		}
	}

	out := &openapi.QuotasRead{
		Quotas: make(openapi.QuotaReadList, len(in.Spec.Quotas)),
	}

	for i := range in.Spec.Quotas {
		quota := &in.Spec.Quotas[i]

		metaIndex := slices.IndexFunc(metadata.Items, func(m unikornv1.QuotaMetadata) bool {
			return m.Name == quota.Kind
		})

		meta := &metadata.Items[metaIndex]

		used := allocated[quota.Kind].committed + allocated[quota.Kind].reserved
		free := quota.Quantity.Value() - used

		out.Quotas[i] = openapi.QuotaRead{
			Kind:        quota.Kind,
			Quantity:    int(quota.Quantity.Value()),
			Used:        int(used),
			Free:        int(free),
			Committed:   int(allocated[quota.Kind].committed),
			Reserved:    int(allocated[quota.Kind].reserved),
			DisplayName: meta.Spec.DisplayName,
			Description: meta.Spec.Description,
			Default:     int(meta.Spec.Default.Value()),
		}
	}

	slices.SortStableFunc(out.Quotas, func(a, b openapi.QuotaRead) int {
		return strings.Compare(a.Kind, b.Kind)
	})

	return out, nil
}

func (c *Client) Get(ctx context.Context, organizationID string) (*openapi.QuotasRead, error) {
	result, _, err := common.New(c.client).GetQuota(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	return c.convert(ctx, result, organizationID)
}

func (c *Client) Update(ctx context.Context, organizationID string, request *openapi.QuotasWrite) (*openapi.QuotasRead, error) {
	common := common.New(c.client)

	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	current, virtual, err := common.GetQuota(ctx, organizationID)
	if err != nil {
		return nil, errors.OAuth2InvalidRequest("unnable to read quota").WithError(err)
	}

	required, err := generate(ctx, organization, request)
	if err != nil {
		return nil, err
	}

	if virtual {
		if err := c.client.Create(ctx, required); err != nil {
			return nil, errors.OAuth2InvalidRequest("unnable to create quota").WithError(err)
		}

		return c.convert(ctx, required, organizationID)
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := common.CheckQuotaConsistency(ctx, organizationID, updated, nil); err != nil {
		return nil, errors.OAuth2InvalidRequest("allocation exceeded quota").WithError(err)
	}

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return nil, errors.OAuth2ServerError("failed to patch quotas").WithError(err)
	}

	return c.convert(ctx, updated, organizationID)
}
