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

package quotas

import (
	"context"
	"slices"
	"strings"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	errorsv2 "github.com/unikorn-cloud/core/pkg/server/v2/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"k8s.io/apimachinery/pkg/api/resource"

	"sigs.k8s.io/controller-runtime/pkg/client"
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
	return &unikornv1.ResourceQuota{
		Kind:     in.Kind,
		Quantity: resource.NewQuantity(int64(in.Quantity), resource.DecimalSI),
	}
}

func generateQuotaList(in openapi.QuotaWriteList) []unikornv1.ResourceQuota {
	out := make([]unikornv1.ResourceQuota, len(in))

	for i := range in {
		out[i] = *generateQuota(&in[i])
	}

	return out
}

func generate(ctx context.Context, organization *organizations.Meta, in *openapi.QuotasWrite) (*unikornv1.Quota, error) {
	metadata := &coreapi.ResourceWriteMetadata{
		Name: constants.UndefinedName,
	}

	out := &unikornv1.Quota{
		ObjectMeta: conversion.NewObjectMetadata(metadata, organization.Namespace).WithOrganization(organization.ID).Get(),
		Spec: unikornv1.QuotaSpec{
			Quotas: generateQuotaList(in.Quotas),
		},
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, err
	}

	return out, nil
}

func (c *Client) convert(ctx context.Context, in *unikornv1.Quota, organizationID string) (*openapi.QuotasRead, error) {
	opts := []client.ListOption{
		&client.ListOptions{Namespace: c.namespace},
	}

	var list unikornv1.QuotaMetadataList
	if err := c.client.List(ctx, &list, opts...); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve quota metadata: %w", err).
			Prefixed()

		return nil, err
	}

	// Grab the totals across all allocations.
	allocations, err := common.New(c.client).GetAllocations(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	type usage struct {
		committed int64
		reserved  int64
	}

	memo := make(map[string]usage)

	for i := range allocations.Items {
		allocation := &allocations.Items[i]

		for j := range allocation.Spec.Allocations {
			resource := &allocation.Spec.Allocations[j]

			record := memo[resource.Kind]
			record.committed += resource.Committed.Value()
			record.reserved += resource.Reserved.Value()

			memo[resource.Kind] = record
		}
	}

	out := &openapi.QuotasRead{
		Quotas: make(openapi.QuotaReadList, len(in.Spec.Quotas)),
	}

	for i := range in.Spec.Quotas {
		quota := &in.Spec.Quotas[i]

		isTargetMetadata := func(metadata unikornv1.QuotaMetadata) bool {
			return metadata.Name == quota.Kind
		}

		var (
			index  = slices.IndexFunc(list.Items, isTargetMetadata)
			meta   = &list.Items[index]
			record = memo[meta.Kind]
			used   = record.committed + record.reserved
			free   = quota.Quantity.Value() - used
		)

		out.Quotas[i] = openapi.QuotaRead{
			Kind:        quota.Kind,
			Quantity:    int(quota.Quantity.Value()),
			Used:        int(used),
			Free:        int(free),
			Committed:   int(record.committed),
			Reserved:    int(record.reserved),
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
		return nil, err
	}

	required, err := generate(ctx, organization, request)
	if err != nil {
		return nil, err
	}

	if virtual {
		if err := c.client.Create(ctx, required); err != nil {
			err = errorsv2.NewInternalError().
				WithCausef("failed to create quota: %w", err).
				Prefixed()

			return nil, err
		}

		return c.convert(ctx, required, organizationID)
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := common.CheckQuotaConsistency(ctx, organizationID, updated, nil); err != nil {
		return nil, err
	}

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to patch quota: %w", err).
			Prefixed()

		return nil, err
	}

	return c.convert(ctx, updated, organizationID)
}
