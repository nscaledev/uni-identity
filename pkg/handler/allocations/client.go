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

package allocations

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
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrNamespace = goerrors.New("unable to resolve project namespace")
)

type Client struct {
	// client allows Kubernetes API access.
	client client.Client
	// namespace is the base identity namespace.
	namespace string
}

func New(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

func convertAllocation(in *unikornv1.ResourceAllocation) *openapi.QuotaDetailed {
	out := &openapi.QuotaDetailed{
		Kind:      in.Kind,
		Committed: int(in.Committed.Value()),
		Reserved:  int(in.Reserved.Value()),
	}

	return out
}

func convertAllocationList(in []unikornv1.ResourceAllocation) openapi.QuotaListDetailed {
	out := make(openapi.QuotaListDetailed, len(in))

	for i := range in {
		out[i] = *convertAllocation(&in[i])
	}

	return out
}

func convert(in *unikornv1.Allocation) *openapi.AllocationRead {
	out := &openapi.AllocationRead{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags, coreopenapi.ResourceProvisioningStatusProvisioned),
		Spec: openapi.AllocationSpec{
			Kind:        in.Labels[constants.ReferencedResourceKindLabel],
			Id:          in.Labels[constants.ReferencedResourceIDLabel],
			Allocations: convertAllocationList(in.Spec.Allocations),
		},
	}

	return out
}

func convertList(in *unikornv1.AllocationList) openapi.Allocations {
	out := make(openapi.Allocations, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i])
	}

	return out
}

func generateAllocation(in *openapi.QuotaDetailed) *unikornv1.ResourceAllocation {
	out := &unikornv1.ResourceAllocation{
		Kind:      in.Kind,
		Committed: resource.NewQuantity(int64(in.Committed), resource.DecimalSI),
		Reserved:  resource.NewQuantity(int64(in.Reserved), resource.DecimalSI),
	}

	return out
}

func generateAllocationList(in openapi.QuotaListDetailed) []unikornv1.ResourceAllocation {
	out := make([]unikornv1.ResourceAllocation, len(in))

	for i := range in {
		out[i] = *generateAllocation(&in[i])
	}

	return out
}

func generate(ctx context.Context, namespace *corev1.Namespace, organizationID, projectID string, in *openapi.AllocationWrite) (*unikornv1.Allocation, error) {
	info, err := authorization.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	out := &unikornv1.Allocation{
		ObjectMeta: conversion.NewObjectMetadata(&in.Metadata, namespace.Name, info.Userinfo.Sub).WithOrganization(organizationID).WithProject(projectID).WithLabel(constants.ReferencedResourceKindLabel, in.Spec.Kind).WithLabel(constants.ReferencedResourceIDLabel, in.Spec.Id).Get(),
		Spec: unikornv1.AllocationSpec{
			Tags:        conversion.GenerateTagList(in.Metadata.Tags),
			Allocations: generateAllocationList(in.Spec.Allocations),
		},
	}

	return out, nil
}

func (c *Client) get(ctx context.Context, namespace, allocationID string) (*unikornv1.Allocation, error) {
	result := &unikornv1.Allocation{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: allocationID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("failed to get allocation").WithError(err)
	}

	return result, nil
}

func (c *Client) List(ctx context.Context, organizationID string) (openapi.Allocations, error) {
	result := &unikornv1.AllocationList{}

	requirement, err := labels.NewRequirement(constants.OrganizationLabel, selection.Equals, []string{organizationID})
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to build label selector").WithError(err)
	}

	options := &client.ListOptions{
		LabelSelector: labels.NewSelector().Add(*requirement),
	}

	if err := c.client.List(ctx, result, options); err != nil {
		return nil, errors.OAuth2ServerError("failed to list allocations").WithError(err)
	}

	slices.SortStableFunc(result.Items, func(a, b unikornv1.Allocation) int {
		return strings.Compare(a.Name, b.Name)
	})

	return convertList(result), nil
}

func (c *Client) Create(ctx context.Context, organizationID, projectID string, request *openapi.AllocationWrite) (*openapi.AllocationRead, error) {
	namespace, err := common.New(c.client).ProjectNamespace(ctx, organizationID, projectID)
	if err != nil {
		return nil, err
	}

	// TODO: an allocation for the kind/ID must not already exist, you should be
	// updaing the existing one.  Raise an error.
	resource, err := generate(ctx, namespace, organizationID, projectID, request)
	if err != nil {
		return nil, err
	}

	if err := common.New(c.client).CheckQuotaConsistency(ctx, organizationID, nil, resource); err != nil {
		return nil, errors.OAuth2InvalidRequest("allocation exceeded quota").WithError(err)
	}

	if err := c.client.Create(ctx, resource); err != nil {
		return nil, errors.OAuth2ServerError("failed to create allocation").WithError(err)
	}

	return convert(resource), nil
}

func (c *Client) Get(ctx context.Context, organizationID, projectID, allocationID string) (*openapi.AllocationRead, error) {
	namespace, err := common.New(c.client).ProjectNamespace(ctx, organizationID, projectID)
	if err != nil {
		return nil, err
	}

	result, err := c.get(ctx, namespace.Name, allocationID)
	if err != nil {
		return nil, err
	}

	return convert(result), nil
}

func (c *Client) Delete(ctx context.Context, organizationID, projectID, allocationID string) error {
	namespace, err := common.New(c.client).ProjectNamespace(ctx, organizationID, projectID)
	if err != nil {
		return err
	}

	controlPlane := &unikornv1.Allocation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      allocationID,
			Namespace: namespace.Name,
		},
	}

	if err := c.client.Delete(ctx, controlPlane); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("failed to delete allocation").WithError(err)
	}

	return nil
}

func (c *Client) Update(ctx context.Context, organizationID, projectID, allocationID string, request *openapi.AllocationWrite) (*openapi.AllocationRead, error) {
	common := common.New(c.client)

	namespace, err := common.ProjectNamespace(ctx, organizationID, projectID)
	if err != nil {
		return nil, err
	}

	current, err := c.get(ctx, namespace.Name, allocationID)
	if err != nil {
		return nil, err
	}

	required, err := generate(ctx, namespace, organizationID, projectID, request)
	if err != nil {
		return nil, err
	}

	if err := conversion.UpdateObjectMetadata(required, current, nil, nil); err != nil {
		return nil, errors.OAuth2ServerError("failed to merge metadata").WithError(err)
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := common.CheckQuotaConsistency(ctx, organizationID, nil, updated); err != nil {
		return nil, errors.OAuth2InvalidRequest("allocation exceeded quota").WithError(err)
	}

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return nil, errors.OAuth2ServerError("failed to patch allocation").WithError(err)
	}

	return convert(updated), nil
}
