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

package allocations

import (
	"context"
	goerrors "errors"
	"fmt"
	"sync"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

type SyncClient struct {
	*Client
	// mutex is for serialising allocation decisions; this is supplied
	// when constructing the client, so it can be centralised.
	mutex *sync.Mutex
}

func New(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

func NewSync(client client.Client, namespace string, mutex *sync.Mutex) *SyncClient {
	return &SyncClient{
		Client: New(client, namespace),
		mutex:  mutex,
	}
}

func convertAllocation(in *unikornv1.ResourceAllocation) *openapi.ResourceAllocation {
	out := &openapi.ResourceAllocation{
		Kind:      in.Kind,
		Committed: int(in.Committed.Value()),
		Reserved:  int(in.Reserved.Value()),
	}

	return out
}

func convertAllocationList(in []unikornv1.ResourceAllocation) openapi.ResourceAllocationList {
	out := make(openapi.ResourceAllocationList, len(in))

	for i := range in {
		out[i] = *convertAllocation(&in[i])
	}

	return out
}

func convert(in *unikornv1.Allocation) *openapi.AllocationRead {
	out := &openapi.AllocationRead{
		Metadata: conversion.ProjectScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.AllocationSpec{
			Kind:        in.Labels[constants.ReferencedResourceKindLabel],
			Id:          in.Labels[constants.ReferencedResourceIDLabel],
			Allocations: convertAllocationList(in.Spec.Allocations),
		},
	}

	return out
}

func generateAllocation(in *openapi.ResourceAllocation) *unikornv1.ResourceAllocation {
	out := &unikornv1.ResourceAllocation{
		Kind:      in.Kind,
		Committed: resource.NewQuantity(int64(in.Committed), resource.DecimalSI),
		Reserved:  resource.NewQuantity(int64(in.Reserved), resource.DecimalSI),
	}

	return out
}

func generateAllocationList(in openapi.ResourceAllocationList) []unikornv1.ResourceAllocation {
	out := make([]unikornv1.ResourceAllocation, len(in))

	for i := range in {
		out[i] = *generateAllocation(&in[i])
	}

	return out
}

func generate(ctx context.Context, namespace *corev1.Namespace, organizationID, projectID string, in *openapi.AllocationWrite) (*unikornv1.Allocation, error) {
	out := &unikornv1.Allocation{
		ObjectMeta: conversion.NewObjectMetadata(&in.Metadata, namespace.Name).WithOrganization(organizationID).WithProject(projectID).WithLabel(constants.ReferencedResourceKindLabel, in.Spec.Kind).WithLabel(constants.ReferencedResourceIDLabel, in.Spec.Id).Get(),
		Spec: unikornv1.AllocationSpec{
			Tags:        conversion.GenerateTagList(in.Metadata.Tags),
			Allocations: generateAllocationList(in.Spec.Allocations),
		},
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, fmt.Errorf("%w: failed to set identity metadata", err)
	}

	return out, nil
}

func (c *Client) get(ctx context.Context, namespace, allocationID string) (*unikornv1.Allocation, error) {
	result := &unikornv1.Allocation{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: allocationID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, fmt.Errorf("%w: failed to get allocation", err)
	}

	return result, nil
}

func (c *SyncClient) Create(ctx context.Context, organizationID, projectID string, request *openapi.AllocationWrite) (*openapi.AllocationRead, error) {
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

	// Lock around deciding if we can do this allocation
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if err := common.New(c.client).CheckQuotaConsistency(ctx, organizationID, nil, resource); err != nil {
		return nil, err
	}

	if err := c.client.Create(ctx, resource); err != nil {
		return nil, fmt.Errorf("%w: failed to create allocation", err)
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

		return fmt.Errorf("%w: failed to delete allocation", err)
	}

	return nil
}

func (c *SyncClient) Update(ctx context.Context, organizationID, projectID, allocationID string, request *openapi.AllocationWrite) (*openapi.AllocationRead, error) {
	common := common.New(c.client)

	namespace, err := common.ProjectNamespace(ctx, organizationID, projectID)
	if err != nil {
		return nil, err
	}

	// Lock around deciding if we can do this allocation.
	// Taking the lock here means that each operation will get the most recent revision and
	// succeed at patching. Otherwise, first concurrent update here wins and the rest fail.
	c.mutex.Lock()
	defer c.mutex.Unlock()

	current, err := c.get(ctx, namespace.Name, allocationID)
	if err != nil {
		return nil, err
	}

	required, err := generate(ctx, namespace, organizationID, projectID, request)
	if err != nil {
		return nil, err
	}

	if err := conversion.UpdateObjectMetadata(required, current); err != nil {
		return nil, fmt.Errorf("%w: failed to merge metadata", err)
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := common.CheckQuotaConsistency(ctx, organizationID, nil, updated); err != nil {
		return nil, err
	}

	if err := c.client.Patch(ctx, updated, client.MergeFromWithOptions(current, &client.MergeFromWithOptimisticLock{})); err != nil {
		return nil, fmt.Errorf("%w: failed to patch allocation", err)
	}

	return convert(updated), nil
}
