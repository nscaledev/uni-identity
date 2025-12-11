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
	"slices"
	"strings"
	"sync"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/controller-runtime/pkg/client"
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
	return &openapi.ResourceAllocation{
		Kind:      in.Kind,
		Committed: int(in.Committed.Value()),
		Reserved:  int(in.Reserved.Value()),
	}
}

func convertAllocationList(in []unikornv1.ResourceAllocation) openapi.ResourceAllocationList {
	out := make(openapi.ResourceAllocationList, len(in))

	for i := range in {
		out[i] = *convertAllocation(&in[i])
	}

	return out
}

func convert(in *unikornv1.Allocation) *openapi.AllocationRead {
	metadata, _ := conversion.MaybeProjectScopedResourceReadMetadata(in, in.Spec.Tags)

	return &openapi.AllocationRead{
		Metadata: metadata,
		Spec: openapi.AllocationSpec{
			Kind:        in.Labels[constants.ReferencedResourceKindLabel],
			Id:          in.Labels[constants.ReferencedResourceIDLabel],
			Allocations: convertAllocationList(in.Spec.Allocations),
		},
	}
}

func convertList(in *unikornv1.AllocationList) openapi.Allocations {
	out := make(openapi.Allocations, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i])
	}

	return out
}

func generateAllocation(in *openapi.ResourceAllocation) *unikornv1.ResourceAllocation {
	return &unikornv1.ResourceAllocation{
		Kind:      in.Kind,
		Committed: resource.NewQuantity(int64(in.Committed), resource.DecimalSI),
		Reserved:  resource.NewQuantity(int64(in.Reserved), resource.DecimalSI),
	}
}

func generateAllocationList(in openapi.ResourceAllocationList) []unikornv1.ResourceAllocation {
	out := make([]unikornv1.ResourceAllocation, len(in))

	for i := range in {
		out[i] = *generateAllocation(&in[i])
	}

	return out
}

func generate(ctx context.Context, namespace, organizationID string, projectID *string, in *openapi.AllocationWrite) (*unikornv1.Allocation, error) {
	metadata := conversion.NewObjectMetadata(&in.Metadata, namespace).
		WithOrganization(organizationID).
		WithLabel(constants.ReferencedResourceKindLabel, in.Spec.Kind).
		WithLabel(constants.ReferencedResourceIDLabel, in.Spec.Id)

	if projectID != nil {
		metadata = metadata.WithProject(*projectID)
	}

	out := &unikornv1.Allocation{
		ObjectMeta: metadata.Get(),
		Spec: unikornv1.AllocationSpec{
			Tags:        conversion.GenerateTagList(in.Metadata.Tags),
			Allocations: generateAllocationList(in.Spec.Allocations),
		},
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	return out, nil
}

func (c *Client) List(ctx context.Context, organizationID string) (openapi.Allocations, error) {
	options := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{
			constants.OrganizationLabel: organizationID,
		}),
	}

	var list unikornv1.AllocationList
	if err := c.client.List(ctx, &list, options); err != nil {
		return nil, errors.OAuth2ServerError("failed to list allocations").WithError(err)
	}

	slices.SortStableFunc(list.Items, func(a, b unikornv1.Allocation) int {
		return strings.Compare(a.Name, b.Name)
	})

	return convertList(&list), nil
}

func (c *SyncClient) Create(ctx context.Context, organizationID string, projectID *string, request *openapi.AllocationWrite) (*openapi.AllocationRead, error) {
	targetNamespace := c.namespace

	if projectID != nil {
		namespace, err := common.New(c.client).ProjectNamespace(ctx, organizationID, *projectID)
		if err != nil {
			return nil, err
		}

		targetNamespace = namespace.Name
	}

	// TODO: an allocation for the kind/ID must not already exist, you should be
	// updating the existing one.  Raise an error.
	allocation, err := generate(ctx, targetNamespace, organizationID, projectID, request)
	if err != nil {
		return nil, err
	}

	// Lock around deciding if we can do this allocation
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if err := common.New(c.client).CheckQuotaConsistency(ctx, organizationID, nil, allocation); err != nil {
		return nil, errors.OAuth2InvalidRequest("allocation exceeded quota").WithError(err)
	}

	if err := c.client.Create(ctx, allocation); err != nil {
		return nil, errors.OAuth2ServerError("failed to create allocation").WithError(err)
	}

	return convert(allocation), nil
}

func (c *Client) Get(ctx context.Context, organizationID string, projectID *string, allocationID string) (*openapi.AllocationRead, error) {
	allocation, err := c.get(ctx, organizationID, projectID, allocationID)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("failed to get allocation").WithError(err)
	}

	return convert(allocation), nil
}

func (c *Client) get(ctx context.Context, organizationID string, projectID *string, allocationID string) (*unikornv1.Allocation, error) {
	objectKey := client.ObjectKey{
		Namespace: c.namespace,
		Name:      allocationID,
	}

	if projectID != nil {
		namespace, err := common.New(c.client).ProjectNamespace(ctx, organizationID, *projectID)
		if err != nil {
			return nil, err
		}

		objectKey.Namespace = namespace.Name
	}

	var allocation unikornv1.Allocation
	if err := c.client.Get(ctx, objectKey, &allocation); err != nil {
		return nil, err
	}

	return &allocation, nil
}

func (c *Client) Delete(ctx context.Context, organizationID string, projectID *string, allocationID string) error {
	source, err := c.get(ctx, organizationID, projectID, allocationID)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("failed to delete allocation").WithError(err)
	}

	allocation := &unikornv1.Allocation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      source.Name,
			Namespace: source.Namespace,
		},
	}

	if err := c.client.Delete(ctx, allocation); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("failed to delete allocation").WithError(err)
	}

	return nil
}

func (c *SyncClient) Update(ctx context.Context, organizationID string, projectID *string, allocationID string, request *openapi.AllocationWrite) (*openapi.AllocationRead, error) {
	current, err := c.get(ctx, organizationID, projectID, allocationID)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("failed to update allocation").WithError(err)
	}

	required, err := generate(ctx, current.Namespace, organizationID, projectID, request)
	if err != nil {
		return nil, err
	}

	if err := conversion.UpdateObjectMetadata(required, current); err != nil {
		return nil, errors.OAuth2ServerError("failed to merge metadata").WithError(err)
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	// Lock around deciding if we can do this allocation
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if err := common.New(c.client).CheckQuotaConsistency(ctx, organizationID, nil, updated); err != nil {
		return nil, errors.OAuth2InvalidRequest("allocation exceeded quota").WithError(err)
	}

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return nil, errors.OAuth2ServerError("failed to patch allocation").WithError(err)
	}

	return convert(updated), nil
}
