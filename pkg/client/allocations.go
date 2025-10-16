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

package client

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/errors"
	"github.com/unikorn-cloud/core/pkg/manager"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/util/api"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type APIClientGetter func(context.Context) (openapi.ClientWithResponsesInterface, error)

// Allocations wraps up quota allocation management.  This is specific to API
// handlers only.
type Allocations struct {
	client       client.Client
	getAPIClient APIClientGetter
}

func NewAllocations(client client.Client, getAPIClient APIClientGetter) *Allocations {
	return &Allocations{
		client:       client,
		getAPIClient: getAPIClient,
	}
}

func generateAllocation(reference string, allocations openapi.ResourceAllocationList) openapi.AllocationWrite {
	parts := strings.Split(reference, "/")

	return openapi.AllocationWrite{
		Metadata: coreapi.ResourceWriteMetadata{
			Name: "undefined",
		},
		Spec: openapi.AllocationSpec{
			Kind:        parts[0],
			Id:          parts[1],
			Allocations: allocations,
		},
	}
}

func setAllocationID(resource client.Object, allocation *openapi.AllocationRead) {
	annotations := resource.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	annotations[constants.AllocationAnnotation] = allocation.Metadata.Id

	resource.SetAnnotations(annotations)
}

func getAllocationID(resource client.Object) (string, error) {
	annotations := resource.GetAnnotations()
	if annotations == nil {
		return "", fmt.Errorf("%w: resource has no annotations", errors.ErrConsistency)
	}

	id, ok := annotations[constants.AllocationAnnotation]
	if !ok {
		return "", fmt.Errorf("%w: resource has no allocation annotations", errors.ErrConsistency)
	}

	return id, nil
}

// Create accepts a resource kind, creates an allocation for it with the requested
// set of resources, and patches the allocation ID into the resource for tracking.
// TODO: could we not just use the resource reference as eky, rather than messing with IDs?
func (r *Allocations) Create(ctx context.Context, resource client.Object, allocations openapi.ResourceAllocationList) error {
	// On creation the principal is always directly avaialable from the API,
	// this is to whom the allocation will be charged.
	userPrincipal, err := principal.GetPrincipal(ctx)
	if err != nil {
		return err
	}

	apiClient, err := r.getAPIClient(ctx)
	if err != nil {
		return err
	}

	reference, err := manager.GenerateResourceReference(r.client, resource)
	if err != nil {
		return err
	}

	response, err := apiClient.PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsWithResponse(ctx, userPrincipal.OrganizationID, userPrincipal.ProjectID, generateAllocation(reference, allocations))
	if err != nil {
		return err
	}

	if response.StatusCode() != http.StatusCreated {
		return api.ExtractError(response.StatusCode(), response)
	}

	setAllocationID(resource, response.JSON201)

	return nil
}

// Update updates an existing allocation, typically for scaling operations.
func (r *Allocations) Update(ctx context.Context, resource client.Object, allocations openapi.ResourceAllocationList) error {
	// On update the principal will come from the object itself, as we cannot guarantee
	// the user who is modifying the resource is the same as who initially created it.
	userPrincipal, err := principal.FromResource(resource)
	if err != nil {
		return err
	}

	apiClient, err := r.getAPIClient(ctx)
	if err != nil {
		return err
	}

	reference, err := manager.GenerateResourceReference(r.client, resource)
	if err != nil {
		return err
	}

	allocationID, err := getAllocationID(resource)
	if err != nil {
		return err
	}

	response, err := apiClient.PutApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDWithResponse(ctx, userPrincipal.OrganizationID, userPrincipal.ProjectID, allocationID, generateAllocation(reference, allocations))
	if err != nil {
		return err
	}

	if response.StatusCode() != http.StatusOK {
		return api.ExtractError(response.StatusCode(), response)
	}

	return nil
}

// Delete deletes the allocation.
func (r *Allocations) Delete(ctx context.Context, resource client.Object) error {
	// On delete the principal will come from the object itself, as we cannot guarantee
	// the user who is deleting the resource is the same as who initially created it.
	userPrincipal, err := principal.FromResource(resource)
	if err != nil {
		return err
	}

	apiClient, err := r.getAPIClient(ctx)
	if err != nil {
		return err
	}

	allocationID, err := getAllocationID(resource)
	if err != nil {
		return err
	}

	response, err := apiClient.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDWithResponse(ctx, userPrincipal.OrganizationID, userPrincipal.ProjectID, allocationID)
	if err != nil {
		return err
	}

	if response.StatusCode() != http.StatusAccepted {
		return api.ExtractError(response.StatusCode(), response)
	}

	return nil
}
