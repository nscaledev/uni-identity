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
	goerrors "errors"
	"net/http"
	"strings"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/manager"
	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/util/api"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrInvalidResourceReference = goerrors.New("invalid resource reference format")
	ErrNoAllocationAnnotation   = goerrors.New("resource has no allocation annotation")
)

// Allocations wraps up quota allocation management.  This is specific to API
// handlers only.
type Allocations struct {
	client client.Client
	api    openapi.ClientWithResponsesInterface
}

func NewAllocations(client client.Client, api openapi.ClientWithResponsesInterface) *Allocations {
	return &Allocations{
		client: client,
		api:    api,
	}
}

func computeResourceKindAndID(reference string) (string, string, error) {
	parts := strings.Split(reference, "/")
	if len(parts) != 2 {
		return "", "", ErrInvalidResourceReference
	}

	return parts[0], parts[1], nil
}

func generateAllocation(reference string, allocations openapi.ResourceAllocationList) (openapi.AllocationWrite, error) {
	resourceKind, resourceID, err := computeResourceKindAndID(reference)
	if err != nil {
		return openapi.AllocationWrite{}, err
	}

	allocation := openapi.AllocationWrite{
		Metadata: coreapi.ResourceWriteMetadata{
			Name: "undefined",
		},
		Spec: openapi.AllocationSpec{
			Kind:        resourceKind,
			Id:          resourceID,
			Allocations: allocations,
		},
	}

	return allocation, nil
}

func setAllocationID(resource client.Object, id string) {
	annotations := resource.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	annotations[constants.AllocationAnnotation] = id

	resource.SetAnnotations(annotations)
}

func getAllocationID(resource client.Object) (string, error) {
	annotations := resource.GetAnnotations()
	if annotations == nil {
		return "", ErrNoAllocationAnnotation
	}

	id, ok := annotations[constants.AllocationAnnotation]
	if !ok {
		return "", ErrNoAllocationAnnotation
	}

	return id, nil
}

func (r *Allocations) CreateRaw(ctx context.Context, organizationID, projectID, reference string, allocations openapi.ResourceAllocationList) (string, error) {
	params, err := generateAllocation(reference, allocations)
	if err != nil {
		return "", err
	}

	response, err := r.api.PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsWithResponse(ctx, organizationID, projectID, params)
	if err != nil {
		return "", err
	}

	if code := response.StatusCode(); code != http.StatusCreated {
		return "", api.ExtractError(code, response)
	}

	return response.JSON201.Metadata.Id, nil
}

// Create accepts a resource kind, creates an allocation for it with the requested
// set of resources, and patches the allocation ID into the resource for tracking.
// TODO: could we not just use the resource reference as eky, rather than messing with IDs?
func (r *Allocations) Create(ctx context.Context, resource client.Object, allocations openapi.ResourceAllocationList) error {
	// On creation the principal is always directly available from the API,
	// this is to whom the allocation will be charged.
	userPrincipal, err := principal.GetPrincipal(ctx)
	if err != nil {
		return err
	}

	reference, err := manager.GenerateResourceReference(r.client, resource)
	if err != nil {
		return err
	}

	allocationID, err := r.CreateRaw(ctx, userPrincipal.OrganizationID, userPrincipal.ProjectID, reference, allocations)
	if err != nil {
		return err
	}

	setAllocationID(resource, allocationID)

	return nil
}

func (r *Allocations) UpdateRaw(ctx context.Context, organizationID, projectID, id, reference string, allocations openapi.ResourceAllocationList) error {
	params, err := generateAllocation(reference, allocations)
	if err != nil {
		return err
	}

	response, err := r.api.PutApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDWithResponse(ctx, organizationID, projectID, id, params)
	if err != nil {
		return err
	}

	if code := response.StatusCode(); code != http.StatusOK {
		return api.ExtractError(code, response)
	}

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

	reference, err := manager.GenerateResourceReference(r.client, resource)
	if err != nil {
		return err
	}

	allocationID, err := getAllocationID(resource)
	if err != nil {
		return err
	}

	return r.UpdateRaw(ctx, userPrincipal.OrganizationID, userPrincipal.ProjectID, allocationID, reference, allocations)
}

func (r *Allocations) DeleteRaw(ctx context.Context, organizationID, projectID, id string) error {
	response, err := r.api.DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDWithResponse(ctx, organizationID, projectID, id)
	if err != nil {
		return err
	}

	if code := response.StatusCode(); code != http.StatusAccepted {
		if code == http.StatusNotFound {
			return nil
		}

		return api.ExtractError(code, response)
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

	allocationID, err := getAllocationID(resource)
	if err != nil {
		return err
	}

	return r.DeleteRaw(ctx, userPrincipal.OrganizationID, userPrincipal.ProjectID, allocationID)
}
