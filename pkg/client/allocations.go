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

type APIClientGetter func(context.Context) (openapi.ClientWithResponsesInterface, error)

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

// OrganizationScopedCreateRaw creates a new allocation at organisation scope and returns the allocation ID.
// The reference must be in the format "<resource-kind>/<resource-id>".
func (r *Allocations) OrganizationScopedCreateRaw(ctx context.Context, organizationID, reference string, allocations openapi.ResourceAllocationList) (string, error) {
	params, err := generateAllocation(reference, allocations)
	if err != nil {
		return "", err
	}

	response, err := r.api.PostApiV1OrganizationsOrganizationIDAllocationsWithResponse(ctx, organizationID, params)
	if err != nil {
		return "", err
	}

	if code := response.StatusCode(); code != http.StatusCreated {
		return "", api.ExtractError(code, response)
	}

	return response.JSON201.Metadata.Id, nil
}

// ProjectScopedCreateRaw creates a new allocation at project scope and returns the allocation ID.
// The reference must be in the format "<resource-kind>/<resource-id>".
func (r *Allocations) ProjectScopedCreateRaw(ctx context.Context, organizationID, projectID, reference string, allocations openapi.ResourceAllocationList) (string, error) {
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

// OrganizationScopedCreate creates a new allocation at organisation scope by reading the required
// information from the resource annotations and persisting the allocation ID back to the annotations.
func (r *Allocations) OrganizationScopedCreate(ctx context.Context, resource client.Object, allocations openapi.ResourceAllocationList) error {
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

	allocationID, err := r.OrganizationScopedCreateRaw(ctx, userPrincipal.OrganizationID, reference, allocations)
	if err != nil {
		return err
	}

	setAllocationID(resource, allocationID)

	return nil
}

// ProjectScopedCreate creates a new allocation at project scope by reading the required
// information from the resource annotations and persisting the allocation ID back to the annotations.
// TODO: could we not just use the resource reference as key, rather than messing with IDs?
func (r *Allocations) ProjectScopedCreate(ctx context.Context, resource client.Object, allocations openapi.ResourceAllocationList) error {
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

	allocationID, err := r.ProjectScopedCreateRaw(ctx, userPrincipal.OrganizationID, userPrincipal.ProjectID, reference, allocations)
	if err != nil {
		return err
	}

	setAllocationID(resource, allocationID)

	return nil
}

// Create creates a new allocation at project scope by reading the required
// information from the resource annotations and persisting the allocation ID
// back to the annotations.
// Deprecated: use ProjectScopedCreate instead.
func (r *Allocations) Create(ctx context.Context, resource client.Object, allocations openapi.ResourceAllocationList) error {
	return r.ProjectScopedCreate(ctx, resource, allocations)
}

// OrganizationScopedUpdateRaw updates an existing allocation at organisation scope.
// The reference must be in the format "<resource-kind>/<resource-id>".
func (r *Allocations) OrganizationScopedUpdateRaw(ctx context.Context, organizationID, id, reference string, allocations openapi.ResourceAllocationList) error {
	params, err := generateAllocation(reference, allocations)
	if err != nil {
		return err
	}

	response, err := r.api.PutApiV1OrganizationsOrganizationIDAllocationsAllocationIDWithResponse(ctx, organizationID, id, params)
	if err != nil {
		return err
	}

	if code := response.StatusCode(); code != http.StatusOK {
		return api.ExtractError(code, response)
	}

	return nil
}

// ProjectScopedUpdateRaw updates an existing allocation at project scope.
// The reference must be in the format "<resource-kind>/<resource-id>".
func (r *Allocations) ProjectScopedUpdateRaw(ctx context.Context, organizationID, projectID, id, reference string, allocations openapi.ResourceAllocationList) error {
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

// OrganizationScopedUpdate updates an existing allocation at organisation scope by reading the required
// information from the resource annotations.
func (r *Allocations) OrganizationScopedUpdate(ctx context.Context, resource client.Object, allocations openapi.ResourceAllocationList) error {
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

	return r.OrganizationScopedUpdateRaw(ctx, userPrincipal.OrganizationID, allocationID, reference, allocations)
}

// ProjectScopedUpdate updates an existing allocation at project scope by reading the required
// information from the resource annotations.
func (r *Allocations) ProjectScopedUpdate(ctx context.Context, resource client.Object, allocations openapi.ResourceAllocationList) error {
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

	return r.ProjectScopedUpdateRaw(ctx, userPrincipal.OrganizationID, userPrincipal.ProjectID, allocationID, reference, allocations)
}

// Update updates an existing allocation at project scope by reading the required
// information from the resource annotations.
// Deprecated: use ProjectScopedUpdate instead.
func (r *Allocations) Update(ctx context.Context, resource client.Object, allocations openapi.ResourceAllocationList) error {
	return r.ProjectScopedUpdate(ctx, resource, allocations)
}

// OrganizationScopedDeleteRaw deletes an existing allocation at organisation scope.
func (r *Allocations) OrganizationScopedDeleteRaw(ctx context.Context, organizationID, id string) error {
	response, err := r.api.DeleteApiV1OrganizationsOrganizationIDAllocationsAllocationIDWithResponse(ctx, organizationID, id)
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

// ProjectScopedDeleteRaw deletes an existing allocation at project scope.
func (r *Allocations) ProjectScopedDeleteRaw(ctx context.Context, organizationID, projectID, id string) error {
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

// OrganizationScopedDelete deletes an existing allocation at organisation scope by reading the required
// information from the resource annotations.
func (r *Allocations) OrganizationScopedDelete(ctx context.Context, resource client.Object) error {
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

	return r.OrganizationScopedDeleteRaw(ctx, userPrincipal.OrganizationID, allocationID)
}

// ProjectScopedDelete deletes an existing allocation at project scope by reading the required
// information from the resource annotations.
func (r *Allocations) ProjectScopedDelete(ctx context.Context, resource client.Object) error {
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

	return r.ProjectScopedDeleteRaw(ctx, userPrincipal.OrganizationID, userPrincipal.ProjectID, allocationID)
}

// Delete deletes an existing allocation at project scope by reading the required
// information from the resource annotations.
// Deprecated: use ProjectScopedDelete instead.
func (r *Allocations) Delete(ctx context.Context, resource client.Object) error {
	return r.ProjectScopedDelete(ctx, resource)
}
