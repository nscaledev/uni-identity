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

//nolint:revive
package handler

import (
	"context"
	"net/http"
	"slices"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/util"
	"github.com/unikorn-cloud/identity/pkg/handler/allocations"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

func (h *Handler) allocationsClient() *allocations.Client {
	return allocations.New(h.client, h.namespace)
}

func (h *Handler) allocationsSyncClient() *allocations.SyncClient {
	return allocations.NewSync(h.directclient, h.namespace, &h.allocationMutex)
}

func (h *Handler) hasAllocationAccess(ctx context.Context, operation openapi.AclOperation, organizationID string, projectID *string) error {
	const endpoint = "identity:allocations"

	if projectID != nil {
		return rbac.AllowProjectScope(ctx, endpoint, operation, organizationID, *projectID)
	}

	return rbac.AllowOrganizationScope(ctx, endpoint, operation, organizationID)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDAllocations(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	ctx := r.Context()

	result, err := h.allocationsClient().List(ctx, organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result = slices.DeleteFunc(result, func(resource openapi.AllocationRead) bool {
		return h.hasAllocationAccess(ctx, openapi.Read, organizationID, resource.Metadata.ProjectId) != nil
	})

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDAllocations(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	ctx := r.Context()

	if err := h.hasAllocationAccess(ctx, openapi.Create, organizationID, nil); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	var request openapi.AllocationWrite
	if err := util.ReadJSONBody(r, &request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.allocationsSyncClient().Create(ctx, organizationID, nil, &request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDAllocationsAllocationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, allocationID openapi.AllocationIDParameter) {
	ctx := r.Context()

	if err := h.hasAllocationAccess(ctx, openapi.Delete, organizationID, nil); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.allocationsClient().Delete(ctx, organizationID, nil, allocationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDAllocationsAllocationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, allocationID openapi.AllocationIDParameter) {
	ctx := r.Context()

	if err := h.hasAllocationAccess(ctx, openapi.Read, organizationID, nil); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.allocationsClient().Get(ctx, organizationID, nil, allocationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDAllocationsAllocationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, allocationID openapi.AllocationIDParameter) {
	ctx := r.Context()

	if err := h.hasAllocationAccess(ctx, openapi.Update, organizationID, nil); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	var request openapi.AllocationWrite
	if err := util.ReadJSONBody(r, &request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.allocationsSyncClient().Update(ctx, organizationID, nil, allocationID, &request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocations(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	ctx := r.Context()

	if err := h.hasAllocationAccess(ctx, openapi.Create, organizationID, &projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	var request openapi.AllocationWrite
	if err := util.ReadJSONBody(r, &request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.allocationsSyncClient().Create(ctx, organizationID, &projectID, &request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, allocationID openapi.AllocationIDParameter) {
	ctx := r.Context()

	if err := h.hasAllocationAccess(ctx, openapi.Delete, organizationID, &projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.allocationsClient().Delete(ctx, organizationID, &projectID, allocationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, allocationID openapi.AllocationIDParameter) {
	ctx := r.Context()

	if err := h.hasAllocationAccess(ctx, openapi.Read, organizationID, &projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.allocationsClient().Get(ctx, organizationID, &projectID, allocationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, allocationID openapi.AllocationIDParameter) {
	ctx := r.Context()

	if err := h.hasAllocationAccess(ctx, openapi.Update, organizationID, &projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	var request openapi.AllocationWrite
	if err := util.ReadJSONBody(r, &request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.allocationsSyncClient().Update(ctx, organizationID, &projectID, allocationID, &request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}
