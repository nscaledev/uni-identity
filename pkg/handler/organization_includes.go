/*
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

package handler

import (
	"context"
	"fmt"
	"slices"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/quotas"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// quotasErrorText is the generic reason for a row whose quota data does not
// render. It never contains the internal error.
const quotasErrorText = "quota data is inconsistent"

// organizationExtras holds the supporting objects of one request, grouped by
// organization ID. Every object comes from the informer cache without a copy,
// so treat it as read-only.
type organizationExtras struct {
	quotas      map[string][]unikornv1.Quota
	allocations map[string][]unikornv1.Allocation
	projects    map[string][]unikornv1.Project
	metadata    []unikornv1.QuotaMetadata
}

// listShared lists every object of one kind in all namespaces, without deep
// copies.
//
// YAGNI: each request scans every cached object of the kind, whatever the
// caller can see. A label selector over the caller's IDs still compares each
// object with the full ID list. Add the selector only if this scan becomes a
// hot path.
func (h *Handler) listShared(ctx context.Context, list client.ObjectList) error {
	return h.client.List(ctx, list, &client.ListOptions{UnsafeDisableDeepCopy: ptr.To(true)})
}

// byOrganizationLabel groups items by their organization label. Items
// without the label go under the empty key, which no organization uses.
func byOrganizationLabel[T any](items []T, labels func(*T) map[string]string) map[string][]T {
	out := map[string][]T{}

	for i := range items {
		id := labels(&items[i])[constants.OrganizationLabel]

		out[id] = append(out[id], items[i])
	}

	return out
}

// loadQuotaExtras lists the Quota, Allocation and QuotaMetadata objects that
// the quotas include needs. A QuotaMetadata object without a default causes a
// fault on every row, so it fails the request.
func (h *Handler) loadQuotaExtras(ctx context.Context, extras *organizationExtras) error {
	quotaList := &unikornv1.QuotaList{}

	if err := h.listShared(ctx, quotaList); err != nil {
		return err
	}

	allocationList := &unikornv1.AllocationList{}

	if err := h.listShared(ctx, allocationList); err != nil {
		return err
	}

	metadataList := &unikornv1.QuotaMetadataList{}

	if err := h.client.List(ctx, metadataList, &client.ListOptions{Namespace: h.namespace, UnsafeDisableDeepCopy: ptr.To(true)}); err != nil {
		return err
	}

	for i := range metadataList.Items {
		if metadataList.Items[i].Spec.Default == nil {
			return fmt.Errorf("%w: quota metadata %s has no default", coreerrors.ErrConsistency, metadataList.Items[i].Name)
		}
	}

	extras.quotas = byOrganizationLabel(quotaList.Items, func(q *unikornv1.Quota) map[string]string { return q.Labels })
	extras.allocations = byOrganizationLabel(allocationList.Items, func(a *unikornv1.Allocation) map[string]string { return a.Labels })
	extras.metadata = metadataList.Items

	return nil
}

// loadProjectExtras lists the Project objects that the projectsCount include
// needs.
func (h *Handler) loadProjectExtras(ctx context.Context, extras *organizationExtras) error {
	projectList := &unikornv1.ProjectList{}

	if err := h.listShared(ctx, projectList); err != nil {
		return err
	}

	extras.projects = byOrganizationLabel(projectList.Items, func(p *unikornv1.Project) map[string]string { return p.Labels })

	return nil
}

// loadExtras lists whatever the requested includes need.
func (h *Handler) loadExtras(ctx context.Context, wantQuotas, wantCount bool) (*organizationExtras, error) {
	extras := &organizationExtras{}

	if wantQuotas {
		if err := h.loadQuotaExtras(ctx, extras); err != nil {
			return nil, err
		}
	}

	if wantCount {
		if err := h.loadProjectExtras(ctx, extras); err != nil {
			return nil, err
		}
	}

	return extras, nil
}

// renderQuotas renders one organization's quotas from the buckets.
func renderQuotas(organizationID string, extras *organizationExtras) (openapi.QuotaReadList, error) {
	stored := extras.quotas[organizationID]
	if len(stored) > 1 {
		return nil, fmt.Errorf("%w: expected at most 1 organization quota, found %d", coreerrors.ErrConsistency, len(stored))
	}

	var quota *unikornv1.Quota

	if len(stored) == 1 {
		quota = &stored[0]
	}

	normalised, err := common.Normalise(quota, extras.metadata)
	if err != nil {
		return nil, err
	}

	return quotas.Convert(normalised, extras.metadata, extras.allocations[organizationID])
}

// applyQuotas sets item.Quotas when the caller can read the quotas of the
// organization. A fault in the quota data of that organization affects only
// that row. The row gets a generic reason in quotasError, and the log gets
// the fault.
func applyQuotas(ctx context.Context, item *openapi.OrganizationRead, organizationID ids.OrganizationID, extras *organizationExtras) {
	if rbac.AllowOrganizationScopeID(ctx, "identity:quotas", openapi.Read, organizationID) != nil {
		return
	}

	list, err := renderQuotas(item.Metadata.Id, extras)
	if err != nil {
		log.FromContext(ctx).Error(err, "organization quota data fault", "organization", item.Metadata.Id)

		item.QuotasError = ptr.To(quotasErrorText)

		return
	}

	item.Quotas = &list
}

// applyProjectsCount sets item.ProjectsCount when the caller can see projects
// in the organization. This is true with organization-scope read, or when
// project-scope read shows at least one project.
func applyProjectsCount(ctx context.Context, item *openapi.OrganizationRead, organizationID ids.OrganizationID, extras *organizationExtras) {
	orgRead := rbac.AllowOrganizationScopeID(ctx, "identity:projects", openapi.Read, organizationID) == nil

	visible := 0

	for _, project := range extras.projects[item.Metadata.Id] {
		if projectVisible(ctx, organizationID, project.Name) {
			visible++
		}
	}

	if !orgRead && visible == 0 {
		return
	}

	item.ProjectsCount = ptr.To(visible)
}

// includeOrganizationExtras sets the extras that include names on each item
// that the caller can inspect. A row whose ID does not parse keeps only its
// base fields. This service creates the IDs as UUIDs.
func (h *Handler) includeOrganizationExtras(ctx context.Context, items openapi.Organizations, include []string) error {
	if len(items) == 0 || len(include) == 0 {
		return nil
	}

	wantQuotas := slices.Contains(include, string(openapi.Quotas))
	wantCount := slices.Contains(include, string(openapi.ProjectsCount))

	extras, err := h.loadExtras(ctx, wantQuotas, wantCount)
	if err != nil {
		return err
	}

	for i := range items {
		organizationID, err := ids.ParseOrganizationID(items[i].Metadata.Id)
		if err != nil {
			continue
		}

		if wantQuotas {
			applyQuotas(ctx, &items[i], organizationID, extras)
		}

		if wantCount {
			applyProjectsCount(ctx, &items[i], organizationID, extras)
		}
	}

	return nil
}
