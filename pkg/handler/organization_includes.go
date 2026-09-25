/*
Copyright 2022-2024 EscherCloud.
Copyright 2024-2025 the Unikorn Authors.
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
	"strings"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/projects"
	"github.com/unikorn-cloud/identity/pkg/handler/quotas"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	"k8s.io/utils/ptr"
)

// includeFlags is the parsed include parameter.
type includeFlags struct {
	quotas   bool
	projects bool
	count    bool
}

func parseIncludeFlags(include []string) includeFlags {
	return includeFlags{
		quotas:   slices.Contains(include, string(openapi.GetApiV2OrganizationsParamsIncludeQuotas)),
		projects: slices.Contains(include, string(openapi.GetApiV2OrganizationsParamsIncludeProjects)),
		count:    slices.Contains(include, string(openapi.GetApiV2OrganizationsParamsIncludeProjectsCount)),
	}
}

// organizationExtras holds one page's supporting objects, bucketed by
// organization ID.  The informer cache shares every object.  Do not change
// them.
type organizationExtras struct {
	quotas      map[string][]*unikornv1.Quota
	allocations map[string][]*unikornv1.Allocation
	projects    map[string][]*unikornv1.Project
	metadata    []unikornv1.QuotaMetadata
}

// loadQuotaExtras lists quotas, allocations and metadata for the page.
func (h *Handler) loadQuotaExtras(ctx context.Context, extras *organizationExtras, pageIDs []string) error {
	c := common.New(h.client)
	quotaList := &unikornv1.QuotaList{}

	if err := c.ListForOrganizations(ctx, quotaList, pageIDs); err != nil {
		return err
	}

	allocationList := &unikornv1.AllocationList{}

	if err := c.ListForOrganizations(ctx, allocationList, pageIDs); err != nil {
		return err
	}

	metadata, err := c.QuotaMetadata(ctx, h.namespace)
	if err != nil {
		return err
	}

	extras.quotas = map[string][]*unikornv1.Quota{}

	for i := range quotaList.Items {
		id := quotaList.Items[i].Labels[constants.OrganizationLabel]
		extras.quotas[id] = append(extras.quotas[id], &quotaList.Items[i])
	}

	extras.allocations = map[string][]*unikornv1.Allocation{}

	for i := range allocationList.Items {
		id := allocationList.Items[i].Labels[constants.OrganizationLabel]
		extras.allocations[id] = append(extras.allocations[id], &allocationList.Items[i])
	}

	extras.metadata = metadata

	return nil
}

// loadProjectExtras lists projects for the page.
func (h *Handler) loadProjectExtras(ctx context.Context, extras *organizationExtras, pageIDs []string) error {
	projectList := &unikornv1.ProjectList{}

	if err := common.New(h.client).ListForOrganizations(ctx, projectList, pageIDs); err != nil {
		return err
	}

	extras.projects = map[string][]*unikornv1.Project{}

	for i := range projectList.Items {
		id := projectList.Items[i].Labels[constants.OrganizationLabel]
		extras.projects[id] = append(extras.projects[id], &projectList.Items[i])
	}

	return nil
}

// loadExtras lists whatever the requested includes need.
func (h *Handler) loadExtras(ctx context.Context, flags includeFlags, pageIDs []string) (*organizationExtras, error) {
	extras := &organizationExtras{}

	if flags.quotas {
		if err := h.loadQuotaExtras(ctx, extras, pageIDs); err != nil {
			return nil, err
		}
	}

	if flags.projects || flags.count {
		if err := h.loadProjectExtras(ctx, extras, pageIDs); err != nil {
			return nil, err
		}
	}

	return extras, nil
}

// applyQuotas fills item.Quotas when the caller may read the organization's
// quotas.  A data fault in such a row fails the page.
func applyQuotas(ctx context.Context, item *openapi.OrganizationListItem, organizationID ids.OrganizationID, extras *organizationExtras) error {
	permitted := rbac.AllowOrganizationScopeID(ctx, "identity:quotas", openapi.Read, organizationID) == nil
	if !permitted {
		return nil
	}

	stored := extras.quotas[item.Metadata.Id]
	if len(stored) > 1 {
		return fmt.Errorf("%w: organization %s has %d quotas", coreerrors.ErrConsistency, item.Metadata.Id, len(stored))
	}

	var quota *unikornv1.Quota

	if len(stored) == 1 {
		quota = stored[0]
	}

	normalised, err := common.Normalise(quota, extras.metadata)
	if err != nil {
		return fmt.Errorf("%w: organization %s", err, item.Metadata.Id)
	}

	list, err := quotas.Convert(normalised, extras.metadata, extras.allocations[item.Metadata.Id])
	if err != nil {
		return fmt.Errorf("%w: organization %s", err, item.Metadata.Id)
	}

	item.Quotas = &list

	return nil
}

// visibleProjects returns the organization's projects the caller may read,
// sorted by object name as the v1 list is.  It skips a project whose name
// is not a valid ID, as the v1 list does.  It converts nothing, so a
// count-only request pays no conversion cost.
func visibleProjects(ctx context.Context, organizationID ids.OrganizationID, stored []*unikornv1.Project, orgRead bool) []*unikornv1.Project {
	visible := make([]*unikornv1.Project, 0, len(stored))

	for _, project := range stored {
		projectID, err := ids.ParseProjectID(project.Name)
		if err != nil {
			continue
		}

		if orgRead || rbac.AllowProjectScopeID(ctx, "identity:projects", openapi.Read, organizationID, projectID) == nil {
			visible = append(visible, project)
		}
	}

	slices.SortStableFunc(visible, func(a, b *unikornv1.Project) int {
		return strings.Compare(a.Name, b.Name)
	})

	return visible
}

// applyProjects fills item.Projects and item.ProjectsCount when the caller
// can see projects in the organization: organization-scope read, or at
// least one project visible through project-scope read.
func applyProjects(ctx context.Context, item *openapi.OrganizationListItem, organizationID ids.OrganizationID, extras *organizationExtras, flags includeFlags) {
	orgRead := rbac.AllowOrganizationScopeID(ctx, "identity:projects", openapi.Read, organizationID) == nil
	visible := visibleProjects(ctx, organizationID, extras.projects[item.Metadata.Id], orgRead)

	if !orgRead && len(visible) == 0 {
		return
	}

	if flags.projects {
		converted := make(openapi.Projects, 0, len(visible))

		for _, project := range visible {
			converted = append(converted, *projects.Convert(project))
		}

		item.Projects = &converted
	}

	if flags.count {
		item.ProjectsCount = ptr.To(len(visible))
	}
}

// applyExtras fills one item.
func applyExtras(ctx context.Context, item *openapi.OrganizationListItem, organizationID ids.OrganizationID, extras *organizationExtras, flags includeFlags) error {
	if flags.quotas {
		if err := applyQuotas(ctx, item, organizationID, extras); err != nil {
			return err
		}
	}

	if flags.projects || flags.count {
		applyProjects(ctx, item, organizationID, extras, flags)
	}

	return nil
}

// includeOrganizationExtras fills the extras named by include on every item
// that the caller can inspect.
func (h *Handler) includeOrganizationExtras(ctx context.Context, items []openapi.OrganizationListItem, include []string) error {
	if len(items) == 0 || len(include) == 0 {
		return nil
	}

	flags := parseIncludeFlags(include)

	// Every ID comes from our own page and is a generated UUID.  A row that
	// still fails to parse keeps its base fields and gets no extras.  The
	// selector leaves it out, because one invalid value fails the whole list.
	parsed := make([]*ids.OrganizationID, len(items))
	pageIDs := make([]string, 0, len(items))

	for i := range items {
		organizationID, err := ids.ParseOrganizationID(items[i].Metadata.Id)
		if err != nil {
			continue
		}

		parsed[i] = &organizationID

		pageIDs = append(pageIDs, items[i].Metadata.Id)
	}

	if len(pageIDs) == 0 {
		return nil
	}

	extras, err := h.loadExtras(ctx, flags, pageIDs)
	if err != nil {
		return err
	}

	for i := range items {
		if parsed[i] == nil {
			continue
		}

		if err := applyExtras(ctx, &items[i], *parsed[i], extras, flags); err != nil {
			return err
		}
	}

	return nil
}
