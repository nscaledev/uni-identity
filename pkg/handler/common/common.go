/*
Copyright 2024-2025 the Unikorn Authors.

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

package common

import (
	"context"
	"slices"

	"github.com/unikorn-cloud/core/pkg/constants"
	errorsv2 "github.com/unikorn-cloud/core/pkg/server/v2/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/principal"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Client wraps up control plane related management handling.
type Client struct {
	// client allows Kubernetes API access.
	client client.Client
}

// New returns a new client with required parameters.
func New(client client.Client) *Client {
	return &Client{
		client: client,
	}
}

func organizationSelector(organizationID string) labels.Selector {
	return labels.SelectorFromSet(labels.Set{
		constants.OrganizationLabel: organizationID,
	})
}

func projectSelector(organizationID, projectID string) labels.Selector {
	return labels.SelectorFromSet(labels.Set{
		constants.KindLabel:         constants.KindLabelValueProject,
		constants.OrganizationLabel: organizationID,
		constants.ProjectLabel:      projectID,
	})
}

// ProjectNamespace is shared by higher order services.
func ProjectNamespace(ctx context.Context, cli client.Client, organizationID, projectID string) (*corev1.Namespace, error) {
	opts := []client.ListOption{
		&client.ListOptions{
			LabelSelector: projectSelector(organizationID, projectID),
		},
	}

	var list corev1.NamespaceList
	if err := cli.List(ctx, &list, opts...); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve project namespaces: %w", err).
			Prefixed()

		return nil, err
	}

	if len(list.Items) == 0 {
		err := errorsv2.NewInternalError().
			WithSimpleCause("no project namespace found").
			Prefixed()

		return nil, err
	}

	if len(list.Items) > 1 {
		err := errorsv2.NewInternalError().
			WithSimpleCause("multiple project namespaces found").
			Prefixed()

		return nil, err
	}

	return &list.Items[0], nil
}

func (c *Client) ProjectNamespace(ctx context.Context, organizationID, projectID string) (*corev1.Namespace, error) {
	return ProjectNamespace(ctx, c.client, organizationID, projectID)
}

func (c *Client) GetQuota(ctx context.Context, organizationID string) (*unikornv1.Quota, bool, error) {
	quotaOpts := []client.ListOption{
		&client.ListOptions{
			LabelSelector: organizationSelector(organizationID),
		},
	}

	var quotaList unikornv1.QuotaList
	if err := c.client.List(ctx, &quotaList, quotaOpts...); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve quotas: %w", err).
			Prefixed()

		return nil, false, err
	}

	if len(quotaList.Items) > 1 {
		err := errorsv2.NewInternalError().
			WithSimpleCause("multiple quotas found").
			Prefixed()

		return nil, false, err
	}

	// We are going to lazily create the quota and any new quota items that come
	// into existence.
	quota := &unikornv1.Quota{}
	virtual := true

	if len(quotaList.Items) != 0 {
		quota = &quotaList.Items[0]
		virtual = false
	}

	var metadataList unikornv1.QuotaMetadataList
	if err := c.client.List(ctx, &metadataList); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve quota metadata: %w", err).
			Prefixed()

		return nil, false, err
	}

	names := make([]string, 0, len(metadataList.Items))

	for i := range metadataList.Items {
		meta := &metadataList.Items[i]

		names = append(names, meta.Name)

		isTargetQuota := func(q unikornv1.ResourceQuota) bool {
			return q.Kind == meta.Name
		}

		if slices.IndexFunc(quota.Spec.Quotas, isTargetQuota) >= 0 {
			continue
		}

		quota.Spec.Quotas = append(quota.Spec.Quotas, unikornv1.ResourceQuota{
			Kind:     meta.Name,
			Quantity: meta.Spec.Default,
		})
	}

	// And remove anything that's been retired.
	quota.Spec.Quotas = slices.DeleteFunc(quota.Spec.Quotas, func(q unikornv1.ResourceQuota) bool {
		return !slices.Contains(names, q.Kind)
	})

	return quota, virtual, nil
}

func (c *Client) GetAllocations(ctx context.Context, organizationID string) (*unikornv1.AllocationList, error) {
	opts := []client.ListOption{
		&client.ListOptions{
			LabelSelector: organizationSelector(organizationID),
		},
	}

	var list unikornv1.AllocationList
	if err := c.client.List(ctx, &list, opts...); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve allocations: %w", err).
			Prefixed()

		return nil, err
	}

	return &list, nil
}

// CheckQuotaConsistency by default loads up the organization's quota and all allocations and
// checks that the total of allocations does not exceed the quota.  If you pass in a quota
// argument, i.e. when updating the quotas, this will override the read from the organization.
// If you pass in an allocation, i.e. when creating or updating an allocation, this will be
// unioned with the organization's allocations, overriding an existing one if it exists.
func (c *Client) CheckQuotaConsistency(ctx context.Context, organizationID string, quota *unikornv1.Quota, allocation *unikornv1.Allocation) error {
	// Handle the default quota.
	if quota == nil {
		temp, _, err := c.GetQuota(ctx, organizationID)
		if err != nil {
			return err
		}

		quota = temp
	}

	allocations, err := c.GetAllocations(ctx, organizationID)
	if err != nil {
		return err
	}

	// Handle allocation union.
	if allocation != nil {
		isTargetAllocation := func(a unikornv1.Allocation) bool {
			return a.Name == allocation.Name
		}

		index := slices.IndexFunc(allocations.Items, isTargetAllocation)
		if index < 0 {
			allocations.Items = append(allocations.Items, *allocation)
		} else {
			allocations.Items[index] = *allocation
		}
	}

	return checkQuotaConsistency(quota, allocations)
}

func checkQuotaConsistency(quota *unikornv1.Quota, allocations *unikornv1.AllocationList) error {
	capacities := make(map[string]int64)

	for i := range quota.Spec.Quotas {
		quota := &quota.Spec.Quotas[i]

		capacities[quota.Kind] = quota.Quantity.Value()
	}

	totals := make(map[string]int64)

	for i := range allocations.Items {
		allocation := &allocations.Items[i]

		for j := range allocation.Spec.Allocations {
			resource := &allocation.Spec.Allocations[j]

			totals[resource.Kind] += resource.Committed.Value() + resource.Reserved.Value()
		}
	}

	for resource, desired := range totals {
		if capacity, ok := capacities[resource]; ok && desired > capacity {
			return errorsv2.NewQuotaExhaustedError(resource, desired, capacity).Prefixed()
		}
	}

	return nil
}

// SetIdentityMetadata sets identity specific metadata on a resource during generation.
func SetIdentityMetadata(ctx context.Context, meta *metav1.ObjectMeta) error {
	if err := setIdentityMetadata(ctx, meta); err != nil {
		return errorsv2.NewInternalError().
			WithCausef("failed to set object metadata: %w", err).
			Prefixed()
	}

	return nil
}

func setIdentityMetadata(ctx context.Context, meta *metav1.ObjectMeta) error {
	info, err := authorization.FromContext(ctx)
	if err != nil {
		return err
	}

	if meta.Annotations == nil {
		meta.Annotations = map[string]string{}
	}

	meta.Annotations[constants.CreatorAnnotation] = info.Userinfo.Sub

	principal, err := principal.FromContext(ctx)
	if err != nil {
		return err
	}

	meta.Annotations[constants.CreatorPrincipalAnnotation] = principal.Actor

	if principal.OrganizationID != "" {
		if meta.Labels == nil {
			meta.Labels = map[string]string{}
		}

		meta.Labels[constants.OrganizationPrincipalLabel] = principal.OrganizationID
	}

	if principal.ProjectID != "" {
		if meta.Labels == nil {
			meta.Labels = map[string]string{}
		}

		meta.Labels[constants.ProjectPrincipalLabel] = principal.ProjectID
	}

	return nil
}

// IdentityMetadataMutator is called on an update and preserves identity information.
func IdentityMetadataMutator(required, current metav1.Object) error {
	// Do annotations first...
	req := required.GetAnnotations()
	cur := current.GetAnnotations()

	// When we generate an updated resource, the creator is actually the modifier.
	if v, ok := req[constants.CreatorAnnotation]; ok {
		req[constants.ModifierAnnotation] = v
	}

	if v, ok := req[constants.CreatorPrincipalAnnotation]; ok {
		req[constants.ModifierPrincipalAnnotation] = v
	}

	// And the original creator needs to be preserved.
	if v, ok := cur[constants.CreatorAnnotation]; ok {
		req[constants.CreatorAnnotation] = v
	}

	if v, ok := cur[constants.CreatorPrincipalAnnotation]; ok {
		req[constants.CreatorPrincipalAnnotation] = v
	}

	required.SetAnnotations(req)

	// Then labels...
	req = required.GetLabels()
	cur = current.GetLabels()

	// The principal organization and project are intedned to be immutable, this should
	// be enforced by a validating admission policy for each service's custom resource types.
	if v, ok := cur[constants.OrganizationPrincipalLabel]; ok {
		req[constants.OrganizationPrincipalLabel] = v
	} else {
		delete(req, constants.OrganizationPrincipalLabel)
	}

	if v, ok := cur[constants.ProjectPrincipalLabel]; ok {
		req[constants.ProjectPrincipalLabel] = v
	} else {
		delete(req, constants.ProjectPrincipalLabel)
	}

	required.SetLabels(req)

	return nil
}
