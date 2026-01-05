/*
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

package common

import (
	"context"
	"fmt"
	"slices"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/principal"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

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

func organizationSelector(organizationID string) (labels.Selector, error) {
	organizationIDRequirement, err := labels.NewRequirement(constants.OrganizationLabel, selection.Equals, []string{organizationID})
	if err != nil {
		return labels.Nothing(), err
	}

	return labels.NewSelector().Add(*organizationIDRequirement), nil
}

func projectSelector(organizationID, projectID string) (labels.Selector, error) {
	kindRequirement, err := labels.NewRequirement(constants.KindLabel, selection.Equals, []string{constants.KindLabelValueProject})
	if err != nil {
		return labels.Nothing(), err
	}

	organizationIDRequirement, err := labels.NewRequirement(constants.OrganizationLabel, selection.Equals, []string{organizationID})
	if err != nil {
		return labels.Nothing(), err
	}

	projectIDRequirement, err := labels.NewRequirement(constants.ProjectLabel, selection.Equals, []string{projectID})
	if err != nil {
		return labels.Nothing(), err
	}

	return labels.NewSelector().Add(*kindRequirement, *organizationIDRequirement, *projectIDRequirement), nil
}

// ProjectNamespace is shared by higher order services.
func ProjectNamespace(ctx context.Context, cli client.Client, organizationID, projectID string) (*corev1.Namespace, error) {
	selector, err := projectSelector(organizationID, projectID)
	if err != nil {
		return nil, err
	}

	options := &client.ListOptions{
		LabelSelector: selector,
	}

	var resources corev1.NamespaceList

	if err := cli.List(ctx, &resources, options); err != nil {
		return nil, err
	}

	if len(resources.Items) != 1 {
		return nil, fmt.Errorf("%w: expected to find 1 project namespace", coreerrors.ErrConsistency)
	}

	return &resources.Items[0], nil
}

func (c *Client) ProjectNamespace(ctx context.Context, organizationID, projectID string) (*corev1.Namespace, error) {
	return ProjectNamespace(ctx, c.client, organizationID, projectID)
}

func (c *Client) GetQuota(ctx context.Context, organizationID string) (*unikornv1.Quota, bool, error) {
	selector, err := organizationSelector(organizationID)
	if err != nil {
		return nil, false, err
	}

	options := &client.ListOptions{
		LabelSelector: selector,
	}

	var resources unikornv1.QuotaList

	if err := c.client.List(ctx, &resources, options); err != nil {
		return nil, false, err
	}

	if len(resources.Items) > 1 {
		return nil, false, fmt.Errorf("%w: expected to find 1 organization quota", coreerrors.ErrConsistency)
	}

	// We are going to lazily create the quota and any new quota items that come
	// into existence.
	var quota *unikornv1.Quota

	var virtual bool

	if len(resources.Items) == 0 {
		quota = &unikornv1.Quota{}

		virtual = true
	} else {
		quota = &resources.Items[0]
	}

	metadata := &unikornv1.QuotaMetadataList{}

	if err := c.client.List(ctx, metadata, &client.ListOptions{}); err != nil {
		return nil, false, err
	}

	names := make([]string, len(metadata.Items))

	for i, meta := range metadata.Items {
		names[i] = meta.Name

		findQuota := func(q unikornv1.ResourceQuota) bool {
			return q.Kind == meta.Name
		}

		if index := slices.IndexFunc(quota.Spec.Quotas, findQuota); index >= 0 {
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
	selector, err := organizationSelector(organizationID)
	if err != nil {
		return nil, err
	}

	options := &client.ListOptions{
		LabelSelector: selector,
	}

	var resources unikornv1.AllocationList

	if err := c.client.List(ctx, &resources, options); err != nil {
		return nil, err
	}

	return &resources, nil
}

// CheckQuotaConsistency by default loads up the organization's quota and all allocations and
// checks that the total of alloocations does not exceed the quota.  If you pass in a quota
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
		find := func(a unikornv1.Allocation) bool {
			return a.Name == allocation.Name
		}

		index := slices.IndexFunc(allocations.Items, find)
		if index < 0 {
			allocations.Items = append(allocations.Items, *allocation)
		} else {
			allocations.Items[index] = *allocation
		}
	}

	return checkQuotaConsistency(quota, allocations)
}

func checkQuotaConsistency(quota *unikornv1.Quota, allocations *unikornv1.AllocationList) error {
	capacities := map[string]int64{}

	for i := range quota.Spec.Quotas {
		quota := &quota.Spec.Quotas[i]

		capacities[quota.Kind] = quota.Quantity.Value()
	}

	totals := map[string]int64{}

	for i := range allocations.Items {
		allocation := &allocations.Items[i]

		for j := range allocation.Spec.Allocations {
			resource := &allocation.Spec.Allocations[j]

			totals[resource.Kind] += resource.Committed.Value() + resource.Reserved.Value()
		}
	}

	for k, v := range totals {
		if capacity, ok := capacities[k]; ok && v > capacity {
			return fmt.Errorf("%w: total allocation of %d would exceed quota limit of %d", coreerrors.ErrConsistency, v, capacity)
		}
	}

	return nil
}

// SetIdentityMetadata sets identity specific metadata on a resource during generation.
func SetIdentityMetadata(ctx context.Context, meta *metav1.ObjectMeta) error {
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
