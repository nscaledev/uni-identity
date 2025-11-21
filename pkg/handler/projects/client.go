/*
Copyright 2022-2024 EscherCloud.
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

package projects

import (
	"context"
	"slices"
	"strings"

	"github.com/unikorn-cloud/core/pkg/server/conversion"
	errorsv2 "github.com/unikorn-cloud/core/pkg/server/v2/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// Client wraps up project related management handling.
type Client struct {
	// client allows Kubernetes API access.
	client    client.Client
	namespace string
}

// New returns a new client with required parameters.
func New(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

func convert(in *unikornv1.Project) *openapi.ProjectRead {
	out := &openapi.ProjectRead{
		Metadata: conversion.OrganizationScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.ProjectSpec{
			GroupIDs: openapi.GroupIDs{},
		},
	}

	if in.Spec.GroupIDs != nil {
		out.Spec.GroupIDs = in.Spec.GroupIDs
	}

	return out
}

func convertList(in *unikornv1.ProjectList) openapi.Projects {
	out := make(openapi.Projects, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i])
	}

	return out
}

func (c *Client) List(ctx context.Context, organizationID string) (openapi.Projects, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	opts := []client.ListOption{
		&client.ListOptions{Namespace: organization.Namespace},
	}

	var list unikornv1.ProjectList
	if err := c.client.List(ctx, &list, opts...); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve projects: %w", err).
			Prefixed()

		return nil, err
	}

	slices.SortStableFunc(list.Items, func(a, b unikornv1.Project) int {
		return strings.Compare(a.Name, b.Name)
	})

	return convertList(&list), nil
}

func (c *Client) get(ctx context.Context, namespace, name string) (*unikornv1.Project, error) {
	key := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}

	var project unikornv1.Project
	if err := c.client.Get(ctx, key, &project); err != nil {
		if kerrors.IsNotFound(err) {
			err = errorsv2.NewResourceMissingError("project").
				WithCause(err).
				Prefixed()

			return nil, err
		}

		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve project: %w", err).
			Prefixed()

		return nil, err
	}

	return &project, nil
}

func (c *Client) Get(ctx context.Context, organizationID, projectID string) (*openapi.ProjectRead, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	result, err := c.get(ctx, organization.Namespace, projectID)
	if err != nil {
		return nil, err
	}

	return convert(result), nil
}

func (c *Client) generate(ctx context.Context, organization *organizations.Meta, in *openapi.ProjectWrite) (*unikornv1.Project, error) {
	out := &unikornv1.Project{
		ObjectMeta: conversion.NewObjectMetadata(&in.Metadata, organization.Namespace).WithOrganization(organization.ID).Get(),
		Spec: unikornv1.ProjectSpec{
			Tags:     conversion.GenerateTagList(in.Metadata.Tags),
			GroupIDs: in.Spec.GroupIDs,
		},
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, err
	}

	for _, groupID := range in.Spec.GroupIDs {
		key := client.ObjectKey{
			Namespace: organization.Namespace,
			Name:      groupID,
		}

		var group unikornv1.Group
		if err := c.client.Get(ctx, key, &group); err != nil {
			if kerrors.IsNotFound(err) {
				err = errorsv2.NewInvalidRequestError().
					WithCausef("no group found: %w", err).
					WithErrorDescription("One of the specified group IDs is invalid or cannot be resolved.").
					Prefixed()

				return nil, err
			}

			err = errorsv2.NewInternalError().
				WithCausef("failed to retrieve group: %w", err).
				Prefixed()

			return nil, err
		}
	}

	return out, nil
}

// Create creates the implicit project identified by the JTW claims.
func (c *Client) Create(ctx context.Context, organizationID string, request *openapi.ProjectWrite) (*openapi.ProjectRead, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	resource, err := c.generate(ctx, organization, request)
	if err != nil {
		return nil, err
	}

	if err := c.client.Create(ctx, resource); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to create project: %w", err).
			Prefixed()

		return nil, err
	}

	return convert(resource), nil
}

func (c *Client) Update(ctx context.Context, organizationID, projectID string, request *openapi.ProjectWrite) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	current, err := c.get(ctx, organization.Namespace, projectID)
	if err != nil {
		return err
	}

	required, err := c.generate(ctx, organization, request)
	if err != nil {
		return err
	}

	if err := conversion.UpdateObjectMetadata(required, current, common.IdentityMetadataMutator); err != nil {
		return err
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return errorsv2.NewInternalError().
			WithCausef("failed to patch project: %w", err).
			Prefixed()
	}

	return nil
}

// Delete deletes the project.
func (c *Client) Delete(ctx context.Context, organizationID, projectID string) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	project := &unikornv1.Project{
		ObjectMeta: metav1.ObjectMeta{
			Name:      projectID,
			Namespace: organization.Namespace,
		},
	}

	if err := c.client.Delete(ctx, project); err != nil {
		if kerrors.IsNotFound(err) {
			return errorsv2.NewResourceMissingError("group").
				WithCause(err).
				Prefixed()
		}

		return errorsv2.NewInternalError().
			WithCausef("failed to delete group: %w", err).
			Prefixed()
	}

	return nil
}

// ReferenceCreate adds a external reference to the project that blocks deletion
// until it has been removed.
func (c *Client) ReferenceCreate(ctx context.Context, organizationID, projectID, reference string) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	resource, err := c.get(ctx, organization.Namespace, projectID)
	if err != nil {
		return err
	}

	if resource.DeletionTimestamp != nil {
		return errorsv2.NewConflictError().
			WithSimpleCause("project is being deleted").
			WithErrorDescription("The project is being deleted and cannot be modified.").
			Prefixed()
	}

	if ok := controllerutil.AddFinalizer(resource, reference); !ok {
		return nil
	}

	if err := c.client.Update(ctx, resource); err != nil {
		return errorsv2.NewInternalError().
			WithCausef("failed to update project: %w", err).
			Prefixed()
	}

	return nil
}

// ReferenceDelete removes an external reference from the project.
func (c *Client) ReferenceDelete(ctx context.Context, organizationID, projectID, reference string) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	resource, err := c.get(ctx, organization.Namespace, projectID)
	if err != nil {
		return err
	}

	if ok := controllerutil.RemoveFinalizer(resource, reference); !ok {
		return nil
	}

	if err := c.client.Update(ctx, resource); err != nil {
		return errorsv2.NewInternalError().
			WithCausef("failed to update project: %w", err).
			Prefixed()
	}

	return nil
}
