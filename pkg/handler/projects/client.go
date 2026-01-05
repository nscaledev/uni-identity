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

package projects

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
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

	var result unikornv1.ProjectList

	if err := c.client.List(ctx, &result, &client.ListOptions{Namespace: organization.Namespace}); err != nil {
		return nil, err
	}

	slices.SortStableFunc(result.Items, func(a, b unikornv1.Project) int {
		return strings.Compare(a.Name, b.Name)
	})

	return convertList(&result), nil
}

func (c *Client) get(ctx context.Context, organization *organizations.Meta, projectID string) (*unikornv1.Project, error) {
	result := &unikornv1.Project{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: organization.Namespace, Name: projectID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("failed to get project").WithError(err)
	}

	return result, nil
}

func (c *Client) Get(ctx context.Context, organizationID, projectID string) (*openapi.ProjectRead, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	result, err := c.get(ctx, organization, projectID)
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
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	for _, groupID := range in.Spec.GroupIDs {
		var resource unikornv1.Group

		if err := c.client.Get(ctx, client.ObjectKey{Namespace: organization.Namespace, Name: groupID}, &resource); err != nil {
			if kerrors.IsNotFound(err) {
				return nil, errors.OAuth2InvalidRequest(fmt.Sprintf("group ID %s does not exist", groupID)).WithError(err)
			}

			return nil, errors.OAuth2ServerError("failed to validate group ID").WithError(err)
		}
	}

	return out, nil
}

// Create creates the implicit project indentified by the JTW claims.
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
		return nil, errors.OAuth2ServerError("failed to create project").WithError(err)
	}

	return convert(resource), nil
}

func (c *Client) Update(ctx context.Context, organizationID, projectID string, request *openapi.ProjectWrite) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	current, err := c.get(ctx, organization, projectID)
	if err != nil {
		return err
	}

	required, err := c.generate(ctx, organization, request)
	if err != nil {
		return err
	}

	if err := conversion.UpdateObjectMetadata(required, current, common.IdentityMetadataMutator); err != nil {
		return errors.OAuth2ServerError("failed to merge metadata").WithError(err)
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return errors.OAuth2ServerError("failed to patch project").WithError(err)
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
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("failed to delete project").WithError(err)
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

	resource, err := c.get(ctx, organization, projectID)
	if err != nil {
		return err
	}

	if resource.DeletionTimestamp != nil {
		return errors.OAuth2InvalidRequest("unable to add reference, resource is being deleted")
	}

	if ok := controllerutil.AddFinalizer(resource, reference); !ok {
		return nil
	}

	if err := c.client.Update(ctx, resource); err != nil {
		return errors.OAuth2ServerError("failed to update project").WithError(err)
	}

	return nil
}

// ReferenceDelete removes an external reference from the project.
func (c *Client) ReferenceDelete(ctx context.Context, organizationID, projectID, reference string) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	resource, err := c.get(ctx, organization, projectID)
	if err != nil {
		return err
	}

	if ok := controllerutil.RemoveFinalizer(resource, reference); !ok {
		return nil
	}

	if err := c.client.Update(ctx, resource); err != nil {
		return errors.OAuth2ServerError("failed to update project").WithError(err)
	}

	return nil
}
