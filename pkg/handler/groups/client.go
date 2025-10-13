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

package groups

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Client struct {
	client    client.Client
	namespace string
}

func New(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

func convert(in *unikornv1.Group) *openapi.GroupRead {
	out := &openapi.GroupRead{
		Metadata: conversion.OrganizationScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.GroupSpec{
			RoleIDs:           openapi.StringList{},
			UserIDs:           &openapi.StringList{},
			Subjects:          &openapi.StringList{},
			ServiceAccountIDs: openapi.StringList{},
		},
	}

	if in.Spec.RoleIDs != nil {
		out.Spec.RoleIDs = in.Spec.RoleIDs
	}

	if in.Spec.UserIDs != nil {
		out.Spec.UserIDs = &in.Spec.UserIDs
	}

	if in.Spec.Subjects != nil {
		out.Spec.Subjects = &in.Spec.Subjects
	}

	if in.Spec.ServiceAccountIDs != nil {
		out.Spec.ServiceAccountIDs = in.Spec.ServiceAccountIDs
	}

	return out
}

func convertList(in *unikornv1.GroupList) openapi.Groups {
	slices.SortStableFunc(in.Items, func(a, b unikornv1.Group) int {
		return strings.Compare(a.Name, b.Name)
	})

	out := make(openapi.Groups, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i])
	}

	return out
}

func (c *Client) List(ctx context.Context, organizationID string) (openapi.Groups, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	result := &unikornv1.GroupList{}

	if err := c.client.List(ctx, result, &client.ListOptions{Namespace: organization.Namespace}); err != nil {
		return nil, errors.OAuth2ServerError("failed to list groups").WithError(err)
	}

	return convertList(result), nil
}

func (c *Client) get(ctx context.Context, organization *organizations.Meta, groupID string) (*unikornv1.Group, error) {
	result := &unikornv1.Group{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: organization.Namespace, Name: groupID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("failed to get group").WithError(err)
	}

	return result, nil
}

func (c *Client) Get(ctx context.Context, organizationID, groupID string) (*openapi.GroupRead, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	result, err := c.get(ctx, organization, groupID)
	if err != nil {
		return nil, err
	}

	return convert(result), nil
}

func (c *Client) populateSubjectsAndUserIDs(ctx context.Context, out *unikornv1.Group, organization *organizations.Meta, in *openapi.GroupWrite) error {
	// On the way in, we prioritise Subjects over UserIDs. If you provided subjects, those are used and the userIDs ignored.
	// If you provide UserIDs, they are converted to subjects, and both are stored.
	var subjects, userIDs openapi.StringList

	if in.Spec.Subjects != nil {
		// On the assumption that the caller understands Subjects, just use the subjects. This is a one-way step, since
		// we don't attempt to find OrganizationUser records and populate .UserIDs, so it'll be empty hereafter.
		subjects = *in.Spec.Subjects
	} else if in.Spec.UserIDs != nil {
		// On the assumption that the caller understands UserIDs,
		for _, userorgid := range *in.Spec.UserIDs {
			userIDs = append(userIDs, userorgid)

			var orguser unikornv1.OrganizationUser
			if err := c.client.Get(ctx, client.ObjectKey{Name: userorgid, Namespace: organization.Namespace}, &orguser); err != nil {
				return errors.OAuth2ServerError("failed to get organization member record").WithError(err)
			}

			userid := orguser.Labels[constants.UserLabel]

			var user unikornv1.User
			if err := c.client.Get(ctx, client.ObjectKey{Name: userid, Namespace: c.namespace}, &user); err != nil {
				return errors.OAuth2ServerError("failed to get user record").WithError(err)
			}

			subjects = append(subjects, user.Spec.Subject)
		}
	}

	out.Spec.Subjects = subjects
	out.Spec.UserIDs = userIDs

	return nil
}

func (c *Client) generate(ctx context.Context, organization *organizations.Meta, in *openapi.GroupWrite) (*unikornv1.Group, error) {
	// Validate roles exist.
	for _, roleID := range in.Spec.RoleIDs {
		var resource unikornv1.Role

		if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: roleID}, &resource); err != nil {
			if kerrors.IsNotFound(err) {
				return nil, errors.OAuth2InvalidRequest(fmt.Sprintf("role ID %s does not exist", roleID)).WithError(err)
			}

			return nil, errors.OAuth2ServerError("failed to validate role ID").WithError(err)
		}

		if resource.Spec.Protected {
			return nil, errors.HTTPForbidden("requested role is protected")
		}

		// Check that the user is allowed to grant the role, this closes a security
		// hole where a user can cause privilige escalation by just knowing the
		// elevated role ID.  As these are typically generated by hashing the name
		// guessing them is pretty trivial.
		if err := rbac.AllowRole(ctx, &resource, organization.ID); err != nil {
			return nil, errors.HTTPForbidden("requested role cannot be granted").WithError(err)
		}
	}

	// TODO: validate user and service account existence.
	out := &unikornv1.Group{
		ObjectMeta: conversion.NewObjectMetadata(&in.Metadata, organization.Namespace).WithOrganization(organization.ID).Get(),
		Spec: unikornv1.GroupSpec{
			Tags:              conversion.GenerateTagList(in.Metadata.Tags),
			RoleIDs:           in.Spec.RoleIDs,
			ServiceAccountIDs: in.Spec.ServiceAccountIDs,
		},
	}

	if err := c.populateSubjectsAndUserIDs(ctx, out, organization, in); err != nil {
		return nil, err
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, errors.OAuth2ServerError("failed to set identity metadata").WithError(err)
	}

	return out, nil
}

func (c *Client) Create(ctx context.Context, organizationID string, request *openapi.GroupWrite) (*openapi.GroupRead, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	resource, err := c.generate(ctx, organization, request)
	if err != nil {
		return nil, err
	}

	if err := c.client.Create(ctx, resource); err != nil {
		return nil, errors.OAuth2ServerError("failed to create group").WithError(err)
	}

	return convert(resource), nil
}

func (c *Client) Update(ctx context.Context, organizationID, groupID string, request *openapi.GroupWrite) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	current, err := c.get(ctx, organization, groupID)
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
		return errors.OAuth2ServerError("failed to patch group").WithError(err)
	}

	return nil
}

func (c *Client) Delete(ctx context.Context, organizationID, groupID string) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	// Projects have a "foreign key" into groups, so we need to remove that
	// association with the group that's about to be deleted.  Failure to
	// do so may cause RBAC problems otherwise.
	var projects unikornv1.ProjectList

	if err := c.client.List(ctx, &projects, &client.ListOptions{Namespace: organization.Namespace}); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("failed to list projects").WithError(err)
	}

	for i := range projects.Items {
		project := &projects.Items[i]

		if index := slices.Index(project.Spec.GroupIDs, groupID); index >= 0 {
			project.Spec.GroupIDs = slices.Delete(project.Spec.GroupIDs, index, index+1)

			if err := c.client.Update(ctx, project); err != nil {
				return errors.OAuth2ServerError("failed to update project").WithError(err)
			}
		}
	}

	resource := &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Name:      groupID,
			Namespace: organization.Namespace,
		},
	}

	if err := c.client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("failed to delete group").WithError(err)
	}

	return nil
}
