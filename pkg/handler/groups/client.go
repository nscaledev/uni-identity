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
	"slices"
	"strings"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	errorsv2 "github.com/unikorn-cloud/core/pkg/server/v2/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Client struct {
	client    client.Client
	namespace string
	issuer    common.IssuerValue
}

func New(client client.Client, namespace string, internalIssuer common.IssuerValue) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
		issuer:    internalIssuer,
	}
}

func convert(in *unikornv1.Group) *openapi.GroupRead {
	out := &openapi.GroupRead{
		Metadata: conversion.OrganizationScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.GroupSpec{
			RoleIDs:           openapi.StringList{},
			UserIDs:           &openapi.StringList{},
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
		subjects := make([]openapi.Subject, len(in.Spec.Subjects))
		for i, insub := range in.Spec.Subjects {
			subjects[i].Id = insub.ID
			subjects[i].Issuer = insub.Issuer

			if insub.Email != "" {
				subjects[i].Email = ptr.To(insub.Email)
			}
		}

		out.Spec.Subjects = &subjects
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

	opts := []client.ListOption{
		&client.ListOptions{Namespace: organization.Namespace},
	}

	var list unikornv1.GroupList
	if err := c.client.List(ctx, &list, opts...); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve groups: %w", err).
			Prefixed()

		return nil, err
	}

	return convertList(&list), nil
}

func (c *Client) get(ctx context.Context, namespace, name string) (*unikornv1.Group, error) {
	key := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}

	var group unikornv1.Group
	if err := c.client.Get(ctx, key, &group); err != nil {
		if kerrors.IsNotFound(err) {
			err = errorsv2.NewResourceMissingError("group").
				WithCause(err).
				Prefixed()

			return nil, err
		}

		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve group: %w", err).
			Prefixed()

		return nil, err
	}

	return &group, nil
}

func (c *Client) Get(ctx context.Context, organizationID, groupID string) (*openapi.GroupRead, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	result, err := c.get(ctx, organization.Namespace, groupID)
	if err != nil {
		return nil, err
	}

	return convert(result), nil
}

func generateSubjects(in []openapi.Subject) []unikornv1.GroupSubject {
	subjects := make([]unikornv1.GroupSubject, len(in))
	for i, insub := range in {
		subjects[i].ID = insub.Id
		subjects[i].Issuer = insub.Issuer

		if insub.Email != nil {
			subjects[i].Email = *insub.Email
		}
	}

	return subjects
}

// findUserBySubject finds a User resource by subject field.
func (c *Client) findUserBySubject(ctx context.Context, subject string) (*unikornv1.User, error) {
	opts := []client.ListOption{
		&client.ListOptions{Namespace: c.namespace},
	}

	var list unikornv1.UserList
	if err := c.client.List(ctx, &list, opts...); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve users: %w", err).
			Prefixed()

		return nil, err
	}

	for _, user := range list.Items {
		if user.Spec.Subject == subject {
			return &user, nil
		}
	}

	err := errorsv2.NewInvalidRequestError().
		WithSimpleCausef("no user found with subject %s", subject).
		WithErrorDescription("One of the specified subjects is invalid or cannot be resolved.").
		Prefixed()

	return nil, err
}

// findOrgUserByUserID finds an OrganizationUser in an org by the user ID label.
func (c *Client) findOrgUserByUserID(ctx context.Context, namespace, userID string) (*unikornv1.OrganizationUser, error) {
	opts := []client.ListOption{
		&client.ListOptions{
			Namespace: namespace,
			LabelSelector: labels.SelectorFromSet(labels.Set{
				constants.UserLabel: userID,
			}),
		},
	}

	var list unikornv1.OrganizationUserList
	if err := c.client.List(ctx, &list, opts...); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve organization users: %w", err).
			Prefixed()

		return nil, err
	}

	if len(list.Items) == 0 {
		err := errorsv2.NewResourceMissingError("organization user").Prefixed()
		return nil, err
	}

	if len(list.Items) > 1 {
		err := errorsv2.NewInternalError().
			WithSimpleCause("multiple organization users found").
			Prefixed()

		return nil, err
	}

	return &list.Items[0], nil
}

// subjectsToUserIDs converts internal subjects to UserIDs.
func (c *Client) subjectsToUserIDs(ctx context.Context, namespace string, subjects []unikornv1.GroupSubject) ([]string, error) {
	var userIDs []string //nolint:prealloc

	for _, subject := range subjects {
		if subject.Issuer != c.issuer.URL {
			continue // Skip external subjects
		}

		user, err := c.findUserBySubject(ctx, subject.ID)
		if err != nil {
			return nil, err
		}

		orgUser, err := c.findOrgUserByUserID(ctx, namespace, user.Name)
		if err != nil {
			return nil, err
		}

		userIDs = append(userIDs, orgUser.Name)
	}

	return userIDs, nil
}

// userIDsToSubjects converts UserIDs to subjects.
func (c *Client) userIDsToSubjects(ctx context.Context, namespace string, organizationUserIDs []string) ([]unikornv1.GroupSubject, error) {
	subjects := make([]unikornv1.GroupSubject, 0, len(organizationUserIDs))

	for _, organizationUserID := range organizationUserIDs {
		organizationUserKey := client.ObjectKey{
			Namespace: namespace,
			Name:      organizationUserID,
		}

		var organizationUser unikornv1.OrganizationUser
		if err := c.client.Get(ctx, organizationUserKey, &organizationUser); err != nil {
			if kerrors.IsNotFound(err) {
				err = errorsv2.NewInvalidRequestError().
					WithCausef("no organization user found: %w", err).
					WithErrorDescription("One of the specified organization IDs is invalid or cannot be resolved.").
					Prefixed()

				return nil, err
			}

			err = errorsv2.NewInternalError().
				WithCausef("failed to retrieve organization user: %w", err).
				Prefixed()

			return nil, err
		}

		userKey := client.ObjectKey{
			Namespace: c.namespace,
			Name:      organizationUser.Labels[constants.UserLabel],
		}

		var user unikornv1.User
		if err := c.client.Get(ctx, userKey, &user); err != nil {
			if kerrors.IsNotFound(err) {
				err = errorsv2.NewInvalidRequestError().
					WithCausef("no user found: %w", err).
					WithErrorDescription("One of the specified organization IDs is invalid or cannot be resolved.").
					Prefixed()

				return nil, err
			}

			err = errorsv2.NewInternalError().
				WithCausef("failed to retrieve user: %w", err).
				Prefixed()

			return nil, err
		}

		subjects = append(subjects, unikornv1.GroupSubject{
			ID:     user.Spec.Subject,
			Email:  user.Spec.Subject,
			Issuer: c.issuer.URL,
		})
	}

	return subjects, nil
}

// populateSubjectsAndUserIDs takes the API request and populates the UserIDs and Subjects fields of a Group. This elides
// between the old way of setting groups (userIDs pointing to OrganizationUser records), and the new way (Subjects pointing to
// user records *somewhere*).
// If you provide **subjects**, the func converts subjects with the internal issuer to UserIDs as well, allowing
// both old and new clients to coexist during migration.
// If you provide **UserIDs**, this func assumes you are an old-style client: the given UserIDs are converted to subjects,
// and both subjects and userIDs are stored.
// Providing both Subjects and UserIDs is an error.
func (c *Client) populateSubjectsAndUserIDs(ctx context.Context, out *unikornv1.Group, organization *organizations.Meta, in *openapi.GroupWrite) error {
	var (
		subjects []unikornv1.GroupSubject
		userIDs  []string
		err      error
	)

	if in.Spec.Subjects != nil && in.Spec.UserIDs != nil {
		return errorsv2.NewInvalidRequestError().
			WithSimpleCause("both subjects and userIDs provided").
			WithErrorDescription("The request must include either 'subjects' or 'userIDs', but not both.").
			Prefixed()
	}

	if in.Spec.Subjects != nil {
		subjects = generateSubjects(*in.Spec.Subjects)

		userIDs, err = c.subjectsToUserIDs(ctx, organization.Namespace, subjects)
		if err != nil {
			return err
		}
	} else if in.Spec.UserIDs != nil {
		userIDs = *in.Spec.UserIDs

		subjects, err = c.userIDsToSubjects(ctx, organization.Namespace, userIDs)
		if err != nil {
			return err
		}
	}

	out.Spec.Subjects = subjects
	out.Spec.UserIDs = userIDs

	return nil
}

func (c *Client) generate(ctx context.Context, organization *organizations.Meta, in *openapi.GroupWrite) (*unikornv1.Group, error) {
	// Validate roles exist.
	for _, roleID := range in.Spec.RoleIDs {
		key := client.ObjectKey{
			Namespace: organization.Namespace,
			Name:      roleID,
		}

		var role unikornv1.Role
		if err := c.client.Get(ctx, key, &role); err != nil {
			if kerrors.IsNotFound(err) {
				err = errorsv2.NewInvalidRequestError().
					WithCausef("no role found: %w", err).
					WithErrorDescription("One of the specified role IDs is invalid or cannot be resolved.").
					Prefixed()

				return nil, err
			}

			err = errorsv2.NewInternalError().
				WithCausef("failed to retrieve role: %w", err).
				Prefixed()

			return nil, err
		}

		if role.Spec.Protected {
			err := errorsv2.NewInvalidRequestError().
				WithSimpleCause("requested role is protected").
				WithErrorDescription("One of the specified role IDs is invalid or cannot be resolved.").
				Prefixed()

			return nil, err
		}

		// Check that the user is allowed to grant the role, this closes a security
		// hole where a user can cause privilege escalation by just knowing the
		// elevated role ID.  As these are typically generated by hashing the name
		// guessing them is pretty trivial.
		if err := rbac.AllowRole(ctx, &role, organization.ID); err != nil {
			err = errorsv2.NewInvalidRequestError().
				WithCausef("requested role cannot be granted: %w", err).
				WithErrorDescription("One of the specified role IDs is invalid or cannot be resolved.").
				Prefixed()

			return nil, err
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
		return nil, err
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
		err = errorsv2.NewInternalError().
			WithCausef("failed to create group: %w", err).
			Prefixed()

		return nil, err
	}

	return convert(resource), nil
}

func (c *Client) Update(ctx context.Context, organizationID, groupID string, request *openapi.GroupWrite) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	current, err := c.get(ctx, organization.Namespace, groupID)
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
			WithCausef("failed to patch group: %w", err).
			Prefixed()
	}

	return nil
}

func (c *Client) Delete(ctx context.Context, organizationID, groupID string) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	opts := []client.ListOption{
		&client.ListOptions{Namespace: organization.Namespace},
	}

	// Projects have a "foreign key" into groups, so we need to remove that
	// association with the group that's about to be deleted.  Failure to
	// do so may cause RBAC problems otherwise.
	var list unikornv1.ProjectList
	if err := c.client.List(ctx, &list, opts...); err != nil {
		return errorsv2.NewInternalError().
			WithCausef("failed to retrieve projects: %w", err).
			Prefixed()
	}

	for _, project := range list.Items {
		index := slices.Index(project.Spec.GroupIDs, groupID)
		if index < 0 {
			continue
		}

		project.Spec.GroupIDs = slices.Delete(project.Spec.GroupIDs, index, index+1)

		if err := c.client.Update(ctx, &project); err != nil {
			return errorsv2.NewInternalError().
				WithCausef("failed to update project: %w", err).
				Prefixed()
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
