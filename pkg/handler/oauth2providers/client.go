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

package oauth2providers

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

func (c *Client) get(ctx context.Context, namespace, name string) (*unikornv1.OAuth2Provider, error) {
	key := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}

	var provider unikornv1.OAuth2Provider
	if err := c.client.Get(ctx, key, &provider); err != nil {
		if kerrors.IsNotFound(err) {
			err = errorsv2.NewResourceMissingError("oauth2 provider").
				WithCause(err).
				Prefixed()

			return nil, err
		}

		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve oauth2 provider: %w", err).
			Prefixed()

		return nil, err
	}

	return &provider, nil
}

func convert(in *unikornv1.OAuth2Provider) *openapi.Oauth2ProviderRead {
	out := &openapi.Oauth2ProviderRead{
		Metadata: conversion.OrganizationScopedResourceReadMetadata(in, in.Spec.Tags),
		Spec: openapi.Oauth2ProviderSpec{
			ClientID: in.Spec.ClientID,
		},
	}

	if in.Spec.Type != nil {
		t := openapi.Oauth2ProviderType(*in.Spec.Type)
		out.Spec.Type = &t
	}

	/*
		// Only show sensitive details for organizations you are an admin of.
		if showDetails(permissions) {
			out.Spec.ClientSecret = in.Spec.ClientSecret
		}
	*/

	return out
}

func convertList(in *unikornv1.OAuth2ProviderList) openapi.Oauth2Providers {
	slices.SortStableFunc(in.Items, func(a, b unikornv1.OAuth2Provider) int {
		return strings.Compare(a.Name, b.Name)
	})

	out := make(openapi.Oauth2Providers, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i])
	}

	return out
}

func (c *Client) list(ctx context.Context, opts ...client.ListOption) (*unikornv1.OAuth2ProviderList, error) {
	var list unikornv1.OAuth2ProviderList
	if err := c.client.List(ctx, &list, opts...); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve oauth2 providers: %w", err).
			Prefixed()

		return nil, err
	}

	return &list, nil
}

func (c *Client) ListGlobal(ctx context.Context) (openapi.Oauth2Providers, error) {
	opts := []client.ListOption{
		&client.ListOptions{Namespace: c.namespace},
	}

	list, err := c.list(ctx, opts...)
	if err != nil {
		return nil, err
	}

	return convertList(list), nil
}

func (c *Client) List(ctx context.Context, organizationID string) (openapi.Oauth2Providers, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	opts := []client.ListOption{
		&client.ListOptions{Namespace: organization.Namespace},
	}

	list, err := c.list(ctx, opts...)
	if err != nil {
		return nil, err
	}

	return convertList(list), nil
}

func (c *Client) generate(ctx context.Context, organization *organizations.Meta, in *openapi.Oauth2ProviderWrite) (*unikornv1.OAuth2Provider, error) {
	out := &unikornv1.OAuth2Provider{
		ObjectMeta: conversion.NewObjectMetadata(&in.Metadata, organization.Namespace).WithOrganization(organization.ID).Get(),
		Spec: unikornv1.OAuth2ProviderSpec{
			Issuer:   in.Spec.Issuer,
			ClientID: in.Spec.ClientID,
		},
	}

	if err := common.SetIdentityMetadata(ctx, &out.ObjectMeta); err != nil {
		return nil, err
	}

	// TODO: always require this to be written.
	if in.Spec.ClientSecret != nil {
		out.Spec.ClientSecret = *in.Spec.ClientSecret
	}

	out.Spec.Tags = conversion.GenerateTagList(in.Metadata.Tags)

	return out, nil
}

func (c *Client) Create(ctx context.Context, organizationID string, request *openapi.Oauth2ProviderWrite) (*openapi.Oauth2ProviderRead, error) {
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
			WithCausef("failed to create oauth2 provider: %w", err).
			Prefixed()

		return nil, err
	}

	return convert(resource), nil
}

func (c *Client) Update(ctx context.Context, organizationID, providerID string, request *openapi.Oauth2ProviderWrite) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	current, err := c.get(ctx, organization.Namespace, providerID)
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
			WithCausef("failed to patch oauth2 provider: %w", err).
			Prefixed()
	}

	return nil
}

func (c *Client) Delete(ctx context.Context, organizationID, providerID string) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	resource := &unikornv1.OAuth2Provider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      providerID,
			Namespace: organization.Namespace,
		},
	}

	if err := c.client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errorsv2.NewResourceMissingError("oauth2 provider").
				WithCause(err).
				Prefixed()
		}

		return errorsv2.NewInternalError().
			WithCausef("failed to delete oauth2 provider: %w", err).
			Prefixed()
	}

	return nil
}
