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

package roles

import (
	"cmp"
	"context"
	"slices"

	"github.com/unikorn-cloud/core/pkg/server/conversion"
	errorsv2 "github.com/unikorn-cloud/core/pkg/server/v2/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

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

func convert(in unikornv1.Role) openapi.RoleRead {
	return openapi.RoleRead{
		Metadata: conversion.ResourceReadMetadata(&in, in.Spec.Tags),
	}
}

func convertList(in unikornv1.RoleList) openapi.Roles {
	var out openapi.Roles

	for _, resource := range in.Items {
		out = append(out, convert(resource))
	}

	slices.SortFunc(out, func(a, b openapi.RoleRead) int {
		return cmp.Compare(a.Metadata.Name, b.Metadata.Name)
	})

	return out
}

func (c *Client) List(ctx context.Context, organizationID string) (openapi.Roles, error) {
	var result unikornv1.RoleList

	if err := c.client.List(ctx, &result, &client.ListOptions{Namespace: c.namespace}); err != nil {
		err = errorsv2.NewInternalError().
			WithCausef("failed to retrieve roles: %w", err).
			Prefixed()

		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(role unikornv1.Role) bool {
		return role.Spec.Protected || rbac.AllowRole(ctx, &role, organizationID) != nil
	})

	return convertList(result), nil
}
