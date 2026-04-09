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

package roles

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	"github.com/unikorn-cloud/core/pkg/server/conversion"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/ids"
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

func convert(in unikornv1.Role) (openapi.RoleRead, error) {
	metadata, err := conversion.ResourceReadMetadata(&in, in.Spec.Tags)
	if err != nil {
		return openapi.RoleRead{}, fmt.Errorf("%w: failed to convert role %s/%s", err, in.Namespace, in.Name)
	}

	out := openapi.RoleRead{
		Metadata: metadata,
	}

	return out, nil
}

func convertList(in unikornv1.RoleList) (openapi.Roles, error) {
	var out openapi.Roles

	for _, resource := range in.Items {
		item, err := convert(resource)
		if err != nil {
			return nil, err
		}

		out = append(out, item)
	}

	slices.SortFunc(out, func(a, b openapi.RoleRead) int {
		return cmp.Compare(a.Metadata.Name, b.Metadata.Name)
	})

	return out, nil
}

func (c *Client) List(ctx context.Context, organizationID ids.OrganizationID) (openapi.Roles, error) {
	var result unikornv1.RoleList

	if err := c.client.List(ctx, &result, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(role unikornv1.Role) bool {
		return role.Spec.Protected || rbac.AllowRole(ctx, &role, organizationID) != nil
	})

	return convertList(result)
}
