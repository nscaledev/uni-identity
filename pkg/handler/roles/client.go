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

func convert(in unikornv1.Role, grantable bool) openapi.RoleRead {
	out := openapi.RoleRead{
		Metadata:  conversion.ResourceReadMetadata(&in, in.Spec.Tags),
		Grantable: grantable,
	}

	return out
}

func convertList(ctx context.Context, in unikornv1.RoleList, organizationID ids.OrganizationID) openapi.Roles {
	// Allocated rather than declared nil: the schema types this response as a
	// non-nullable array, and a nil slice marshals to null, which response
	// validation rejects.
	out := make(openapi.Roles, 0, len(in.Items))

	for _, resource := range in.Items {
		grantable := rbac.AllowRole(ctx, &resource, organizationID) == nil

		out = append(out, convert(resource, grantable))
	}

	slices.SortFunc(out, func(a, b openapi.RoleRead) int {
		return cmp.Compare(a.Metadata.Name, b.Metadata.Name)
	})

	return out
}

func (c *Client) List(ctx context.Context, organizationID ids.OrganizationID) (openapi.Roles, error) {
	var result unikornv1.RoleList

	if err := c.client.List(ctx, &result, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return nil, err
	}

	// Protected roles are internal and never exposed.  Ungrantable roles ARE
	// exposed (grantable: false) so clients can resolve and display every
	// role a group references; omitting them invites clients to round-trip
	// a group without a role they cannot see, silently revoking it.  These
	// are two different reasons for absence and must not share a filter.
	result.Items = slices.DeleteFunc(result.Items, func(role unikornv1.Role) bool {
		return role.Spec.Protected
	})

	return convertList(ctx, result, organizationID), nil
}
