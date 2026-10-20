/*
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

package aggregation

import (
	"context"
	"fmt"
	"maps"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Resolve sets Computed on each role in place; roles must be the caller's copies of every role in the namespace.
// Every decision on an aggregating role uses this, never status.
func Resolve(roles map[string]*unikornv1.Role) {
	results := Compute(roles)

	for id, role := range roles {
		if !role.IsAggregating() {
			continue
		}

		computed := &unikornv1.ComputedAggregation{}

		if result := results[id]; result != nil {
			computed.Scopes = result.EffectiveScopes
			computed.Available = result.Available.Status == corev1.ConditionTrue
			computed.Sources = result.AggregatedFrom
		}

		role.Computed = computed
	}
}

// ResolveRole resolves one role in place, listing its namespace only if it aggregates.
func ResolveRole(ctx context.Context, cli client.Client, role *unikornv1.Role) error {
	return NewResolver(cli, role.Namespace).Resolve(ctx, role)
}

// Resolver lists a namespace's roles at most once per request. It is not safe for concurrent use.
type Resolver struct {
	cli       client.Client
	namespace string
	roles     map[string]*unikornv1.Role
}

// NewResolver returns a Resolver for roles in namespace.
func NewResolver(cli client.Client, namespace string) *Resolver {
	return &Resolver{cli: cli, namespace: namespace}
}

// Resolve resolves one role in place. If the list fails the role holds nothing (fail closed).
func (r *Resolver) Resolve(ctx context.Context, role *unikornv1.Role) error {
	if !role.IsAggregating() {
		return nil
	}

	if r.roles == nil {
		list := &unikornv1.RoleList{}

		if err := r.cli.List(ctx, list, client.InNamespace(r.namespace)); err != nil {
			role.Computed = &unikornv1.ComputedAggregation{}

			return fmt.Errorf("listing roles to resolve role %s: %w", role.Name, err)
		}

		roles := make(map[string]*unikornv1.Role, len(list.Items))

		for i := range list.Items {
			roles[list.Items[i].Name] = &list.Items[i]
		}

		r.roles = roles
	}

	roles := maps.Clone(r.roles)
	roles[role.Name] = role

	Resolve(roles)

	return nil
}
