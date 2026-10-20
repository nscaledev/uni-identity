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

// Resolve works out, live, what every aggregating role in roles holds, and
// sets it on each role's Computed field in place.  roles is keyed by role ID,
// must hold every role in the namespace, and must be the caller's own copies.
// Every decision about an aggregating role (the ACL build, grant checks, the
// roles API) runs on roles resolved here, never on status.
func Resolve(roles map[string]*unikornv1.Role) {
	results := Compute(roles)

	for id, role := range roles {
		if !role.IsAggregating() {
			continue
		}

		// A role being deleted is not computed, so it holds nothing.
		computed := &unikornv1.ComputedAggregation{}

		if result := results[id]; result != nil {
			computed.Scopes = result.EffectiveScopes
			computed.Available = result.Available.Status == corev1.ConditionTrue
			computed.Sources = result.AggregatedFrom
		}

		role.Computed = computed
	}
}

// ResolveRole resolves one role in place, for a caller that loaded just that
// role.  A role that does not aggregate is left alone; for one that does,
// every role in its namespace is listed, because any of them can be a source.
// A caller resolving several roles uses a Resolver, which lists once.
func ResolveRole(ctx context.Context, cli client.Client, role *unikornv1.Role) error {
	return NewResolver(cli, role.Namespace).Resolve(ctx, role)
}

// Resolver resolves roles from one namespace for one request.  It lists the
// namespace's roles the first time an aggregating role needs them, and uses
// that list for every later role, so a request that checks several roles
// lists once.  A role that does not aggregate never causes a list.  It is not
// safe for use by more than one goroutine.
type Resolver struct {
	cli       client.Client
	namespace string
	roles     map[string]*unikornv1.Role
}

// NewResolver returns a Resolver for roles in namespace.
func NewResolver(cli client.Client, namespace string) *Resolver {
	return &Resolver{cli: cli, namespace: namespace}
}

// Resolve resolves one role in place.  A role that does not aggregate is left
// alone.  For one that does, the caller's copy is resolved against the listed
// roles.  If the roles cannot be listed the role is set to hold nothing and
// not be ready, and the error is returned: it never keeps a Computed value it
// had before.
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

	// Use the caller's copy of the role itself, without changing the list.
	roles := maps.Clone(r.roles)
	roles[role.Name] = role

	Resolve(roles)

	return nil
}
