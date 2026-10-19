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

package v1alpha1

import (
	"slices"
	"strings"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// AggregateToLabelPrefix prefixes the label a source role carries to opt
	// into an aggregating role, e.g. identity.unikorn-cloud.org/aggregate-to-administrator.
	AggregateToLabelPrefix = "identity.unikorn-cloud.org/aggregate-to-"

	// RoleConditionGrantable is True when an aggregating role can grant every
	// role labelled for it, and False naming the ones it can't.
	RoleConditionGrantable unikornv1core.ConditionType = "Grantable"

	// RoleReasonAggregated means the role's effective scopes are up to date.
	RoleReasonAggregated = "Aggregated"
	// RoleReasonMissingRoleRef means a roleRef names a role that does not
	// exist.  The last effective scopes are kept.
	RoleReasonMissingRoleRef = "MissingRoleRef"
	// RoleReasonCycle means the role is part of an aggregation cycle.  The
	// last effective scopes are kept.
	RoleReasonCycle = "Cycle"
	// RoleReasonInvalidSelector means a role selector is not allowed.  The
	// last effective scopes are kept.
	RoleReasonInvalidSelector = "InvalidSelector"
	// RoleReasonGrantable means every labelled source is grantable.
	RoleReasonGrantable = "Grantable"
	// RoleReasonNotGrantable means at least one labelled source is not.
	RoleReasonNotGrantable = "NotGrantable"
)

// AggregateToLabel returns the label a source role carries to be selected by
// the aggregating role with the given display name.
func AggregateToLabel(name string) string {
	return AggregateToLabelPrefix + name
}

// IsAggregating tells whether the role takes its scopes from source roles.
func (r *Role) IsAggregating() bool {
	return r.Spec.AggregationRule != nil
}

// EffectiveScopes returns the scopes a role holds.  Every reader of a role's
// scopes (ACL build, grant checks, the roles API) must use this, never
// Spec.Scopes directly.
//
// A role without an aggregationRule holds spec.scopes.  An aggregating role
// holds status.effectiveScopes, which only the role controller writes.  Global
// scopes are never taken from status, whoever wrote it: aggregation never
// produces them, so any there are not trusted.  Until the controller has
// written status, an aggregating role holds nothing here.  The ACL build
// bridges that gap with BootstrapRoles.
func (r *Role) EffectiveScopes() RoleScopes {
	if !r.IsAggregating() {
		return r.Spec.Scopes
	}

	if r.Status.EffectiveScopes == nil {
		return RoleScopes{}
	}

	return RoleScopes{
		Organization: r.Status.EffectiveScopes.Organization,
		Project:      r.Status.EffectiveScopes.Project,
	}
}

// AggregationReady tells whether a role's effective scopes can be trusted for
// a grant check.  A role that does not aggregate always can.  An aggregating
// role can once the controller has written status for its current generation,
// and that status is either Available or stuck (missing ref, cycle, bad
// selector) on scopes that are not empty: holders of a stuck role hold
// exactly its kept scopes.  Before that its effective scopes are empty or out
// of date, so a grant check against them could let anyone hand out a role
// that is about to hold far more.
func (r *Role) AggregationReady() bool {
	if !r.IsAggregating() {
		return true
	}

	if r.Status.EffectiveScopes == nil {
		return false
	}

	condition := meta.FindStatusCondition(r.Status.Conditions, string(unikornv1core.ConditionAvailable))
	if condition == nil || condition.ObservedGeneration != r.Generation {
		return false
	}

	if condition.Status == metav1.ConditionTrue {
		return true
	}

	scopes := r.EffectiveScopes()

	return len(scopes.Organization)+len(scopes.Project) > 0
}

// BootstrapRoles fills in the effective scopes of every aggregating role the
// controller has not reconciled yet, in place, with BootstrapScopes.  roles is
// keyed by role ID.  It is for the ACL build only, on roles it has just
// listed.
//
// This keeps org admins working while a built-in role is converted to an
// aggregating one: its hand-written scopes move to a base role it refs, so
// until the controller runs, holders keep exactly what they had.  Service
// role scopes arrive when the controller writes status.  Without this, every
// admin would hold nothing for the time between the apply and the first
// reconcile, and the ACL cache would keep that for its whole TTL.
func BootstrapRoles(roles map[string]*Role) {
	for _, role := range roles {
		if !role.IsAggregating() || role.Status.EffectiveScopes != nil {
			continue
		}

		scopes := role.BootstrapScopes(roles)

		role.Status.EffectiveScopes = &scopes
	}
}

// BootstrapScopes returns what an aggregating role holds before the
// controller has written its status: its own spec.scopes plus what the
// non-aggregating roles it names in roleRefs hold, never with global scopes.
// roles is keyed by role ID and is only read.
func (r *Role) BootstrapScopes(roles map[string]*Role) RoleScopes {
	// Start from any scopes the role had before it aggregated, so adding an
	// aggregationRule never takes anything away before the controller runs,
	// even with a bad ref.
	scopes := MergeScopes(RoleScopes{}, r.Spec.Scopes, false)

	for _, ref := range r.Spec.AggregationRule.RoleRefs {
		source, ok := roles[ref]
		if !ok || source.IsAggregating() || !source.DeletionTimestamp.IsZero() {
			continue
		}

		scopes = MergeScopes(scopes, source.Spec.Scopes, r.Spec.AggregationRule.FlattenToOrganization)
	}

	return scopes
}

// MergeScopes folds a source's scopes into an aggregating role's scopes.
// Global scopes are never aggregated: they would hand out cross-organization
// authority.  Organization scopes stay at organization scope.  Project scopes
// stay at project scope, or move to organization scope when flatten is set.
func MergeScopes(into, source RoleScopes, flatten bool) RoleScopes {
	out := RoleScopes{
		Organization: UnionScopes(into.Organization, source.Organization),
		Project:      into.Project,
	}

	if flatten {
		out.Organization = UnionScopes(out.Organization, source.Project)
	} else {
		out.Project = UnionScopes(out.Project, source.Project)
	}

	return out
}

// UnionScopes returns the union of two scope lists, sorted by name, with the
// operations for each name merged and sorted, or nil if both are empty.
func UnionScopes(a, b []RoleScope) []RoleScope {
	operations := map[string][]Operation{}

	for _, list := range [][]RoleScope{a, b} {
		for _, scope := range list {
			operations[scope.Name] = append(operations[scope.Name], scope.Operations...)
		}
	}

	if len(operations) == 0 {
		return nil
	}

	out := make([]RoleScope, 0, len(operations))

	for name, ops := range operations {
		ops = slices.Clone(ops)
		slices.Sort(ops)

		out = append(out, RoleScope{Name: name, Operations: slices.Compact(ops)})
	}

	slices.SortFunc(out, func(x, y RoleScope) int {
		return strings.Compare(x.Name, y.Name)
	})

	return out
}
