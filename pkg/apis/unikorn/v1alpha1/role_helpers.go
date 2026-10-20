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
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
)

const (
	// AggregateToLabelPrefix is the label prefix a source role uses to opt into an aggregating role.
	AggregateToLabelPrefix = "identity.unikorn-cloud.org/aggregate-to-"

	// RoleConditionGrantable is True when an aggregating role can grant every role labelled for it.
	RoleConditionGrantable unikornv1core.ConditionType = "Grantable"

	// RoleReasonAggregated means the role's effective scopes are up to date.
	RoleReasonAggregated = "Aggregated"
	// RoleReasonMissingRoleRef means a roleRef names no live role.
	RoleReasonMissingRoleRef = "MissingRoleRef"
	// RoleReasonInvalidRoleRef means a roleRef names a protected role other than the base role.
	RoleReasonInvalidRoleRef = "InvalidRoleRef"
	// RoleReasonCycle means the role is part of an aggregation cycle.
	RoleReasonCycle = "Cycle"
	// RoleReasonInvalidSelector means a role selector is not allowed.
	RoleReasonInvalidSelector = "InvalidSelector"

	// BaseRoleSuffix names the only protected role an aggregating role may ref, e.g. administrator-base.
	BaseRoleSuffix = "-base"
	// RoleReasonGrantable means every labelled source is grantable.
	RoleReasonGrantable = "Grantable"
	// RoleReasonNotGrantable means at least one labelled source is not.
	RoleReasonNotGrantable = "NotGrantable"
	// RoleReasonNotAvailable means the role is stuck, so it cannot be granted.
	RoleReasonNotAvailable = "NotAvailable"
	// RoleReasonDeleting means the role is being deleted and holds nothing.
	RoleReasonDeleting = "Deleting"
)

// AggregateToLabel returns the label that opts a source role into the named aggregating role.
func AggregateToLabel(name string) string {
	return AggregateToLabelPrefix + name
}

// DisplayName returns the role's display name label, or its ID if it has none.
func (r *Role) DisplayName() string {
	if name, ok := r.Labels[coreconstants.NameLabel]; ok {
		return name
	}

	return r.Name
}

// ChartRoleID returns the ID the chart gives a role name; it must match the chart's resource.id helper.
func ChartRoleID(name string) string {
	sum := sha256.Sum256([]byte(name))
	s := hex.EncodeToString(sum[:])

	return "f" + s[1:8] + "-" + s[8:12] + "-4" + s[13:16] + "-8" + s[17:20] + "-" + s[20:32]
}

// BaseRoleName returns the name of the only protected role this role may ref.
func (r *Role) BaseRoleName() string {
	return r.DisplayName() + BaseRoleSuffix
}

// MayRef allows any non-protected role, and only this role's own base role, matched by chart IDs.
// Defence in depth behind the chart's admission policy, see pkg/controllers/role/README.md.
func (r *Role) MayRef(source *Role) bool {
	if !source.Spec.Protected {
		return true
	}

	if r.Name != ChartRoleID(r.DisplayName()) {
		return false
	}

	base := r.BaseRoleName()

	return source.Name == ChartRoleID(base) && source.DisplayName() == base
}

// IsAggregating tells whether the role takes its scopes from source roles.
func (r *Role) IsAggregating() bool {
	return r.Spec.AggregationRule != nil
}

// EffectiveScopes is what a role holds; every reader must use it, never Spec.Scopes or Status.
// An unresolved aggregating role holds nothing, so a missed resolve fails closed.
func (r *Role) EffectiveScopes() RoleScopes {
	if !r.IsAggregating() {
		return r.Spec.Scopes
	}

	if r.Computed == nil {
		return RoleScopes{}
	}

	return RoleScopes{
		Organization: r.Computed.Scopes.Organization,
		Project:      r.Computed.Scopes.Project,
	}
}

// AggregationReady: a stuck aggregating role is never grantable, whatever it holds.
func (r *Role) AggregationReady() bool {
	if !r.IsAggregating() {
		return true
	}

	return r.Computed != nil && r.Computed.Available
}

// MergeScopes never aggregates global scopes: they would hand out cross-organization authority.
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

// UnionScopes returns the sorted union of two scope lists, or nil if both are empty.
func UnionScopes(a, b []RoleScope) []RoleScope {
	set := ScopeSet{}

	set.Add(a)
	set.Add(b)

	return set.List()
}

// ScopeSet sorts a union of many scope lists once, not once per list.
// +k8s:deepcopy-gen=false
type ScopeSet map[string][]Operation

func (s ScopeSet) Add(scopes []RoleScope) {
	for _, scope := range scopes {
		s[scope.Name] = append(s[scope.Name], scope.Operations...)
	}
}

// List returns the scopes sorted, or nil if the set is empty.
func (s ScopeSet) List() []RoleScope {
	if len(s) == 0 {
		return nil
	}

	out := make([]RoleScope, 0, len(s))

	for name, ops := range s {
		ops = slices.Clone(ops)
		slices.Sort(ops)

		out = append(out, RoleScope{Name: name, Operations: slices.Compact(ops)})
	}

	slices.SortFunc(out, func(x, y RoleScope) int {
		return strings.Compare(x.Name, y.Name)
	})

	return out
}
