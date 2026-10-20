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
	// AggregateToLabelPrefix prefixes the label a source role carries to opt
	// into an aggregating role, e.g. identity.unikorn-cloud.org/aggregate-to-administrator.
	AggregateToLabelPrefix = "identity.unikorn-cloud.org/aggregate-to-"

	// RoleConditionGrantable is True when an aggregating role can grant every
	// role labelled for it, and False naming the ones it can't.
	RoleConditionGrantable unikornv1core.ConditionType = "Grantable"

	// RoleReasonAggregated means the role's effective scopes are up to date.
	RoleReasonAggregated = "Aggregated"
	// RoleReasonMissingRoleRef means a roleRef names a role that does not
	// exist or is being deleted.  That ref gives nothing.
	RoleReasonMissingRoleRef = "MissingRoleRef"
	// RoleReasonInvalidRoleRef means a roleRef names a protected role that is
	// not this role's base role.  That ref gives nothing.
	RoleReasonInvalidRoleRef = "InvalidRoleRef"
	// RoleReasonCycle means the role is part of an aggregation cycle.  Each
	// role in the cycle holds what the roles outside it give.
	RoleReasonCycle = "Cycle"
	// RoleReasonInvalidSelector means a role selector is not allowed.  The
	// selectors give nothing, only roleRefs are used.
	RoleReasonInvalidSelector = "InvalidSelector"

	// BaseRoleSuffix ends the display name of the only protected role an
	// aggregating role may name in roleRefs: administrator may ref
	// administrator-base.
	BaseRoleSuffix = "-base"
	// RoleReasonGrantable means every labelled source is grantable.
	RoleReasonGrantable = "Grantable"
	// RoleReasonNotGrantable means at least one labelled source is not.
	RoleReasonNotGrantable = "NotGrantable"
	// RoleReasonNotAvailable means the role is stuck, so it cannot be
	// granted, whatever its labelled sources are.
	RoleReasonNotAvailable = "NotAvailable"
	// RoleReasonDeleting means the role is being deleted.  It holds nothing
	// and cannot be granted.
	RoleReasonDeleting = "Deleting"
)

// AggregateToLabel returns the label a source role carries to be selected by
// the aggregating role with the given display name.
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

// ChartRoleID returns the ID the identity chart gives a role with this
// display name: a version 4 style UUID made from the SHA-256 of the name.
// It must match the chart's resource.id helper.
func ChartRoleID(name string) string {
	sum := sha256.Sum256([]byte(name))
	s := hex.EncodeToString(sum[:])

	return "f" + s[1:8] + "-" + s[8:12] + "-4" + s[13:16] + "-8" + s[17:20] + "-" + s[20:32]
}

// BaseRoleName returns the display name of the only protected role this role
// may name in roleRefs.
func (r *Role) BaseRoleName() string {
	return r.DisplayName() + BaseRoleSuffix
}

// MayRef tells whether an aggregating role may use source through roleRefs.
// Any role that is not protected may be used.  A protected role may only be
// used when it is this role's own base role: its display name is this role's
// display name plus "-base", its ID is the one the chart gives that name, and
// this role's own ID is the one the chart gives its display name.  Matching
// the source ID stops another protected role being used by copying the base
// role's name label onto it.  Matching this role's ID stops a decoy role that
// copies the aggregating role's name label claiming its base role.  Renaming
// an aggregating role locks it out of its base role.
//
// The admission policy in the identity chart is the main guard.  This is
// defence in depth only: it stops any other aggregating role passing
// protected scopes on if the policy is missing or wrong.
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

// EffectiveScopes returns the scopes a role holds.  Every reader of a role's
// scopes (ACL build, grant checks, the roles API) must use this, never
// Spec.Scopes or Status directly.
//
// A role without an aggregationRule holds spec.scopes.  An aggregating role
// holds what aggregation.Resolve worked out live from the current roles.
// Status, which the role controller writes, is never used: it is a record
// for people, and may be stale or wrong.  An aggregating role that was not
// resolved holds nothing, so a code path that forgets to resolve fails
// closed.  Global scopes are never held through aggregation.
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

// AggregationReady tells whether a role may be granted at all.  A role that
// does not aggregate always may.  An aggregating role may only once it has
// been resolved live and is Available: a stuck role (missing ref, cycle, bad
// selector or ref) is never grantable, whatever it holds, so a broken role
// cannot be handed out on the strength of a partial result.
func (r *Role) AggregationReady() bool {
	if !r.IsAggregating() {
		return true
	}

	return r.Computed != nil && r.Computed.Available
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
	set := ScopeSet{}

	set.Add(a)
	set.Add(b)

	return set.List()
}

// ScopeSet gathers scopes from many lists, so a union of many lists is sorted
// once, not once per list.
// +k8s:deepcopy-gen=false
type ScopeSet map[string][]Operation

// Add adds a list of scopes to the set.
func (s ScopeSet) Add(scopes []RoleScope) {
	for _, scope := range scopes {
		s[scope.Name] = append(s[scope.Name], scope.Operations...)
	}
}

// List returns the scopes in the set, sorted by name, with the operations for
// each name sorted and with no repeats, or nil if the set is empty.
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
