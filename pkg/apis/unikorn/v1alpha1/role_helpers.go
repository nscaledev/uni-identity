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
	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
)

const (
	// AggregateToLabelPrefix prefixes the label a source role carries to opt
	// into an aggregating role, e.g. identity.unikorn-cloud.org/aggregate-to-administrator.
	AggregateToLabelPrefix = "identity.unikorn-cloud.org/aggregate-to-"

	// RoleConditionGrantable is True when an aggregating role can grant every
	// source role its selectors match, and False naming the first one it
	// can't.
	RoleConditionGrantable unikornv1core.ConditionType = "Grantable"

	// RoleReasonAggregated means the role's effective scopes are up to date.
	RoleReasonAggregated = "Aggregated"
	// RoleReasonMissingRoleRef means a roleRef names a role that does not
	// exist.  The last effective scopes are kept.
	RoleReasonMissingRoleRef = "MissingRoleRef"
	// RoleReasonCycle means the role is part of an aggregation cycle.  The
	// last effective scopes are kept.
	RoleReasonCycle = "Cycle"
	// RoleReasonGrantable means every selected source is grantable.
	RoleReasonGrantable = "Grantable"
	// RoleReasonNotGrantable means at least one selected source is not.
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
// Spec.Scopes directly.  A role without an aggregationRule holds spec.scopes.
// An aggregating role holds status.effectiveScopes, which the role controller
// writes; until it has, the role holds nothing, so it fails closed.
func (r *Role) EffectiveScopes() RoleScopes {
	if !r.IsAggregating() {
		return r.Spec.Scopes
	}

	if r.Status.EffectiveScopes == nil {
		return RoleScopes{}
	}

	return *r.Status.EffectiveScopes
}
