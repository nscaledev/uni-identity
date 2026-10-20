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

//nolint:testpackage // The test drives the unexported grantable check directly.
package role

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/aggregation"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func orgScopes(names ...string) unikornv1.RoleScopes {
	scopes := unikornv1.RoleScopes{}

	for _, name := range names {
		scopes.Organization = append(scopes.Organization, unikornv1.RoleScope{Name: name, Operations: []unikornv1.Operation{unikornv1.Read}})
	}

	return scopes
}

// labelledFor makes a role labelled for the named aggregating roles.
func labelledFor(id string, scopes unikornv1.RoleScopes, names ...string) *unikornv1.Role {
	labels := map[string]string{}

	for _, name := range names {
		labels[unikornv1.AggregateToLabel(name)] = "true"
	}

	return newRole(id, labels, unikornv1.RoleSpec{Scopes: scopes})
}

// aggregating makes a role that selects aggregate-to-<id> and refs refs.
func aggregating(id string, flatten bool, refs ...string) *unikornv1.Role {
	return newRole(id, nil, unikornv1.RoleSpec{
		AggregationRule: &unikornv1.RoleAggregationRule{
			RoleSelectors: []metav1.LabelSelector{
				{MatchLabels: map[string]string{unikornv1.AggregateToLabel(id): "true"}},
			},
			RoleRefs:              refs,
			FlattenToOrganization: flatten,
		},
	})
}

// chartAggregating is aggregating with the ID the chart gives the name, as
// an aggregating role must have to use its base role.
func chartAggregating(name string, flatten bool, refs ...string) *unikornv1.Role {
	role := aggregating(name, flatten, refs...)
	role.Name = unikornv1.ChartRoleID(name)

	return role
}

func grantableFor(t *testing.T, roles ...*unikornv1.Role) map[string]aggregation.Condition {
	t.Helper()

	snapshot := map[string]*unikornv1.Role{}

	for _, role := range roles {
		snapshot[role.Name] = role
	}

	out := map[string]aggregation.Condition{}

	for id, result := range aggregation.Compute(snapshot) {
		out[id] = grantable(t.Context(), result)
	}

	return out
}

// TestGrantableBaseRefAndSelector checks a role can grant the role labelled
// for it, alongside its protected base role.
func TestGrantableBaseRefAndSelector(t *testing.T) {
	t.Parallel()

	results := grantableFor(t, adminBase(), chartAggregating("administrator", true, adminBaseID), fleetOperator())

	require.Equal(t, corev1.ConditionTrue, results[adminID].Status, results[adminID].Message)
	require.Equal(t, unikornv1.RoleReasonGrantable, results[adminID].Reason)
	require.Equal(t, "can grant all 1 labelled roles", results[adminID].Message)
}

// TestGrantableFlattenAndNot checks a flattening and a non-flattening role
// can both grant a role with project scopes labelled for them.
func TestGrantableFlattenAndNot(t *testing.T) {
	t.Parallel()

	source := labelledFor("project-writer", unikornv1.RoleScopes{
		Organization: orgScopes("svc:things").Organization,
		Project:      []unikornv1.RoleScope{{Name: "svc:things", Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Delete}}},
	}, "administrator", "user")

	results := grantableFor(t, source, aggregating("administrator", true), aggregating("user", false))

	for _, id := range []string{"administrator", "user"} {
		require.Equalf(t, corev1.ConditionTrue, results[id].Status, "%s: %s", id, results[id].Message)
	}
}

// TestGrantableChain checks every role in a chain can grant what is labelled
// for it, aggregating roles included.
func TestGrantableChain(t *testing.T) {
	t.Parallel()

	reader := aggregating("reader", false)
	reader.Labels[unikornv1.AggregateToLabel("auditor")] = "true"
	reader.Labels[unikornv1.AggregateToLabel("user")] = "true"

	user := aggregating("user", false)
	user.Labels[unikornv1.AggregateToLabel("administrator")] = "true"

	auditor := aggregating("auditor", true)
	auditor.Labels[unikornv1.AggregateToLabel("administrator")] = "true"

	fleetReader := labelledFor("fleet-reader", unikornv1.RoleScopes{
		Project: orgScopes("radar:topology").Organization,
	}, "reader")

	results := grantableFor(t, reader, user, auditor, aggregating("administrator", true), fleetReader)

	require.Len(t, results, 4)

	for id, result := range results {
		require.Equalf(t, corev1.ConditionTrue, result.Status, "%s: %s", id, result.Message)
	}
}

// TestNotGrantableWhileStuck checks a role stuck on a missing roleRef is
// recorded as not grantable, even though it could grant every live role
// labelled for it: the server never grants a stuck role (see
// Role.AggregationReady), so the record must not say it can.
func TestNotGrantableWhileStuck(t *testing.T) {
	t.Parallel()

	results := grantableFor(t, chartAggregating("administrator", true, adminBaseID), fleetOperator())

	require.Equal(t, corev1.ConditionFalse, results[adminID].Status)
	require.Equal(t, unikornv1.RoleReasonNotAvailable, results[adminID].Reason)
	require.Equal(t, "role is stuck, it cannot be granted", results[adminID].Message)
}

// TestGrantableNamesLabelledGlobalRole checks a role labelled for
// aggregation that has global scopes makes Grantable False, naming it,
// because no org admin can ever grant it.
func TestGrantableNamesLabelledGlobalRole(t *testing.T) {
	t.Parallel()

	global := labelledFor("svc-global", unikornv1.RoleScopes{
		Global: orgScopes("svc:everything").Organization,
	}, "administrator")

	results := grantableFor(t, aggregating("administrator", true), global)

	require.Equal(t, corev1.ConditionFalse, results["administrator"].Status)
	require.Equal(t, unikornv1.RoleReasonNotGrantable, results["administrator"].Reason)
	require.Equal(t, "cannot grant: svc-global", results["administrator"].Message)
}

// TestGrantableUsesLiveScopesOfAggregatingLabelledRole checks an aggregating
// role labelled for another one is judged on what it holds live, which has
// no global scopes, not on its own spec.scopes.global: it is used as a
// source, and Grantable does not name it.
func TestGrantableUsesLiveScopesOfAggregatingLabelledRole(t *testing.T) {
	t.Parallel()

	user := aggregating("user", false)
	user.Labels[unikornv1.AggregateToLabel("administrator")] = "true"
	user.Spec.Scopes.Global = orgScopes("svc:everything").Organization

	reader := labelledFor("reader", orgScopes("svc:things"), "user")

	snapshot := map[string]*unikornv1.Role{}

	for _, role := range []*unikornv1.Role{user, reader, aggregating("administrator", true)} {
		snapshot[role.Name] = role
	}

	result := aggregation.Compute(snapshot)["administrator"]

	require.Empty(t, result.Skipped)
	require.Len(t, result.AggregatedFrom, 1)
	require.Equal(t, "user", result.AggregatedFrom[0].ID)
	require.Equal(t, orgScopes("svc:things").Organization, result.EffectiveScopes.Organization)
	require.Len(t, result.Labelled, 1)
	require.Empty(t, result.Labelled[0].Scopes.Global)

	condition := grantable(t.Context(), result)
	require.Equal(t, corev1.ConditionTrue, condition.Status, condition.Message)
}
