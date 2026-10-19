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

package roles_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/aggregation"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/roles"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	namespace          = "identity"
	testOrganizationID = "acbaf1e5-6414-4066-b74e-2d95dc766299"
)

func newRole(name string, protected bool, orgScopes []unikornv1.RoleScope) *unikornv1.Role {
	return &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{"unikorn-cloud.org/name": name},
		},
		Spec: unikornv1.RoleSpec{
			Protected: protected,
			Scopes:    unikornv1.RoleScopes{Organization: orgScopes},
		},
	}
}

func TestListReturnsUngrantableRolesWithFlag(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	grantableRole := newRole("basic", false, []unikornv1.RoleScope{
		{Name: "identity:groups", Operations: []unikornv1.Operation{unikornv1.Read}},
	})
	radar := newRole("radar", false, []unikornv1.RoleScope{
		{Name: "radar:things", Operations: []unikornv1.Operation{unikornv1.Read}},
	})
	hidden := newRole("internal", true, nil)

	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(grantableRole, radar, hidden).Build()

	// Caller holds identity:groups read at org scope, but nothing radar.
	endpoints := openapi.AclEndpoints{{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Read}}}
	organizations := openapi.AclOrganizationList{{Id: testOrganizationID, Endpoints: &endpoints}}
	ctx := rbac.NewContext(t.Context(), &openapi.Acl{Organizations: &organizations})

	orgID, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	result, err := roles.New(cli, namespace).List(ctx, orgID)
	require.NoError(t, err)

	byName := map[string]openapi.RoleRead{}
	for _, r := range result {
		byName[r.Metadata.Name] = r
	}

	require.Len(t, result, 2, "protected roles stay hidden, ungrantable roles do not")
	require.True(t, byName["basic"].Grantable)
	require.False(t, byName["radar"].Grantable)
	require.NotContains(t, byName, "internal")
}

// TestListEmptyCatalogueMarshalsAsAnEmptyArray covers the case where every role in the
// namespace is filtered out.  The schema declares the response a non-nullable array, so a
// nil slice — which marshals to null — fails response validation rather than reaching the
// client.
func TestListEmptyCatalogueMarshalsAsAnEmptyArray(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	// The only role present is protected, so the filter empties the list.
	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(newRole("internal", true, nil)).Build()

	endpoints := openapi.AclEndpoints{{Name: "identity:roles", Operations: openapi.AclOperations{openapi.Read}}}
	organizations := openapi.AclOrganizationList{{Id: testOrganizationID, Endpoints: &endpoints}}
	ctx := rbac.NewContext(t.Context(), &openapi.Acl{Organizations: &organizations})

	orgID, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	result, err := roles.New(cli, namespace).List(ctx, orgID)
	require.NoError(t, err)
	require.Empty(t, result)

	body, err := json.Marshal(result)
	require.NoError(t, err)
	require.JSONEq(t, "[]", string(body))
}

// adminBase is the protected base role of administrator, with the ID and
// name the chart gives it.
func adminBase() *unikornv1.Role {
	base := newRole(unikornv1.ChartRoleID("administrator-base"), true, []unikornv1.RoleScope{
		{Name: "identity:groups", Operations: []unikornv1.Operation{unikornv1.Read}},
	})
	base.Labels["unikorn-cloud.org/name"] = "administrator-base"

	return base
}

func adminRole(effective []unikornv1.RoleScope, sources ...unikornv1.RoleAggregationSource) *unikornv1.Role {
	role := newRole("administrator", false, nil)
	role.Spec.AggregationRule = &unikornv1.RoleAggregationRule{FlattenToOrganization: true}
	role.Status.EffectiveScopes = &unikornv1.RoleScopes{Organization: effective}
	role.Status.AggregatedFrom = sources
	// Reconciled for the current generation, so it is ready to be granted.
	role.Status.Conditions = []metav1.Condition{{Type: "Available", Status: metav1.ConditionTrue, ObservedGeneration: role.Generation}}

	return role
}

func listAsAdmin(t *testing.T, objects ...*unikornv1.Role) map[string]openapi.RoleRead {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	builder := fake.NewClientBuilder().WithScheme(scheme)
	for _, o := range objects {
		builder = builder.WithObjects(o)
	}

	endpoints := openapi.AclEndpoints{
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Read}},
		{Name: "radar:topology", Operations: openapi.AclOperations{openapi.Read}},
	}
	organizations := openapi.AclOrganizationList{{Id: testOrganizationID, Endpoints: &endpoints}}
	ctx := rbac.NewContext(t.Context(), &openapi.Acl{Organizations: &organizations})

	result, err := roles.New(builder.Build(), namespace).List(ctx, ids.MustParseOrganizationID(testOrganizationID))
	require.NoError(t, err)

	byName := map[string]openapi.RoleRead{}
	for _, r := range result {
		byName[r.Metadata.Name] = r
	}

	return byName
}

// TestListShowsEffectiveScopesAndSources checks an aggregating role reports
// what it really holds, and where it came from, rather than only its
// description.
func TestListShowsEffectiveScopesAndSources(t *testing.T) {
	t.Parallel()

	admin := adminRole(
		[]unikornv1.RoleScope{
			{Name: "identity:groups", Operations: []unikornv1.Operation{unikornv1.Read}},
			{Name: "radar:topology", Operations: []unikornv1.Operation{unikornv1.Read}},
		},
		unikornv1.RoleAggregationSource{ID: "base-id", Name: "administrator-base", Description: "Organization administrator.", ScopesHash: "sha256:aa"},
		unikornv1.RoleAggregationSource{ID: "fleet-id", Name: "fleet-operator", ScopesHash: "sha256:bb"},
	)

	base := newRole("base-id", false, nil)
	base.Labels["unikorn-cloud.org/name"] = "administrator-base"
	fleet := newRole("fleet-id", false, nil)

	byName := listAsAdmin(t, admin, base, fleet)

	got := byName["administrator"]
	require.True(t, got.Grantable)
	require.NotNil(t, got.Scopes.Organization)
	require.Equal(t, openapi.AclEndpoints{
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Read}},
		{Name: "radar:topology", Operations: openapi.AclOperations{openapi.Read}},
	}, *got.Scopes.Organization)
	require.Nil(t, got.Scopes.Global)
	require.Nil(t, got.Scopes.Project)

	require.NotNil(t, got.AggregatedFrom)
	require.Equal(t, []openapi.RoleSource{
		{Id: "base-id", Name: "administrator-base", Description: ptr("Organization administrator.")},
		{Id: "fleet-id", Name: "fleet-operator"},
	}, *got.AggregatedFrom)

	// The scopes hash is internal and never reaches the API.
	body, err := json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(body), "sha256")
}

// TestListShowsPlainRoleScopes checks a role with no aggregationRule returns
// its spec scopes and no sources.
func TestListShowsPlainRoleScopes(t *testing.T) {
	t.Parallel()

	plain := newRole("fleet-operator", false, []unikornv1.RoleScope{
		{Name: "radar:topology", Operations: []unikornv1.Operation{unikornv1.Read}},
	})

	got := listAsAdmin(t, plain)["fleet-operator"]

	require.Equal(t, openapi.AclEndpoints{
		{Name: "radar:topology", Operations: openapi.AclOperations{openapi.Read}},
	}, *got.Scopes.Organization)
	require.Nil(t, got.AggregatedFrom)
}

// TestListFollowsChangedSources checks the API reports the status as the
// controller last wrote it: after a source is removed, its scopes and its
// entry go.
func TestListFollowsChangedSources(t *testing.T) {
	t.Parallel()

	before := adminRole(
		[]unikornv1.RoleScope{{Name: "radar:topology", Operations: []unikornv1.Operation{unikornv1.Read}}},
		unikornv1.RoleAggregationSource{ID: "fleet-id", Name: "fleet-operator", ScopesHash: "sha256:bb"},
	)
	base := newRole("base-id", false, nil)
	fleet := newRole("fleet-id", false, nil)

	require.Len(t, *listAsAdmin(t, before, base, fleet)["administrator"].AggregatedFrom, 1)

	after := adminRole(
		[]unikornv1.RoleScope{{Name: "identity:groups", Operations: []unikornv1.Operation{unikornv1.Read}}},
		unikornv1.RoleAggregationSource{ID: "base-id", Name: "administrator-base", ScopesHash: "sha256:aa"},
	)

	got := listAsAdmin(t, after, base, fleet)["administrator"]
	require.Equal(t, []openapi.RoleSource{{Id: "base-id", Name: "administrator-base"}}, *got.AggregatedFrom)
	require.Equal(t, "identity:groups", (*got.Scopes.Organization)[0].Name)
	require.Len(t, *got.Scopes.Organization, 1)
}

// TestListUnreconciledAggregatingRoleHoldsNothing checks an aggregating role
// the controller has not reconciled yet reports no scopes, matching what the
// ACL build gives its holders.
func TestListUnreconciledAggregatingRoleHoldsNothing(t *testing.T) {
	t.Parallel()

	role := newRole("administrator", false, nil)
	role.Spec.AggregationRule = &unikornv1.RoleAggregationRule{}

	got := listAsAdmin(t, role)["administrator"]

	require.Nil(t, got.Scopes.Organization)
	require.Nil(t, got.AggregatedFrom)
}

// TestListUnreconciledAggregatingRoleReportsBootstrapScopes checks an
// aggregating role the controller has not reconciled yet reports what its
// roleRefs hold, as the ACL build gives its holders, and is not grantable.
func TestListUnreconciledAggregatingRoleReportsBootstrapScopes(t *testing.T) {
	t.Parallel()

	base := adminBase()

	admin := newRole("administrator", false, nil)
	admin.Spec.AggregationRule = &unikornv1.RoleAggregationRule{RoleRefs: []string{base.Name}, FlattenToOrganization: true}

	got := listAsAdmin(t, base, admin)["administrator"]

	require.NotNil(t, got.Scopes.Organization)
	require.Equal(t, openapi.AclEndpoints{
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Read}},
	}, *got.Scopes.Organization)
	require.False(t, got.Grantable)
}

// TestListHidesProtectedSources checks a protected source role is left out
// of aggregatedFrom, as it is left out of the list.
func TestListHidesProtectedSources(t *testing.T) {
	t.Parallel()

	base := adminBase()
	base.Annotations = map[string]string{"unikorn-cloud.org/description": "internal: do not expose"}

	fleet := newRole("fleet-operator", false, []unikornv1.RoleScope{
		{Name: "radar:topology", Operations: []unikornv1.Operation{unikornv1.Read}},
	})

	admin := newRole("administrator", false, nil)
	admin.Spec.AggregationRule = &unikornv1.RoleAggregationRule{RoleRefs: []string{base.Name, fleet.Name}, FlattenToOrganization: true}

	res := aggregation.Compute(t.Context(), map[string]*unikornv1.Role{base.Name: base, fleet.Name: fleet, admin.Name: admin})[admin.Name]
	require.Len(t, res.AggregatedFrom, 2)

	byName := listAsAdmin(t, base, fleet, adminRole(res.EffectiveScopes.Organization, res.AggregatedFrom...))
	require.NotContains(t, byName, "administrator-base")

	got := byName["administrator"]
	require.NotNil(t, got.AggregatedFrom)
	require.Equal(t, []openapi.RoleSource{{Id: "fleet-operator", Name: "fleet-operator"}}, *got.AggregatedFrom)

	// Only protected sources: nothing to show.
	require.Equal(t, base.Name, res.AggregatedFrom[0].ID)

	byName = listAsAdmin(t, base, fleet, adminRole(res.EffectiveScopes.Organization, res.AggregatedFrom[0]))
	require.Nil(t, byName["administrator"].AggregatedFrom)
}

// TestListHidesSourcesThatAreGone checks aggregatedFrom never shows a source
// that no longer exists, even when status still names it, protected or not.
func TestListHidesSourcesThatAreGone(t *testing.T) {
	t.Parallel()

	admin := adminRole(
		[]unikornv1.RoleScope{{Name: "identity:groups", Operations: []unikornv1.Operation{unikornv1.Read}}},
		unikornv1.RoleAggregationSource{ID: "base-id", Name: "administrator-base"},
		unikornv1.RoleAggregationSource{ID: "gone-id", Name: "gone"},
	)

	require.Nil(t, listAsAdmin(t, admin)["administrator"].AggregatedFrom)

	deleting := newRole("fleet-id", false, nil)
	deleting.Finalizers = []string{"test"}
	now := metav1.Now()
	deleting.DeletionTimestamp = &now

	admin = adminRole(nil, unikornv1.RoleAggregationSource{ID: "fleet-id", Name: "fleet-operator"})

	require.Nil(t, listAsAdmin(t, admin, deleting)["administrator"].AggregatedFrom)
}

func ptr[T any](v T) *T {
	return &v
}
