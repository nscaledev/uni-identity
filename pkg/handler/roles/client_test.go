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

	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
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

// adminRole is administrator as the chart ships it: it refs its base role
// and selects roles labelled for it.  It has no status: no controller runs
// in these tests.
func adminRole(refs ...string) *unikornv1.Role {
	role := newRole("administrator", false, nil)
	role.Spec.AggregationRule = &unikornv1.RoleAggregationRule{
		RoleSelectors: []metav1.LabelSelector{
			{MatchLabels: map[string]string{unikornv1.AggregateToLabel("administrator"): "true"}},
		},
		RoleRefs:              refs,
		FlattenToOrganization: true,
	}

	return role
}

// fleetOperator is a service role labelled for administrator.
func fleetOperator() *unikornv1.Role {
	fleet := newRole("fleet-id", false, []unikornv1.RoleScope{
		{Name: "radar:topology", Operations: []unikornv1.Operation{unikornv1.Read}},
	})
	fleet.Labels["unikorn-cloud.org/name"] = "fleet-operator"
	fleet.Labels[unikornv1.AggregateToLabel("administrator")] = "true"
	fleet.Annotations = map[string]string{coreconstants.DescriptionAnnotation: "Fleet operator."}

	return fleet
}

// withStatus writes a status by hand, as a stale or tampered one would be.
func withStatus(role *unikornv1.Role, scopes []unikornv1.RoleScope, sources ...unikornv1.RoleAggregationSource) *unikornv1.Role {
	role.Status.EffectiveScopes = &unikornv1.RoleScopes{Organization: scopes}
	role.Status.AggregatedFrom = sources
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

	base := adminBase()

	got := listAsAdmin(t, adminRole(base.Name), base, fleetOperator())["administrator"]

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
		{Id: "fleet-id", Name: "fleet-operator", Description: ptr("Fleet operator.")},
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

// TestListFollowsChangedSources checks the API reports the sources as they
// are now, with no controller: after a source stops opting in, its scopes
// and its entry go, though status still names it.
func TestListFollowsChangedSources(t *testing.T) {
	t.Parallel()

	base := adminBase()
	fleet := fleetOperator()

	require.Len(t, *listAsAdmin(t, adminRole(base.Name), base, fleet)["administrator"].AggregatedFrom, 1)

	delete(fleet.Labels, unikornv1.AggregateToLabel("administrator"))

	stale := withStatus(adminRole(base.Name),
		[]unikornv1.RoleScope{{Name: "radar:topology", Operations: []unikornv1.Operation{unikornv1.Read}}},
		unikornv1.RoleAggregationSource{ID: "fleet-id", Name: "fleet-operator", ScopesHash: "sha256:bb"},
	)

	got := listAsAdmin(t, stale, base, fleet)["administrator"]
	require.Nil(t, got.AggregatedFrom)
	require.Equal(t, openapi.AclEndpoints{
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Read}},
	}, *got.Scopes.Organization)
}

// TestListIgnoresStatus checks scopes and sources written into status, by
// anyone, are never reported: a role with no sources holds nothing.
func TestListIgnoresStatus(t *testing.T) {
	t.Parallel()

	role := withStatus(adminRole(),
		[]unikornv1.RoleScope{{Name: "radar:topology", Operations: []unikornv1.Operation{unikornv1.Read}}},
		unikornv1.RoleAggregationSource{ID: "fleet-id", Name: "fleet-operator", ScopesHash: "sha256:bb"},
	)

	// fleet-id is live and not protected, but does not opt in.
	fleet := fleetOperator()
	delete(fleet.Labels, unikornv1.AggregateToLabel("administrator"))

	got := listAsAdmin(t, role, fleet)["administrator"]

	require.Nil(t, got.Scopes.Organization)
	require.Nil(t, got.AggregatedFrom)
}

// TestListNewAggregatingRoleReportsLiveScopes checks an aggregating role the
// controller has never seen reports what its sources give, and can be
// granted by a caller who holds that.
func TestListNewAggregatingRoleReportsLiveScopes(t *testing.T) {
	t.Parallel()

	base := adminBase()

	got := listAsAdmin(t, base, adminRole(base.Name))["administrator"]

	require.NotNil(t, got.Scopes.Organization)
	require.Equal(t, openapi.AclEndpoints{
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Read}},
	}, *got.Scopes.Organization)
	require.True(t, got.Grantable)
}

// TestListStuckRoleIsNotGrantable checks a stuck aggregating role reports
// what its working sources give, and is not grantable even by a caller who
// holds all of it.
func TestListStuckRoleIsNotGrantable(t *testing.T) {
	t.Parallel()

	base := adminBase()

	got := listAsAdmin(t, base, withStatus(adminRole(base.Name, "typo"), nil))["administrator"]

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
	base.Annotations = map[string]string{coreconstants.DescriptionAnnotation: "internal: do not expose"}

	byName := listAsAdmin(t, base, fleetOperator(), adminRole(base.Name))
	require.NotContains(t, byName, "administrator-base")

	got := byName["administrator"]
	require.NotNil(t, got.AggregatedFrom)
	require.Equal(t, []openapi.RoleSource{{Id: "fleet-id", Name: "fleet-operator", Description: ptr("Fleet operator.")}}, *got.AggregatedFrom)

	// Only protected sources: nothing to show, though the base is used.
	got = listAsAdmin(t, base, adminRole(base.Name))["administrator"]
	require.NotNil(t, got.Scopes.Organization)
	require.Nil(t, got.AggregatedFrom)
}

// TestListHidesSourcesThatAreGone checks aggregatedFrom never shows a source
// that no longer exists or is being deleted, even when status still names
// it.
func TestListHidesSourcesThatAreGone(t *testing.T) {
	t.Parallel()

	base := adminBase()

	deleting := fleetOperator()
	deleting.Finalizers = []string{"test"}
	now := metav1.Now()
	deleting.DeletionTimestamp = &now

	admin := withStatus(adminRole(base.Name),
		[]unikornv1.RoleScope{{Name: "radar:topology", Operations: []unikornv1.Operation{unikornv1.Read}}},
		unikornv1.RoleAggregationSource{ID: "gone-id", Name: "gone"},
		unikornv1.RoleAggregationSource{ID: "fleet-id", Name: "fleet-operator"},
	)

	got := listAsAdmin(t, admin, base, deleting)["administrator"]

	require.Nil(t, got.AggregatedFrom)
	require.Equal(t, openapi.AclEndpoints{
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Read}},
	}, *got.Scopes.Organization)
}

func ptr[T any](v T) *T {
	return &v
}
