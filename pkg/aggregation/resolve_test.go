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

package aggregation_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/aggregation"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// These tests check enforcement runs on what roles hold now: no controller
// runs here, and status is only ever stale or tampered.

const testNamespace = "identity"

var errListed = errors.New("listed roles")

func fakeClient(t *testing.T, funcs interceptor.Funcs, roles ...*unikornv1.Role) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	builder := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(funcs)

	for _, role := range roles {
		role.Namespace = testNamespace
		builder = builder.WithObjects(role)
	}

	return builder.Build()
}

// loadAdministrator gets the administrator role and resolves it, as the
// grant handlers do.
func loadAdministrator(t *testing.T, cli client.Client) *unikornv1.Role {
	t.Helper()

	role := &unikornv1.Role{}
	require.NoError(t, cli.Get(t.Context(), types.NamespacedName{Namespace: testNamespace, Name: "administrator"}, role))
	require.NoError(t, aggregation.ResolveRole(t.Context(), cli, role))

	return role
}

// TestStaleStatusIsIgnored checks a status that says a role holds less than
// its sources give now, and is Available, changes nothing: the role holds
// what its sources give, and a caller holding only what status says cannot
// grant it.
func TestStaleStatusIsIgnored(t *testing.T) {
	t.Parallel()

	stale := unikornv1.RoleScopes{Organization: []unikornv1.RoleScope{scope("svc:a", unikornv1.Read)}}

	roles := catalogue(
		newRole("administrator", aggregates(true), availableStatus(stale),
			recorded("source", stale)),
		newRole("source", aggregateTo("administrator"), org(scope("svc:a", unikornv1.Read), scope("svc:b", unikornv1.Delete))),
	)

	aggregation.Resolve(roles)

	admin := roles["administrator"]
	require.Equal(t, []unikornv1.RoleScope{scope("svc:a", unikornv1.Read), scope("svc:b", unikornv1.Delete)}, admin.EffectiveScopes().Organization)
	require.Equal(t, stale, *admin.Status.EffectiveScopes, "Resolve never writes status")

	organizationID := ids.MustParseOrganizationID(testOrganizationID)

	require.Error(t, rbac.AllowRole(holderACL(t, endpoint("svc:a", openapi.Read)), admin, organizationID))
	require.NoError(t, rbac.AllowRole(holderACL(t, endpoint("svc:a", openapi.Read), endpoint("svc:b", openapi.Delete)), admin, organizationID))
}

// TestTamperedStatusIsIgnored checks a status someone wrote by hand, naming
// scopes and a source the role does not have, gives nothing.
func TestTamperedStatusIsIgnored(t *testing.T) {
	t.Parallel()

	roles := catalogue(
		newRole("administrator", aggregates(true), availableStatus(evilScopes()), recorded("evil", evilScopes())),
		newRole("source", aggregateTo("administrator"), org(scope("svc:a", unikornv1.Read))),
	)

	aggregation.Resolve(roles)

	admin := roles["administrator"]
	require.Equal(t, []unikornv1.RoleScope{scope("svc:a", unikornv1.Read)}, admin.EffectiveScopes().Organization)
	require.Equal(t, []string{"source"}, sourceIDs(&aggregation.Result{AggregatedFrom: admin.Computed.Sources}))
}

// TestSourceNarrowingIsEnforcedAtOnce checks a scope a source drops is gone
// from the aggregating role at the next resolve, with no controller.
func TestSourceNarrowingIsEnforcedAtOnce(t *testing.T) {
	t.Parallel()

	source := newRole("source", aggregateTo("administrator"), org(scope("svc:a", unikornv1.Read), scope("svc:danger", unikornv1.Delete)))
	cli := fakeClient(t, interceptor.Funcs{}, newRole("administrator", aggregates(true)), source)

	require.Contains(t, loadAdministrator(t, cli).EffectiveScopes().Organization, scope("svc:danger", unikornv1.Delete))

	source.Spec.Scopes.Organization = []unikornv1.RoleScope{scope("svc:a", unikornv1.Read)}
	require.NoError(t, cli.Update(t.Context(), source))

	require.Equal(t, []unikornv1.RoleScope{scope("svc:a", unikornv1.Read)}, loadAdministrator(t, cli).EffectiveScopes().Organization)
}

// TestSourceWideningIsCheckedAtOnce checks a scope a source adds is part of
// the grant check at the next resolve, with no controller: a caller who held
// everything before cannot grant the role once it holds more.
func TestSourceWideningIsCheckedAtOnce(t *testing.T) {
	t.Parallel()

	source := newRole("source", aggregateTo("administrator"), org(scope("svc:a", unikornv1.Read)))
	cli := fakeClient(t, interceptor.Funcs{}, newRole("administrator", aggregates(true)), source)

	organizationID := ids.MustParseOrganizationID(testOrganizationID)
	caller := holderACL(t, endpoint("svc:a", openapi.Read))

	require.NoError(t, rbac.AllowRole(caller, loadAdministrator(t, cli), organizationID))

	source.Spec.Scopes.Organization = append(source.Spec.Scopes.Organization, scope("svc:b", unikornv1.Delete))
	require.NoError(t, cli.Update(t.Context(), source))

	require.Error(t, rbac.AllowRole(caller, loadAdministrator(t, cli), organizationID))
}

// TestResolveRoleSkipsPlainRole checks ResolveRole does not list roles for
// a role that does not aggregate.
func TestResolveRoleSkipsPlainRole(t *testing.T) {
	t.Parallel()

	failList := interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errListed
		},
	}

	role := newRole("plain", org(scope("svc:a", unikornv1.Read)))
	cli := fakeClient(t, failList, role)

	require.NoError(t, aggregation.ResolveRole(t.Context(), cli, role))
	require.Nil(t, role.Computed)
	require.Equal(t, role.Spec.Scopes, role.EffectiveScopes())
}

// TestResolveRoleListErrorFailsClosed checks an aggregating role that could
// not be resolved holds nothing and cannot be granted.
func TestResolveRoleListErrorFailsClosed(t *testing.T) {
	t.Parallel()

	failList := interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errListed
		},
	}

	role := newRole("administrator", aggregates(true))
	cli := fakeClient(t, failList, role, newRole("source", aggregateTo("administrator"), org(scope("svc:a", unikornv1.Read))))

	require.ErrorIs(t, aggregation.ResolveRole(t.Context(), cli, role), errListed)
	require.Empty(t, role.EffectiveScopes().Organization)
	require.False(t, role.AggregationReady())
}
