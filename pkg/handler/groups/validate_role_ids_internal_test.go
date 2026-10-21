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

package groups

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	// Must match the value in the external test package in this directory: a
	// test moved between the two files would otherwise silently read a
	// different namespace, where a NotFound on a role reads as an exemption
	// rather than a failure.
	testNamespace      = "test-namespace"
	testOrganizationID = "acbaf1e5-6414-4066-b74e-2d95dc766299"
)

func testClient(t *testing.T, roles ...*unikornv1.Role) *Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	builder := fake.NewClientBuilder().WithScheme(scheme)
	for _, role := range roles {
		builder = builder.WithObjects(role)
	}

	// Match New's real signature (client, namespace, issuer); the issuer is
	// unused by role validation — pass its zero value.
	return New(builder.Build(), testNamespace, common.IssuerValue{})
}

func testACL(endpoints openapi.AclEndpoints) context.Context {
	organizations := openapi.AclOrganizationList{{Id: testOrganizationID, Endpoints: &endpoints}}
	return rbac.NewContext(context.Background(), &openapi.Acl{Organizations: &organizations})
}

func testRole(id, name string, protected bool, endpoint string) *unikornv1.Role {
	return &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      id,
			Namespace: testNamespace,
			Labels:    map[string]string{"unikorn-cloud.org/name": name},
		},
		Spec: unikornv1.RoleSpec{
			Protected: protected,
			Scopes: unikornv1.RoleScopes{
				Organization: []unikornv1.RoleScope{{Name: endpoint, Operations: []unikornv1.Operation{unikornv1.Read}}},
			},
		},
	}
}

func TestValidateRoleIDsChecksOnlyAdditions(t *testing.T) {
	t.Parallel()

	radar := testRole("radar-id", "radar", false, "radar:things")
	basic := testRole("basic-id", "basic", false, "identity:groups")
	c := testClient(t, radar, basic)

	orgID, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	// Caller holds identity:groups but nothing radar.
	ctx := testACL(openapi.AclEndpoints{{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Read}}})

	// Create (no current): every role is an addition — radar refused, named.
	_, err = c.validateRoleIDs(ctx, orgID, []string{"radar-id"}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "radar")

	// Update re-sending an existing radar role: not an addition — allowed.
	// A write that leaves the role list alone must not fail on roles that
	// were already on the group.
	_, err = c.validateRoleIDs(ctx, orgID, []string{"radar-id", "basic-id"}, []string{"radar-id"})
	require.NoError(t, err)

	// Adding radar to a group that does not have it: refused.
	_, err = c.validateRoleIDs(ctx, orgID, []string{"radar-id", "basic-id"}, []string{"basic-id"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "radar")
}

func TestValidateRoleIDsProtectedAndMissing(t *testing.T) {
	t.Parallel()

	hidden := testRole("hidden-id", "hidden", true, "identity:groups")
	c := testClient(t, hidden)

	orgID, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	ctx := testACL(openapi.AclEndpoints{{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Read}}})

	// Protected roles are refused even when already on the group — they
	// should never be on an API-managed group at all.
	_, err = c.validateRoleIDs(ctx, orgID, []string{"hidden-id"}, []string{"hidden-id"})
	require.Error(t, err)

	// Unknown role IDs are refused with a clear error.
	_, err = c.validateRoleIDs(ctx, orgID, []string{"nope"}, nil)
	require.Error(t, err)
}

func TestValidateRoleIDsChecksLiveAggregation(t *testing.T) {
	t.Parallel()

	aggregate := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aggregate-id",
			Namespace: testNamespace,
			Labels:    map[string]string{"unikorn-cloud.org/name": "aggregate"},
		},
		Spec: unikornv1.RoleSpec{
			AggregationRule: &unikornv1.RoleAggregationRule{
				RoleSelectors: []metav1.LabelSelector{
					{MatchLabels: map[string]string{unikornv1.AggregateToLabel("aggregate-id"): "true"}},
				},
			},
		},
		Status: unikornv1.RoleStatus{
			EffectiveScopes: &unikornv1.RoleScopes{},
			Conditions: []metav1.Condition{
				{Type: "Available", Status: metav1.ConditionTrue, Reason: unikornv1.RoleReasonAggregated},
			},
		},
	}

	radar := testRole("radar-id", "radar", false, "radar:things")
	radar.Labels[unikornv1.AggregateToLabel("aggregate-id")] = "true"

	c := testClient(t, aggregate, radar)

	orgID, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	nobody := testACL(openapi.AclEndpoints{{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Read}}})

	_, err = c.validateRoleIDs(nobody, orgID, []string{"aggregate-id"}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "aggregate")

	holder := testACL(openapi.AclEndpoints{{Name: "radar:things", Operations: openapi.AclOperations{openapi.Read}}})

	_, err = c.validateRoleIDs(holder, orgID, []string{"aggregate-id"}, nil)
	require.NoError(t, err)
}

var errListFailed = errors.New("list failed")

func countingClient(t *testing.T, fail bool, roles ...*unikornv1.Role) (*Client, *atomic.Int32) {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	lists := &atomic.Int32{}

	builder := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		List: func(ctx context.Context, cli client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			lists.Add(1)

			if fail {
				return errListFailed
			}

			return cli.List(ctx, list, opts...)
		},
	})

	for _, role := range roles {
		builder = builder.WithObjects(role)
	}

	return New(builder.Build(), testNamespace, common.IssuerValue{}), lists
}

func aggregatingRole(id string) *unikornv1.Role {
	return &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      id,
			Namespace: testNamespace,
			Labels:    map[string]string{"unikorn-cloud.org/name": id},
		},
		Spec: unikornv1.RoleSpec{
			AggregationRule: &unikornv1.RoleAggregationRule{
				RoleSelectors: []metav1.LabelSelector{
					{MatchLabels: map[string]string{unikornv1.AggregateToLabel(id): "true"}},
				},
			},
		},
	}
}

func TestValidateRoleIDsListsOncePerRequest(t *testing.T) {
	t.Parallel()

	radar := testRole("radar-id", "radar", false, "radar:things")
	radar.Labels[unikornv1.AggregateToLabel("agg-a")] = "true"
	radar.Labels[unikornv1.AggregateToLabel("agg-b")] = "true"
	radar.Labels[unikornv1.AggregateToLabel("agg-c")] = "true"

	roles := func() []*unikornv1.Role {
		return []*unikornv1.Role{
			aggregatingRole("agg-a"), aggregatingRole("agg-b"), aggregatingRole("agg-c"),
			radar.DeepCopy(), testRole("basic-id", "basic", false, "identity:groups"),
		}
	}

	orgID, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	holder := testACL(openapi.AclEndpoints{
		{Name: "radar:things", Operations: openapi.AclOperations{openapi.Read}},
		{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Read}},
	})

	c, lists := countingClient(t, false, roles()...)

	_, err = c.validateRoleIDs(holder, orgID, []string{"agg-a", "agg-b", "agg-c", "basic-id"}, nil)
	require.NoError(t, err)
	require.Equal(t, int32(1), lists.Load())

	c, lists = countingClient(t, false, roles()...)

	_, err = c.validateRoleIDs(holder, orgID, []string{"radar-id", "basic-id"}, nil)
	require.NoError(t, err)
	require.Zero(t, lists.Load())

	// The existing aggregating role is not resolved, so no list.
	c, lists = countingClient(t, false, roles()...)

	_, err = c.validateRoleIDs(holder, orgID, []string{"agg-a", "basic-id"}, []string{"agg-a"})
	require.NoError(t, err)
	require.Zero(t, lists.Load())
}

func TestValidateRoleIDsListErrorFailsClosed(t *testing.T) {
	t.Parallel()

	c, _ := countingClient(t, true, aggregatingRole("agg-a"))

	orgID, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	_, err = c.validateRoleIDs(testACL(openapi.AclEndpoints{}), orgID, []string{"agg-a"}, nil)
	require.ErrorIs(t, err, errListFailed)
}
