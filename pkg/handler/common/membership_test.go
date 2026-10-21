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

package common_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/core/pkg/constants"
	servererrors "github.com/unikorn-cloud/core/pkg/server/errors"
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
	membershipNamespace      = "identity"
	membershipOrganizationID = "acbaf1e5-6414-4066-b74e-2d95dc766299"
	membershipRoleID         = "radar-id"
	membershipRoleName       = "radar"
)

// membershipRole builds a role scoped to an endpoint no built-in role holds, so only a
// caller whose ACL is extended to cover it can grant the role.
func membershipRole() *unikornv1.Role {
	return &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      membershipRoleID,
			Namespace: membershipNamespace,
			Labels:    map[string]string{constants.NameLabel: membershipRoleName},
		},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Organization: []unikornv1.RoleScope{
					{Name: "radar:things", Operations: []unikornv1.Operation{unikornv1.Read}},
				},
			},
		},
	}
}

func membershipClient(t *testing.T, roles ...*unikornv1.Role) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	builder := fake.NewClientBuilder().WithScheme(scheme)
	for _, role := range roles {
		builder = builder.WithObjects(role)
	}

	return builder.Build()
}

// membershipACL builds a context carrying an ACL that grants only the given
// organization-scoped endpoints in the test organization.
func membershipACL(endpoints openapi.AclEndpoints) context.Context {
	organizations := openapi.AclOrganizationList{{Id: membershipOrganizationID, Endpoints: &endpoints}}

	return rbac.NewContext(context.Background(), &openapi.Acl{Organizations: &organizations})
}

func membershipGroup(roleIDs ...string) *unikornv1.Group {
	return &unikornv1.Group{Spec: unikornv1.GroupSpec{RoleIDs: roleIDs}}
}

// membershipGroupList builds the organization's group list as a reconciler reads it.
func membershipGroupList(names ...string) *unikornv1.GroupList {
	list := &unikornv1.GroupList{}

	for _, name := range names {
		list.Items = append(list.Items, unikornv1.Group{
			ObjectMeta: metav1.ObjectMeta{Name: name},
		})
	}

	return list
}

func TestValidateGroupsExistAcceptsKnownGroups(t *testing.T) {
	t.Parallel()

	require.NoError(t, common.ValidateGroupsExist([]string{"group-a", "group-b"}, membershipGroupList("group-a", "group-b", "group-c")))
}

func TestValidateGroupsExistAcceptsAnEmptyRequest(t *testing.T) {
	t.Parallel()

	// Leaving every group is a legal write and names nothing to check.
	require.NoError(t, common.ValidateGroupsExist(nil, membershipGroupList("group-a")))
}

func TestValidateGroupsExistRefusesUnknownGroup(t *testing.T) {
	t.Parallel()

	// Reconciliation matches the request against the groups that exist, so an
	// ID matching none of them would otherwise be dropped from the write
	// without the caller being told.
	err := common.ValidateGroupsExist([]string{"group-a", "no-such-group"}, membershipGroupList("group-a"))
	require.Error(t, err)
	require.True(t, servererrors.IsBadRequest(err))
	require.Contains(t, err.Error(), "no-such-group", "the error must name the group that does not exist")
}

func TestValidateGroupsExistRefusesAgainstAnEmptyOrganization(t *testing.T) {
	t.Parallel()

	err := common.ValidateGroupsExist([]string{"group-a"}, membershipGroupList())
	require.Error(t, err)
	require.True(t, servererrors.IsBadRequest(err))
	require.Contains(t, err.Error(), "group-a")
}

func TestAllowGroupMembershipAdditionRefusesUngrantableRole(t *testing.T) {
	t.Parallel()

	cli := membershipClient(t, membershipRole())

	organizationID, err := ids.ParseOrganizationID(membershipOrganizationID)
	require.NoError(t, err)

	// The caller may edit users and groups, but holds nothing on radar:things,
	// so it cannot hand the group's role to a new member.
	ctx := membershipACL(openapi.AclEndpoints{
		{Name: "identity:users", Operations: openapi.AclOperations{openapi.Update}},
	})

	err = common.AllowGroupMembershipAddition(ctx, cli, membershipNamespace, organizationID, membershipGroup(membershipRoleID))
	require.Error(t, err)
	require.True(t, servererrors.IsForbidden(err))
	require.Contains(t, err.Error(), membershipRoleName)
	require.Contains(t, err.Error(), membershipRoleID)
}

func TestAllowGroupMembershipAdditionAllowsRoleHolder(t *testing.T) {
	t.Parallel()

	cli := membershipClient(t, membershipRole())

	organizationID, err := ids.ParseOrganizationID(membershipOrganizationID)
	require.NoError(t, err)

	// The grant traces to a holder: this caller has every permission the role
	// carries, so it may confer it.
	ctx := membershipACL(openapi.AclEndpoints{
		{Name: "radar:things", Operations: openapi.AclOperations{openapi.Read}},
	})

	require.NoError(t, common.AllowGroupMembershipAddition(ctx, cli, membershipNamespace, organizationID, membershipGroup(membershipRoleID)))
}

func TestAllowGroupMembershipAdditionRefusesDanglingRole(t *testing.T) {
	t.Parallel()

	cli := membershipClient(t)

	organizationID, err := ids.ParseOrganizationID(membershipOrganizationID)
	require.NoError(t, err)

	ctx := membershipACL(openapi.AclEndpoints{
		{Name: "identity:users", Operations: openapi.AclOperations{openapi.Update}},
	})

	// A role reference that does not resolve cannot be grant-checked, and role
	// IDs are a hash of the role name, so the same ID comes back if the role is
	// ever re-applied and re-binds to every group still referencing it.  A
	// member parked in the group meanwhile would gain the role without anyone
	// having authorised it, so the addition is refused rather than waved
	// through.
	err = common.AllowGroupMembershipAddition(ctx, cli, membershipNamespace, organizationID, membershipGroup("no-such-role"))
	require.Error(t, err)
	require.True(t, servererrors.IsForbidden(err))
	require.Contains(t, err.Error(), "no-such-role", "the error must name the role that cannot be resolved")
}

func TestAllowGroupMembershipAdditionAllowsRolelessGroup(t *testing.T) {
	t.Parallel()

	cli := membershipClient(t, membershipRole())

	organizationID, err := ids.ParseOrganizationID(membershipOrganizationID)
	require.NoError(t, err)

	ctx := membershipACL(openapi.AclEndpoints{
		{Name: "identity:users", Operations: openapi.AclOperations{openapi.Update}},
	})

	// A group with no roles confers nothing, so membership in it is not a grant.
	require.NoError(t, common.AllowGroupMembershipAddition(ctx, cli, membershipNamespace, organizationID, membershipGroup()))
}

func TestAllowGroupMembershipAdditionChecksLiveAggregation(t *testing.T) {
	t.Parallel()

	aggregate := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aggregate-id",
			Namespace: membershipNamespace,
			Labels:    map[string]string{constants.NameLabel: "aggregate"},
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
				{Type: string(unikornv1core.ConditionAvailable), Status: metav1.ConditionTrue, Reason: unikornv1.RoleReasonAggregated},
			},
		},
	}

	source := membershipRole()
	source.Labels[unikornv1.AggregateToLabel("aggregate-id")] = "true"

	cli := membershipClient(t, aggregate, source)

	organizationID, err := ids.ParseOrganizationID(membershipOrganizationID)
	require.NoError(t, err)

	nobody := membershipACL(openapi.AclEndpoints{
		{Name: "identity:users", Operations: openapi.AclOperations{openapi.Update}},
	})

	err = common.AllowGroupMembershipAddition(nobody, cli, membershipNamespace, organizationID, membershipGroup("aggregate-id"))
	require.Error(t, err)
	require.True(t, servererrors.IsForbidden(err))

	holder := membershipACL(openapi.AclEndpoints{
		{Name: "radar:things", Operations: openapi.AclOperations{openapi.Read}},
	})

	require.NoError(t, common.AllowGroupMembershipAddition(holder, cli, membershipNamespace, organizationID, membershipGroup("aggregate-id")))
}

var errMembershipList = errors.New("list failed")

func countingMembershipClient(t *testing.T, fail bool, roles ...*unikornv1.Role) (client.Client, *atomic.Int32) {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	lists := &atomic.Int32{}

	builder := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		List: func(ctx context.Context, cli client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			lists.Add(1)

			if fail {
				return errMembershipList
			}

			return cli.List(ctx, list, opts...)
		},
	})

	for _, role := range roles {
		builder = builder.WithObjects(role)
	}

	return builder.Build(), lists
}

func membershipAggregatingRole(id string) *unikornv1.Role {
	return &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      id,
			Namespace: membershipNamespace,
			Labels:    map[string]string{constants.NameLabel: id},
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

func TestAllowGroupMembershipAdditionListsOnce(t *testing.T) {
	t.Parallel()

	roles := func() []*unikornv1.Role {
		source := membershipRole()
		source.Labels[unikornv1.AggregateToLabel("agg-a")] = "true"
		source.Labels[unikornv1.AggregateToLabel("agg-b")] = "true"
		source.Labels[unikornv1.AggregateToLabel("agg-c")] = "true"

		return []*unikornv1.Role{source, membershipAggregatingRole("agg-a"), membershipAggregatingRole("agg-b"), membershipAggregatingRole("agg-c")}
	}

	organizationID, err := ids.ParseOrganizationID(membershipOrganizationID)
	require.NoError(t, err)

	holder := membershipACL(openapi.AclEndpoints{
		{Name: "radar:things", Operations: openapi.AclOperations{openapi.Read}},
	})

	cli, lists := countingMembershipClient(t, false, roles()...)

	require.NoError(t, common.AllowGroupMembershipAddition(holder, cli, membershipNamespace, organizationID, membershipGroup("agg-a", "agg-b", "agg-c", membershipRoleID)))
	require.Equal(t, int32(1), lists.Load())

	cli, lists = countingMembershipClient(t, false, roles()...)

	require.NoError(t, common.AllowGroupMembershipAddition(holder, cli, membershipNamespace, organizationID, membershipGroup(membershipRoleID)))
	require.Zero(t, lists.Load())
}

func TestAllowGroupMembershipAdditionListErrorFailsClosed(t *testing.T) {
	t.Parallel()

	cli, _ := countingMembershipClient(t, true, membershipAggregatingRole("agg-a"))

	organizationID, err := ids.ParseOrganizationID(membershipOrganizationID)
	require.NoError(t, err)

	err = common.AllowGroupMembershipAddition(membershipACL(openapi.AclEndpoints{}), cli, membershipNamespace, organizationID, membershipGroup("agg-a"))
	require.ErrorIs(t, err, errMembershipList)
}
