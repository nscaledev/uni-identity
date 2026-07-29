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

package serviceaccounts

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace      = "identity"
	testOrgNS          = "test-org-ns"
	testOrganizationID = "acbaf1e5-6414-4066-b74e-2d95dc766299"

	testGroupID          = "radar-group"
	testCleanGroupID     = "clean-group"
	testServiceAccountID = "sa-a"
	testRoleID           = "radar-id"
	testRoleName         = "radar"
)

// testRole builds a role scoped to an endpoint no built-in role holds, so only a caller
// whose ACL is extended to cover it can grant the role.
func testRole() *unikornv1.Role {
	return &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testRoleID,
			Namespace: testNamespace,
			Labels:    map[string]string{constants.NameLabel: testRoleName},
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

// testGroup builds a group already carrying the ungrantable role, standing in for one
// seeded by a third-party service or a more privileged admin.
func testGroup(serviceAccountIDs ...string) *unikornv1.Group {
	return &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testGroupID,
			Namespace: testOrgNS,
		},
		Spec: unikornv1.GroupSpec{
			RoleIDs:           []string{testRoleID},
			ServiceAccountIDs: serviceAccountIDs,
		},
	}
}

// cleanGroup builds a group carrying no roles, so joining it is never a grant.  Its name
// sorts before the radar group's, so a reconciliation reaches it first.
func cleanGroup() *unikornv1.Group {
	return &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testCleanGroupID,
			Namespace: testOrgNS,
		},
	}
}

func testFixture(t *testing.T, objects ...client.Object) (*Client, client.Client) {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	organization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testOrganizationID,
		},
		Status: unikornv1.OrganizationStatus{
			Namespace: testOrgNS,
		},
	}

	objects = append([]client.Object{organization}, objects...)

	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

	// Membership reconciliation needs only the Kubernetes client and the
	// identity namespace.  The token issuer is left nil deliberately: nothing
	// on these paths may mint a token, and a refused create in particular must
	// bail out before it would.
	return &Client{client: cli, namespace: testNamespace}, cli
}

// testACL builds a context carrying an ACL granting only the given organization-scoped
// endpoints in the test organization, over the authorization and principal info the
// handlers stamp onto anything they create.
func testACL(endpoints openapi.AclEndpoints) context.Context {
	ctx := authorization.NewContext(context.Background(), &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: "test-subject",
		},
	})

	ctx = principal.NewContext(ctx, &principal.Principal{
		Actor: "test-principal",
	})

	organizations := openapi.AclOrganizationList{{Id: testOrganizationID, Endpoints: &endpoints}}

	return rbac.NewContext(ctx, &openapi.Acl{Organizations: &organizations})
}

func listGroups(t *testing.T, cli client.Client) *unikornv1.GroupList {
	t.Helper()

	groups := &unikornv1.GroupList{}
	require.NoError(t, cli.List(t.Context(), groups, &client.ListOptions{Namespace: testOrgNS}))

	return groups
}

func getGroup(t *testing.T, cli client.Client) *unikornv1.Group {
	t.Helper()

	return getNamedGroup(t, cli, testGroupID)
}

func getNamedGroup(t *testing.T, cli client.Client, name string) *unikornv1.Group {
	t.Helper()

	group := &unikornv1.Group{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Namespace: testOrgNS, Name: name}, group))

	return group
}

// TestUpdateGroupsRefusesAdditionToUngrantableRoleGroup covers the grant hidden inside a
// service account write: joining a group hands the account every role the group carries,
// so it is refused unless the caller could grant those roles.
func TestUpdateGroupsRefusesAdditionToUngrantableRoleGroup(t *testing.T) {
	t.Parallel()

	c, cli := testFixture(t, testRole(), testGroup())

	organizationID, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	ctx := testACL(openapi.AclEndpoints{
		{Name: "identity:serviceaccounts", Operations: openapi.AclOperations{openapi.Update}},
	})

	err = c.updateGroups(ctx, organizationID, testServiceAccountID, openapi.GroupIDs{testGroupID}, listGroups(t, cli))
	require.Error(t, err)
	require.True(t, errors.IsForbidden(err))
	assert.Contains(t, err.Error(), testRoleName)

	assert.Empty(t, getGroup(t, cli).Spec.ServiceAccountIDs)
}

// TestUpdateGroupsRefusesEveryAdditionWhenOneIsRefused pins the write down as one unit: a
// request joining a harmless group and an ungrantable one must leave both alone, even
// though the harmless one is reached first.
func TestUpdateGroupsRefusesEveryAdditionWhenOneIsRefused(t *testing.T) {
	t.Parallel()

	c, cli := testFixture(t, testRole(), cleanGroup(), testGroup())

	organizationID, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	ctx := testACL(openapi.AclEndpoints{
		{Name: "identity:serviceaccounts", Operations: openapi.AclOperations{openapi.Update}},
	})

	err = c.updateGroups(ctx, organizationID, testServiceAccountID, openapi.GroupIDs{testCleanGroupID, testGroupID}, listGroups(t, cli))
	require.Error(t, err)
	require.True(t, errors.IsForbidden(err))
	assert.Contains(t, err.Error(), testRoleName)

	assert.Empty(t, getNamedGroup(t, cli, testCleanGroupID).Spec.ServiceAccountIDs,
		"the permitted addition must not land when another in the same write is refused")
	assert.Empty(t, getGroup(t, cli).Spec.ServiceAccountIDs)
}

// TestUpdateGroupsAllowsAdditionByRoleHolder is the other half of the gate: the grant
// traces to a holder, so a caller who holds radar:things may confer it.
func TestUpdateGroupsAllowsAdditionByRoleHolder(t *testing.T) {
	t.Parallel()

	c, cli := testFixture(t, testRole(), testGroup())

	organizationID, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	ctx := testACL(openapi.AclEndpoints{
		{Name: "radar:things", Operations: openapi.AclOperations{openapi.Read}},
	})

	require.NoError(t, c.updateGroups(ctx, organizationID, testServiceAccountID, openapi.GroupIDs{testGroupID}, listGroups(t, cli)))
	assert.Equal(t, []string{testServiceAccountID}, getGroup(t, cli).Spec.ServiceAccountIDs)
}

// TestCreateRefusesUngrantableGroupWithoutPersistingTheAccount pins the ordering on the
// create path: the grant is settled before the account exists.  Creating it first and
// discovering the refusal afterwards would strand a service account, with a token already
// issued, that the caller never got told about.
func TestCreateRefusesUngrantableGroupWithoutPersistingTheAccount(t *testing.T) {
	t.Parallel()

	c, cli := testFixture(t, testRole(), testGroup())

	organizationID, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	ctx := testACL(openapi.AclEndpoints{
		{Name: "identity:serviceaccounts", Operations: openapi.AclOperations{openapi.Create}},
	})

	request := &openapi.ServiceAccountWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{Name: "refused-sa"},
		Spec: openapi.ServiceAccountSpec{
			GroupIDs: openapi.GroupIDs{testGroupID},
		},
	}

	_, err = c.Create(ctx, organizationID, request)
	require.Error(t, err)
	require.True(t, errors.IsForbidden(err))
	assert.Contains(t, err.Error(), testRoleName)

	accounts := &unikornv1.ServiceAccountList{}
	require.NoError(t, cli.List(t.Context(), accounts, &client.ListOptions{Namespace: testOrgNS}))
	assert.Empty(t, accounts.Items,
		"a refused create must not leave a service account behind")

	assert.Empty(t, getGroup(t, cli).Spec.ServiceAccountIDs)
}

// TestUpdateGroupsAllowsRemovalFromUngrantableRoleGroup shows removal confers nothing and
// stays ungated, so a group can still be managed down by a caller who could not add to it.
func TestUpdateGroupsAllowsRemovalFromUngrantableRoleGroup(t *testing.T) {
	t.Parallel()

	c, cli := testFixture(t, testRole(), testGroup(testServiceAccountID))

	organizationID, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	ctx := testACL(openapi.AclEndpoints{
		{Name: "identity:serviceaccounts", Operations: openapi.AclOperations{openapi.Update}},
	})

	require.NoError(t, c.updateGroups(ctx, organizationID, testServiceAccountID, openapi.GroupIDs{}, listGroups(t, cli)))

	group := getGroup(t, cli)
	assert.Empty(t, group.Spec.ServiceAccountIDs)
	assert.Equal(t, []string{testRoleID}, group.Spec.RoleIDs)
}

// TestUpdateGroupsAllowsDeletionUnlink covers the delete path, which passes no group IDs at
// all: stripping memberships as cleanup confers nothing and must not be gated.
func TestUpdateGroupsAllowsDeletionUnlink(t *testing.T) {
	t.Parallel()

	c, cli := testFixture(t, testRole(), testGroup(testServiceAccountID))

	organizationID, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	ctx := testACL(openapi.AclEndpoints{
		{Name: "identity:serviceaccounts", Operations: openapi.AclOperations{openapi.Delete}},
	})

	require.NoError(t, c.updateGroups(ctx, organizationID, testServiceAccountID, nil, listGroups(t, cli)))
	assert.Empty(t, getGroup(t, cli).Spec.ServiceAccountIDs)
}

// TestUpdateGroupsAllowsReaffirmingExistingMembership shows the gate keys on the change,
// not the request: re-sending a membership the account already has is not a new grant.
func TestUpdateGroupsAllowsReaffirmingExistingMembership(t *testing.T) {
	t.Parallel()

	c, cli := testFixture(t, testRole(), testGroup(testServiceAccountID))

	organizationID, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	ctx := testACL(openapi.AclEndpoints{
		{Name: "identity:serviceaccounts", Operations: openapi.AclOperations{openapi.Update}},
	})

	require.NoError(t, c.updateGroups(ctx, organizationID, testServiceAccountID, openapi.GroupIDs{testGroupID}, listGroups(t, cli)))
	assert.Equal(t, []string{testServiceAccountID}, getGroup(t, cli).Spec.ServiceAccountIDs)
}
