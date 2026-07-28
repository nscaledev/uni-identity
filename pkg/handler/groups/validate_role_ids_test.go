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

package groups //nolint:testpackage // exercises unexported validation helpers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testNamespace      = "identity"
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
	// This is the reported bug: members-only edits must not fail on roles
	// that were already on the group.
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

func TestValidateRoleRemovalsRejectsUngrantableDrop(t *testing.T) {
	t.Parallel()

	radar := testRole("radar-id", "radar", false, "radar:things")
	c := testClient(t, radar)

	orgID, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	current := &unikornv1.Group{Spec: unikornv1.GroupSpec{RoleIDs: []string{"radar-id"}}}

	// Caller cannot grant radar: dropping it must be rejected, naming it.
	// Without this, a client that cannot resolve the role silently revokes
	// it by round-tripping the group.
	ctx := testACL(openapi.AclEndpoints{{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Update}}})
	err = c.validateRoleRemovals(ctx, orgID, current, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "radar")

	// Keeping it is fine (no removal).
	require.NoError(t, c.validateRoleRemovals(ctx, orgID, current, []string{"radar-id"}))

	// A caller who CAN grant radar may drop it.
	ctx = testACL(openapi.AclEndpoints{{Name: "radar:things", Operations: openapi.AclOperations{openapi.Read}}})
	require.NoError(t, c.validateRoleRemovals(ctx, orgID, current, nil))

	// A dangling role reference (role deleted) may always be dropped.
	dangling := &unikornv1.Group{Spec: unikornv1.GroupSpec{RoleIDs: []string{"no-such-role"}}}
	require.NoError(t, c.validateRoleRemovals(ctx, orgID, dangling, nil))
}
