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

package rbac_test

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// These tests compose PR #533's wildcard-binding mechanics with the REAL
// platform-reader role parsed from charts/identity/values.yaml, per the ID-399
// acceptance criteria. Generic mechanics (parse-time uni::* rejection,
// sentinel/empty-issuer guards, clamping, replace semantics) are pinned by
// bindings_test.go and are deliberately not repeated here.
func TestPlatformReaderWildcardBinding(t *testing.T) {
	t.Parallel()

	const (
		staffIssuer = "https://staff.example.com/"
		roleID      = "platform-reader-role-id"
	)

	reader, ok := loadChartRoles(t)["platform-reader"]
	require.True(t, ok, "platform-reader missing from chart role catalogue")

	roles := map[string]*unikornv1.Role{
		roleID: {
			Spec: unikornv1.RoleSpec{
				Scopes: unikornv1.RoleScopes{
					Global: toRoleScopes(reader.Scopes.Global),
				},
			},
		},
	}

	var bindings rbac.GlobalRoleBindingsValue

	require.NoError(t, bindings.Set(staffIssuer+"::*::"+roleID))

	// Positive: any subject from the staff issuer matches the wildcard.
	matched := rbac.ResolveGlobalRoleBindingsForTest(bindings, staffIssuer, "someone@nscale.com")
	require.Len(t, matched, 1)
	require.Equal(t, []string{roleID}, matched[0].RoleIDs)

	acl := &openapi.Acl{}
	require.NoError(t, rbac.AccumulateGlobalReadPermissionsForTest(acl, matched[0].RoleIDs, roles))
	require.NotNil(t, acl.Global)

	// The resolved ACL is exactly the role's scope set, read-only, with every
	// excluded scope absent. (Read-only-ness is structural on this path — the
	// wildcard accumulator clamps unconditionally; the role DEFINITION's
	// read-only-ness is what the contract test and the unclamped exact-binding
	// integration canary pin.)
	granted := make([]string, 0, len(*acl.Global))

	for _, endpoint := range *acl.Global {
		granted = append(granted, endpoint.Name)

		require.Equal(t, []openapi.AclOperation{openapi.Read}, endpoint.Operations,
			"ACL endpoint %q must be read-only", endpoint.Name)
	}

	require.ElementsMatch(t, slices.Collect(maps.Keys(reader.Scopes.Global)), granted)

	for scope := range platformReaderExcludedScopes() {
		require.NotContains(t, granted, scope, "excluded scope %q leaked into the ACL", scope)
	}

	// Authorization outcomes against the resolved ACL.
	ctx := rbac.NewContext(t.Context(), acl)

	require.NoError(t, rbac.AllowGlobalScope(ctx, "identity:organizations", openapi.Read))
	require.Error(t, rbac.AllowGlobalScope(ctx, "identity:organizations", openapi.Update),
		"write must be denied")
	require.Error(t, rbac.AllowGlobalScope(ctx, "storage:objectstorageendpoints/accesskeys", openapi.Read),
		"access-key read must be denied")

	// Negative — the acceptance-criterion scenario: a UNI-local principal
	// (src_iss = uni) facing the staff wildcard binding resolves no roles.
	require.Empty(t, rbac.ResolveGlobalRoleBindingsForTest(bindings, "uni", "someone@nscale.com"))
}
