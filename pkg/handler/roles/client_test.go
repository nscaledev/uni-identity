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
	"testing"

	"github.com/stretchr/testify/require"

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
