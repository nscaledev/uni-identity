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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestImpersonatedActorSubjectIsFoldedBeforeBindingMatch pins the comparison
// side that the ID-408 fold reached last.  The X-Principal actor comes from the
// principal.unikorn-cloud.org/creator annotation, which the migration
// deliberately leaves alone because it is provenance, so it can still carry the
// pre-migration case.  A global role binding is canonical lower case, because
// the chart refuses to render any other form.  Without folding the actor, a
// delegated request silently loses every binding-derived and group-derived
// grant: it fails closed, so no test of a permitted action catches it.
func TestImpersonatedActorSubjectIsFoldedBeforeBindingMatch(t *testing.T) {
	t.Parallel()

	const boundRoleID = "role-uni-binding-casing"

	boundRole := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      boundRoleID,
		},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Global: []unikornv1.RoleScope{
					{Name: "identity:organizations", Operations: []unikornv1.Operation{unikornv1.Read}},
				},
			},
		},
	}

	f := setupImpersonationEnvironmentWithBindings(t,
		[]unikornv1.RoleScope{
			{Name: "identity:organizations", Operations: []unikornv1.Operation{unikornv1.Read}},
		},
		rbac.Options{
			GlobalRoleBindings: rbac.GlobalRoleBindingsValue{
				{Issuer: constants.UNISentinel, Subject: userBobSubject, RoleIDs: []string{boundRoleID}},
			},
		},
		boundRole,
	)

	acl := impersonate(t, f, "Bob@Example.com")

	require.NotNil(t, acl.Global, "a mixed-case actor must still match its canonical binding")
	assert.Equal(t, openapi.AclEndpoints{
		{Name: "identity:organizations", Operations: []openapi.AclOperation{openapi.Read}},
	}, *acl.Global)
}
