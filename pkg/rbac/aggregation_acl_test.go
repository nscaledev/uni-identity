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

	"github.com/stretchr/testify/require"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	roleAggregateID = "role-aggregate"
	roleSourceID    = "role-source"
	groupAggregate  = "group-aggregate"

	userDaveSubject = "dave@example.com"
	userDaveID      = "user-dave"
)

func organizationEndpointNames(acl *openapi.Acl) []string {
	if acl.Organization == nil || acl.Organization.Endpoints == nil {
		return nil
	}

	names := make([]string, 0, len(*acl.Organization.Endpoints))

	for _, endpoint := range *acl.Organization.Endpoints {
		names = append(names, endpoint.Name)
	}

	return names
}

func TestACLUsesLiveAggregation(t *testing.T) {
	t.Parallel()

	f, c := setupTestEnvironment(t)

	source := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      roleSourceID,
			Labels:    map[string]string{unikornv1.AggregateToLabel(roleAggregateID): "true"},
		},
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Organization: []unikornv1.RoleScope{
					{Name: "org:read", Operations: []unikornv1.Operation{unikornv1.Read}},
					{Name: "project:read", Operations: []unikornv1.Operation{unikornv1.Read}},
				},
			},
		},
	}

	// Status claims org:manage and Available; nothing reads it.
	aggregate := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      roleAggregateID,
		},
		Spec: unikornv1.RoleSpec{
			AggregationRule: &unikornv1.RoleAggregationRule{
				RoleSelectors: []metav1.LabelSelector{
					{MatchLabels: map[string]string{unikornv1.AggregateToLabel(roleAggregateID): "true"}},
				},
			},
		},
		Status: unikornv1.RoleStatus{
			EffectiveScopes: &unikornv1.RoleScopes{
				Organization: []unikornv1.RoleScope{
					{Name: "org:manage", Operations: []unikornv1.Operation{unikornv1.Create, unikornv1.Read, unikornv1.Update, unikornv1.Delete}},
				},
			},
			Conditions: []metav1.Condition{
				{Type: string(unikornv1core.ConditionAvailable), Status: metav1.ConditionTrue, Reason: unikornv1.RoleReasonAggregated},
			},
		},
	}

	group := &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testOrgNS,
			Name:      groupAggregate,
		},
		Spec: unikornv1.GroupSpec{
			RoleIDs: []string{roleAggregateID},
		},
	}

	require.NoError(t, c.Create(t.Context(), source))
	require.NoError(t, c.Create(t.Context(), aggregate))
	require.NoError(t, c.Create(t.Context(), group))

	stored := &unikornv1.Role{}
	require.NoError(t, c.Get(t.Context(), types.NamespacedName{Namespace: testNamespace, Name: roleAggregateID}, stored))
	require.Equal(t, "org:manage", stored.Status.EffectiveScopes.Organization[0].Name)

	createUser(t, c, userDaveID, userDaveSubject, []*unikornv1.Group{group})

	require.ElementsMatch(t, []string{"org:read", "project:read"}, organizationEndpointNames(getACLForUser(t, f.rbac, userDaveSubject)))

	require.NoError(t, c.Get(t.Context(), types.NamespacedName{Namespace: testNamespace, Name: roleSourceID}, source))

	source.Spec.Scopes.Organization = source.Spec.Scopes.Organization[:1]
	require.NoError(t, c.Update(t.Context(), source))

	require.Equal(t, []string{"org:read"}, organizationEndpointNames(getACLForUser(t, f.rbac, userDaveSubject)))
}
