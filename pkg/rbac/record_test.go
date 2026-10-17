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
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/authz"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func recordingContext(t *testing.T) (context.Context, *authz.Recorder) {
	t.Helper()

	recorder := &authz.Recorder{}
	ctx := authz.NewContext(rbac.NewContext(t.Context(), aclFixture()), recorder)

	return ctx, recorder
}

// The scope is the whole point: it is the fact a v2 request cannot recover
// from its own URL.
func TestAllowProjectScopeRecordsTheScope(t *testing.T) {
	t.Parallel()

	ctx, recorder := recordingContext(t)

	require.NoError(t, rbac.AllowProjectScopeID(ctx, resourceType2, openapi.Read,
		ids.MustParseOrganizationID(organizationID), ids.MustParseProjectID(projectID)))

	decisions := recorder.Decisions()
	require.Len(t, decisions, 1)
	require.Equal(t, resourceType2, decisions[0].Endpoint)
	require.Equal(t, openapi.Read, decisions[0].Operation.Access)
	require.Equal(t, ids.MustParseOrganizationID(organizationID), decisions[0].Scope.OrganizationID)
	require.Equal(t, ids.MustParseProjectID(projectID), decisions[0].Scope.ProjectID)
	require.True(t, decisions[0].Allowed)
}

func TestAllowOrganizationScopeRecordsTheScope(t *testing.T) {
	t.Parallel()

	ctx, recorder := recordingContext(t)

	require.NoError(t, rbac.AllowOrganizationScopeID(ctx, resourceType1, openapi.Read,
		ids.MustParseOrganizationID(organizationID)))

	decisions := recorder.Decisions()
	require.Len(t, decisions, 1)
	require.Equal(t, ids.MustParseOrganizationID(organizationID), decisions[0].Scope.OrganizationID)
	require.False(t, decisions[0].Scope.Project(), "an organization scoped check has no project")
}

// A project check falls back through organization and global scope internally.
// Those are the same question being answered, not three separate decisions, and
// recording each would bury the real one in noise.
func TestCascadingChecksRecordOneDecision(t *testing.T) {
	t.Parallel()

	ctx, recorder := recordingContext(t)

	// Granted at organization scope, so the project check succeeds via fallback
	// having consulted global scope first.
	require.NoError(t, rbac.AllowProjectScopeID(ctx, resourceType1, openapi.Read,
		ids.MustParseOrganizationID(organizationID), ids.MustParseProjectID(projectID)))

	require.Len(t, recorder.Decisions(), 1)
}

// The typed and reader variants delegate to the string forms.  Delegation must
// not double count.
func TestReaderVariantRecordsOneDecision(t *testing.T) {
	t.Parallel()

	ctx, recorder := recordingContext(t)

	scope := scopeStub{
		orgID:  ids.MustParseOrganizationID(organizationID),
		projID: ids.MustParseProjectID(projectID),
	}

	require.NoError(t, rbac.AllowProjectScopeReader(ctx, resourceType2, openapi.Read, scope))
	require.Len(t, recorder.Decisions(), 1)
}

// Filtering a list is not a decision about the request.  A list of forty
// visible resources must not leave forty decisions behind.
func TestPredicatesRecordNothing(t *testing.T) {
	t.Parallel()

	ctx, recorder := recordingContext(t)

	orgID := ids.MustParseOrganizationID(organizationID)
	projID := ids.MustParseProjectID(projectID)

	require.True(t, rbac.PermitsOrganizationScopeID(ctx, resourceType1, openapi.Read, orgID))
	require.True(t, rbac.PermitsProjectScopeID(ctx, resourceType2, openapi.Read, orgID, projID))
	require.False(t, rbac.PermitsGlobalScope(ctx, resourceType1, openapi.Read))

	require.Empty(t, recorder.Decisions())
}

// Refusals are not recorded yet.  Other services still use the gates as
// predicates, so recording a refusal would report routine list filtering as a
// denied request.
func TestRefusedGatesRecordNothingYet(t *testing.T) {
	t.Parallel()

	ctx, recorder := recordingContext(t)

	require.Error(t, rbac.AllowOrganizationScopeID(ctx, resourceType1, openapi.Create,
		ids.MustParseOrganizationID(organizationID)))

	require.Empty(t, recorder.Decisions())
}

// Granting a role checks that the caller holds every permission that role
// confers, which is many checks answering one question.  Recording each would
// leave a role's worth of decisions behind for a single group edit and bury
// the operation that was actually performed.
func TestGrantCheckDoesNotFanOut(t *testing.T) {
	t.Parallel()

	ctx, recorder := recordingContext(t)

	role := &unikornv1.Role{
		Spec: unikornv1.RoleSpec{
			Scopes: unikornv1.RoleScopes{
				Organization: []unikornv1.RoleScope{
					{
						Name:       resourceType1,
						Operations: []unikornv1.Operation{unikornv1.Read},
					},
					{
						Name:       resourceType1,
						Operations: []unikornv1.Operation{unikornv1.Read},
					},
				},
			},
		},
	}

	require.NoError(t, rbac.AllowRole(ctx, role, ids.MustParseOrganizationID(organizationID)))

	// One decision for the grant, not one per permission the role confers.
	decisions := recorder.Decisions()
	require.Len(t, decisions, 1)
	require.Equal(t, "identity:roles", decisions[0].Endpoint)
	require.Equal(t, "grant", decisions[0].Operation.Action)

	// A precondition, not the request's own operation, so it never becomes a
	// record in its own right.
	require.Equal(t, authz.Subordinate, decisions[0].Kind)
	require.Empty(t, authz.Primaries(decisions))
}

// Authorization runs in controllers and internal paths that never install a
// recorder.
func TestGatesWithoutARecorder(t *testing.T) {
	t.Parallel()

	ctx := rbac.NewContext(t.Context(), aclFixture())

	require.NotPanics(t, func() {
		_ = rbac.AllowOrganizationScopeID(ctx, resourceType1, openapi.Read,
			ids.MustParseOrganizationID(organizationID))
	})
}

// The record has to say which grant a change relied on, not merely that one was
// checked.  "A role was granted" does not distinguish a rename from somebody
// giving themselves administrator.
func TestGrantNamesTheRole(t *testing.T) {
	t.Parallel()

	ctx, recorder := recordingContext(t)

	role := &unikornv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "16fd2706-8baf-433b-82eb-8c7fada847da",
			Labels: map[string]string{constants.NameLabel: "platform-admin"},
		},
	}

	require.NoError(t, rbac.AllowRole(ctx, role, ids.MustParseOrganizationID(organizationID)))

	decisions := recorder.Decisions()
	require.Len(t, decisions, 1)
	require.Equal(t, "platform-admin", decisions[0].ObjectName)
	require.Equal(t, "16fd2706-8baf-433b-82eb-8c7fada847da", decisions[0].ObjectID.String())
}
