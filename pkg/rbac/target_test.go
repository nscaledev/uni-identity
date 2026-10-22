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

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/authz"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

const objectID = "c9bf9e57-1685-4c89-bafb-ff5af830be8a"

// The explicit form states everything a record needs, so none of it has to be
// guessed from the request's shape afterwards.
func TestAllowProjectScopeOnRecordsTheWholeTarget(t *testing.T) {
	t.Parallel()

	ctx, recorder := recordingContext(t)

	target := authz.Target{
		Endpoint:  resourceType2,
		Operation: authz.Read,
		Kind:      authz.Primary,
		ObjectID:  uuid.MustParse(objectID),
	}

	require.NoError(t, rbac.AllowProjectScopeOn(ctx, target,
		ids.MustParseOrganizationID(organizationID), ids.MustParseProjectID(projectID)))

	decisions := recorder.Decisions()
	require.Len(t, decisions, 1)

	decision := decisions[0]
	require.Equal(t, resourceType2, decision.Endpoint)
	require.Equal(t, "read", decision.Operation.Action)
	require.Equal(t, authz.Primary, decision.Kind)
	require.Equal(t, uuid.MustParse(objectID), decision.ObjectID)
	require.Equal(t, ids.MustParseOrganizationID(organizationID), decision.Scope.OrganizationID)
	require.Equal(t, ids.MustParseProjectID(projectID), decision.Scope.ProjectID)
}

// Starting an instance and creating one are both POST.  The action is the only
// thing that tells them apart, and it survives into the record.
func TestActionSurvivesIntoTheRecord(t *testing.T) {
	t.Parallel()

	ctx, recorder := recordingContext(t)

	target := authz.Target{
		Endpoint:  resourceType1,
		Operation: authz.Action(openapi.Read, "start"),
		Kind:      authz.Primary,
		ObjectID:  uuid.MustParse(objectID),
	}

	require.NoError(t, rbac.AllowOrganizationScopeOn(ctx, target, ids.MustParseOrganizationID(organizationID)))

	decision := recorder.Decisions()[0]
	require.Equal(t, "start", decision.Operation.Action)
	require.Equal(t, openapi.Read, decision.Operation.Access, "the access checked is the one the caller declared")
}

// The explicit form must authorize identically to the gate it replaces, or
// migrating a call site would quietly change who can do what.
func TestExplicitFormAuthorizesIdentically(t *testing.T) {
	t.Parallel()

	orgID := ids.MustParseOrganizationID(organizationID)
	projID := ids.MustParseProjectID(projectID)

	for _, test := range []struct {
		name      string
		endpoint  string
		operation openapi.AclOperation
	}{
		{"granted", resourceType2, openapi.Read},
		{"wrong operation", resourceType2, openapi.Create},
		{"unknown endpoint", "wibble", openapi.Read},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ctx := rbac.NewContext(t.Context(), aclFixture())

			old := rbac.AllowProjectScopeID(ctx, test.endpoint, test.operation, orgID, projID)

			target := authz.Target{
				Endpoint:  test.endpoint,
				Operation: authz.Operation{Access: test.operation, Action: "whatever"},
				Kind:      authz.Primary,
			}
			explicit := rbac.AllowProjectScopeOn(ctx, target, orgID, projID)

			require.Equal(t, old == nil, explicit == nil)
		})
	}
}

// The gates that predate the explicit form keep working, and say so: no object,
// and a precondition rather than the request's own operation.
func TestDeprecatedGatesRecordNoObjectAndNoPrimary(t *testing.T) {
	t.Parallel()

	ctx, recorder := recordingContext(t)

	require.NoError(t, rbac.AllowProjectScopeID(ctx, resourceType2, openapi.Read,
		ids.MustParseOrganizationID(organizationID), ids.MustParseProjectID(projectID)))

	decision := recorder.Decisions()[0]
	require.Equal(t, uuid.Nil, decision.ObjectID)
	require.Equal(t, authz.Subordinate, decision.Kind)
	require.Empty(t, decision.Operation.Action, "the old form cannot name the action")

	require.Empty(t, authz.Primaries(recorder.Decisions()),
		"an unmigrated call site yields no primary, which a consumer can report as a defect")
}

// A create is authorized before the resource exists, so it names no object.
func TestExplicitCreateHasNoObject(t *testing.T) {
	t.Parallel()

	ctx, recorder := recordingContext(t)

	target := authz.Target{
		Endpoint:  resourceType1,
		Operation: authz.Read,
		Kind:      authz.Primary,
	}

	require.NoError(t, rbac.AllowOrganizationScopeOn(ctx, target, ids.MustParseOrganizationID(organizationID)))
	require.Equal(t, uuid.Nil, recorder.Decisions()[0].ObjectID)
}
