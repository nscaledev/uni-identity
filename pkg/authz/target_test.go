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

package authz_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/authz"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// The CRUD operations name themselves, so the common case states both facts
// without the call site repeating itself.
func TestCRUDOperationsCarryBothFacts(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		operation authz.Operation
		access    openapi.AclOperation
		action    string
	}{
		{authz.Create, openapi.Create, "create"},
		{authz.Read, openapi.Read, "read"},
		{authz.Update, openapi.Update, "update"},
		{authz.Delete, openapi.Delete, "delete"},
	} {
		t.Run(test.action, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, test.access, test.operation.Access)
			require.Equal(t, test.action, test.operation.Action)
		})
	}
}

// Starting an instance is a POST, like creating one, so the HTTP method cannot
// tell them apart.  The action is the only place that distinction exists, and
// naming one forces a deliberate choice of the access it requires.
func TestActionNamesWhatWasDoneAndWhatItNeeds(t *testing.T) {
	t.Parallel()

	start := authz.Action(openapi.Update, "start")

	require.Equal(t, openapi.Update, start.Access)
	require.Equal(t, "start", start.Action)
	require.NotEqual(t, authz.Create, start, "an action must not be mistaken for a create just because it is a POST")
}

// A decision whose kind was never stated must not look like the request's own
// operation, or forgetting to mark one would silently relabel a precondition
// as the event.
func TestSubordinateIsTheZeroKind(t *testing.T) {
	t.Parallel()

	var kind authz.Kind

	require.Equal(t, authz.Subordinate, kind)
	require.NotEqual(t, authz.Primary, kind)
}

func TestTargetPopulatesTheDecision(t *testing.T) {
	t.Parallel()

	recorder := &authz.Recorder{}

	recorder.Record(authz.Decision{
		Target: authz.Target{
			Endpoint:  "compute:instances",
			Operation: authz.Action(openapi.Update, "start"),
			Kind:      authz.Primary,
			ObjectID:  uuid.MustParse("c9bf9e57-1685-4c89-bafb-ff5af830be8a"),
		},
		Scope:   authz.Scope{OrganizationID: ids.MustParseOrganizationID("f47ac10b-58cc-4372-a567-0e02b2c3d479")},
		Allowed: true,
	})

	decision := recorder.Decisions()[0]
	require.Equal(t, "compute:instances", decision.Endpoint)
	require.Equal(t, "start", decision.Operation.Action)
	require.Equal(t, authz.Primary, decision.Kind)
	require.Equal(t, uuid.MustParse("c9bf9e57-1685-4c89-bafb-ff5af830be8a"), decision.ObjectID)
}

// A create authorizes before the resource exists, so it has no object to name.
// That must be representable rather than requiring a placeholder.
func TestCreateHasNoObject(t *testing.T) {
	t.Parallel()

	target := authz.Target{
		Endpoint:  "identity:groups",
		Operation: authz.Create,
		Kind:      authz.Primary,
	}

	require.Equal(t, uuid.Nil, target.ObjectID)
}

// Primary decisions are what a consumer turns into records; preconditions are
// evidence attached to them.
func TestPrimaryDecisionsAreSelectable(t *testing.T) {
	t.Parallel()

	recorder := &authz.Recorder{}

	recorder.Record(authz.Decision{
		Target:  authz.Target{Endpoint: "identity:groups", Operation: authz.Update, Kind: authz.Primary},
		Allowed: true,
	})
	recorder.Record(authz.Decision{
		Target:  authz.Target{Endpoint: "identity:roles", Operation: authz.Read},
		Allowed: true,
	})

	primary := authz.Primaries(recorder.Decisions())
	require.Len(t, primary, 1)
	require.Equal(t, "identity:groups", primary[0].Endpoint)
}

// A create names a resource that did not exist when it was authorized, and a
// user's name is its subject rather than its metadata.name, which is only known
// once the resource has been read.
func TestNameSuppliesWhatWasNotKnownAtAuthorization(t *testing.T) {
	t.Parallel()

	recorder := &authz.Recorder{}
	ctx := authz.NewContext(t.Context(), recorder)

	authz.Record(ctx, authz.Decision{
		Target:  authz.Target{Endpoint: "identity:users", Operation: authz.Create, Kind: authz.Primary},
		Allowed: true,
	})

	authz.Name(ctx, "simon.murray@nscale.com")

	require.Equal(t, "simon.murray@nscale.com", recorder.Decisions()[0].ObjectName)
}

// Preconditions describe their own subject, so naming the request must not
// overwrite one of those.
func TestNameLeavesPreconditionsAlone(t *testing.T) {
	t.Parallel()

	recorder := &authz.Recorder{}
	ctx := authz.NewContext(t.Context(), recorder)

	authz.Record(ctx, authz.Decision{
		Target:  authz.Target{Endpoint: "identity:users", Operation: authz.Create, Kind: authz.Primary},
		Allowed: true,
	})
	authz.Record(ctx, authz.Decision{
		Target:  authz.Target{Endpoint: "identity:roles", Operation: authz.Read, ObjectName: "reader"},
		Allowed: true,
	})

	authz.Name(ctx, "simon.murray@nscale.com")

	decisions := recorder.Decisions()
	require.Equal(t, "simon.murray@nscale.com", decisions[0].ObjectName)
	require.Equal(t, "reader", decisions[1].ObjectName, "a precondition names its own subject")
}

// Authorization runs where no recorder was installed.
func TestNameWithoutARecorderIsANoOp(t *testing.T) {
	t.Parallel()

	require.NotPanics(t, func() {
		authz.Name(t.Context(), "anything")
	})
}
