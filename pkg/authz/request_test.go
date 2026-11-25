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
)

const requestObject = "0b8f3f8e-6a3e-4c55-9d43-6b2f1a2c9e10"

func requestTarget() authz.Target {
	return authz.Target{
		Endpoint:   "compute:instances",
		Operation:  authz.Delete,
		Kind:       authz.Primary,
		ObjectID:   uuid.MustParse(requestObject),
		ObjectName: "web-1",
	}
}

func primary(target authz.Target, allowed bool) authz.Decision {
	target.Kind = authz.Primary

	return authz.Decision{
		Target:  target,
		Scope:   testScope(),
		Allowed: allowed,
	}
}

// Nothing stated and nothing checked leaves nothing to describe.
func TestRequestStartsUndescribed(t *testing.T) {
	t.Parallel()

	_, state := (&authz.Recorder{}).Request()
	require.Equal(t, authz.NotDescribed, state)
}

// A declaration describes the request before anything can fail, so a request
// that fails first, such as on a missing object, still says what it attempted.
func TestDeclarationDescribesTheRequest(t *testing.T) {
	t.Parallel()

	recorder := &authz.Recorder{}

	target := requestTarget()
	target.Kind = authz.Subordinate
	recorder.Declare(target)

	request, state := recorder.Request()
	require.Equal(t, authz.Declared, state)
	require.Equal(t, authz.Primary, request.Kind, "a declaration is always the request's own")
	require.Equal(t, uuid.MustParse(requestObject), request.ObjectID)
	require.False(t, request.Scope.Organization(), "nothing has been checked, so no scope is known")
}

// The request's own check completes the declaration with the scope and the
// outcome, and only fills in what the declaration did not know.
func TestCheckCompletesTheDeclaration(t *testing.T) {
	t.Parallel()

	recorder := &authz.Recorder{}
	recorder.Declare(requestTarget())

	// A create's check names no object: it must not erase what was declared.
	check := requestTarget()
	check.ObjectID = uuid.Nil
	check.ObjectName = ""
	recorder.Record(primary(check, true))

	request, state := recorder.Request()
	require.Equal(t, authz.Checked, state)
	require.Equal(t, uuid.MustParse(requestObject), request.ObjectID)
	require.Equal(t, "web-1", request.ObjectName)
	require.Equal(t, testScope(), request.Scope)
	require.True(t, request.Allowed)
	require.Empty(t, recorder.Defects())
}

// A refusal of the request's own check is the event an auditor most wants, so
// it is kept, with the scope it was refused in.
func TestRefusedCheckIsKept(t *testing.T) {
	t.Parallel()

	recorder := &authz.Recorder{}
	recorder.Record(primary(requestTarget(), false))

	request, state := recorder.Request()
	require.Equal(t, authz.Checked, state)
	require.False(t, request.Allowed)
	require.Equal(t, testScope(), request.Scope)
}

// A check made again, as on a conflict retry, is still one request.
func TestRepeatedCheckIsOneRequest(t *testing.T) {
	t.Parallel()

	recorder := &authz.Recorder{}
	recorder.Record(primary(requestTarget(), true))
	recorder.Record(primary(requestTarget(), true))

	require.Len(t, authz.Primaries(recorder.Decisions()), 1)
}

// The first statement of what the request is wins.  A later check about
// something else must not relabel it, and is reported, because the handler
// declared one thing and checked another.
func TestCheckOnSomethingElseIsADefect(t *testing.T) {
	t.Parallel()

	recorder := &authz.Recorder{}
	recorder.Declare(requestTarget())

	other := requestTarget()
	other.Endpoint = "region:networks:v2"
	recorder.Record(primary(other, true))

	request, state := recorder.Request()
	require.Equal(t, "compute:instances", request.Endpoint)
	require.Equal(t, authz.Declared, state, "the other check's outcome is not this request's")
	require.False(t, request.Scope.Organization(), "nor is its scope")
	require.NotEmpty(t, recorder.Defects())
}

// A check on the same kind of thing but a different object is about something
// else too.
func TestCheckOnAnotherObjectIsADefect(t *testing.T) {
	t.Parallel()

	recorder := &authz.Recorder{}
	recorder.Declare(requestTarget())

	other := requestTarget()
	other.ObjectID = uuid.New()
	recorder.Record(primary(other, true))

	request, state := recorder.Request()
	require.Equal(t, uuid.MustParse(requestObject), request.ObjectID)
	require.Equal(t, authz.Declared, state)
	require.NotEmpty(t, recorder.Defects())
}

// Only the request's own check is kept when refused.  A refused precondition is
// never read, and keeping it would turn list filtering into noise.
func TestRefusedPreconditionIsDropped(t *testing.T) {
	t.Parallel()

	recorder := &authz.Recorder{}

	refused := testDecision("region:networks:v2")
	refused.Allowed = false
	recorder.Record(refused)

	require.Empty(t, recorder.Decisions())
}

// Preconditions that were allowed are kept alongside the request.
func TestAllowedPreconditionsAreKept(t *testing.T) {
	t.Parallel()

	recorder := &authz.Recorder{}
	recorder.Record(testDecision("identity:roles"))
	recorder.Record(primary(requestTarget(), true))
	recorder.Record(testDecision("identity:roles"))

	decisions := recorder.Decisions()
	require.Len(t, decisions, 3)
	require.Len(t, authz.Primaries(decisions), 1)
}

// A name learned after the request was described lands on the request.
func TestNameLandsOnTheRequest(t *testing.T) {
	t.Parallel()

	recorder := &authz.Recorder{}
	recorder.Declare(requestTarget())
	recorder.Name("renamed")

	request, _ := recorder.Request()
	require.Equal(t, "renamed", request.ObjectName)
}

// Declaring without a recorder is a no-op, as recording is.
func TestDeclareWithoutARecorderIsANoOp(t *testing.T) {
	t.Parallel()

	authz.Declare(t.Context(), requestTarget())
}
