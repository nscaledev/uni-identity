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
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/authz"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
)

func testScope() authz.Scope {
	return authz.Scope{
		OrganizationID: ids.MustParseOrganizationID("f47ac10b-58cc-4372-a567-0e02b2c3d479"),
		ProjectID:      ids.MustParseProjectID("c9bf9e57-1685-4c89-bafb-ff5af830be8a"),
	}
}

func testDecision(endpoint string) authz.Decision {
	return authz.Decision{
		Endpoint:  endpoint,
		Operation: openapi.Update,
		Scope:     testScope(),
		Allowed:   true,
	}
}

func TestRecorderKeepsDecisionsInOrder(t *testing.T) {
	t.Parallel()

	recorder := &authz.Recorder{}
	recorder.Record(testDecision("identity:groups"))
	recorder.Record(testDecision("identity:roles"))

	decisions := recorder.Decisions()
	require.Len(t, decisions, 2)
	require.Equal(t, "identity:groups", decisions[0].Endpoint)
	require.Equal(t, "identity:roles", decisions[1].Endpoint)
}

func TestDecisionsIsACopy(t *testing.T) {
	t.Parallel()

	recorder := &authz.Recorder{}
	recorder.Record(testDecision("identity:groups"))

	decisions := recorder.Decisions()
	decisions[0].Endpoint = "mutated"

	require.Equal(t, "identity:groups", recorder.Decisions()[0].Endpoint)
}

func TestContextRoundTrip(t *testing.T) {
	t.Parallel()

	recorder := &authz.Recorder{}
	ctx := authz.NewContext(t.Context(), recorder)

	authz.Record(ctx, testDecision("identity:groups"))

	require.Len(t, recorder.Decisions(), 1)
}

// Recording MUST be safe where no recorder was installed.  Authorization runs
// in controllers, tests and internal paths that never pass through the audit
// middleware, and a panic there would take out work that has nothing to do
// with auditing.
func TestRecordWithoutARecorderIsANoOp(t *testing.T) {
	t.Parallel()

	require.NotPanics(t, func() {
		authz.Record(t.Context(), testDecision("identity:groups"))
	})

	_, ok := authz.FromContext(t.Context())
	require.False(t, ok)
}

// A list applies per-item checks, and nothing stops a handler doing that
// concurrently, so the recorder must not be the thing that makes it unsafe.
func TestRecorderIsConcurrencySafe(t *testing.T) {
	t.Parallel()

	const writers = 8

	recorder := &authz.Recorder{}

	var wg sync.WaitGroup

	wg.Add(writers)

	for range writers {
		go func() {
			defer wg.Done()

			recorder.Record(testDecision("identity:groups"))
		}()
	}

	wg.Wait()

	require.Len(t, recorder.Decisions(), writers)
}

// A denied decision is representable even though nothing records one yet, so
// the type does not have to change when refusals start being audited.
func TestDecisionCanRepresentARefusal(t *testing.T) {
	t.Parallel()

	recorder := &authz.Recorder{}

	decision := testDecision("identity:groups")
	decision.Allowed = false
	recorder.Record(decision)

	require.False(t, recorder.Decisions()[0].Allowed)
}
