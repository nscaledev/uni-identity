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
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/require"

	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// These tests pin the remote-shadow comparator (remoteShadowed,
// remote_shadow.go): under RemoteShadow, dispatchCoarse (handler.go) serves
// the LEGACY verdict unconditionally while a remote CoarseEngine is consulted
// alongside it and disagreement is logged.  This is the same zero-behaviour-
// change contract the local Cerbos shadow comparator (shadow.go) applies to
// the local dispatch seam, mirrored onto the remote one: a policy deny, a
// decision-endpoint outage, or a panic in the remote engine may never alter
// the served verdict.
//
// The message taxonomy is load-bearing for the divergence gate: verdict
// disagreements are "divergence", failures to obtain a verdict are
// "evaluation failure", and the two must never blur — a decision-endpoint
// outage must not read as policy divergence. A third message, "compare
// skipped", marks a check that got no remote call. The three messages are
// deliberately DISTINCT from the local comparator's "cerbos shadow …" pair
// (shadow_test.go) so the two paths' signals never merge under the same grep.
//
// Records emit through the request-scoped logr logger, so tests capture them
// with the shared context-seeded sink (logCapture, see decision_log_test.go)
// — no global logger state, parallel-safe.

const (
	wantDivergenceMessage = "remote shadow divergence"
	wantFailureMessage    = "remote shadow evaluation failure"
	wantSkippedMessage    = "remote shadow compare skipped"
)

// captureCoarseEngine is a minimal rbac.CoarseEngine double for the remote
// shadow comparator: it records how many times AllowCoarse was called and
// echoes a canned error (nil == allow), optionally panicking instead — the
// worst-case shadow failure, mirroring shadow_test.go's panicPDP.
type captureCoarseEngine struct {
	err    error
	panics bool

	release chan struct{}

	mu        sync.Mutex
	calls     int
	principal *principal.Principal
}

func (f *captureCoarseEngine) AllowCoarse(ctx context.Context, _ rbac.Resource, _ openapi.AclOperation) error {
	f.mu.Lock()
	f.calls++
	f.principal, _ = principal.FromContext(ctx)
	f.mu.Unlock()

	if f.release != nil {
		select {
		case <-f.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if f.panics {
		panic("deliberate remote shadow test panic")
	}

	return f.err
}

// callCount reads calls under the lock, for a test whose compares a timer
// wakes: a timer gives no happens-before edge from the test to the compare.
func (f *captureCoarseEngine) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.calls
}

func (f *captureCoarseEngine) AllowCoarseMany(_ context.Context, _ []rbac.Resource, _ openapi.AclOperation) ([]bool, error) {
	return nil, nil
}

var _ rbac.CoarseEngine = (*captureCoarseEngine)(nil)

// remoteShadowContext builds the exact context shape RemoteShadow dispatch
// expects: the request-scoped logger (the capture), an ACL for the legacy
// walk, and the remote engine seeded in RemoteShadow mode (the remote-engine
// context seam).
func remoteShadowContext(t *testing.T, capture *logCapture, engine rbac.CoarseEngine, acl *openapi.Acl) context.Context {
	t.Helper()

	ctx := rbac.NewContext(capture.into(aliceContext(t)), acl)

	return rbac.NewRemoteEngineContext(ctx, engine, rbac.RemoteShadow)
}

func remoteErr(sentinel error) error {
	return rbac.CoarseForbidden(rbac.Resource{Kind: "candy"}, openapi.Read, sentinel)
}

func TestRemoteShadowAgreementIsSilent(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) { //nolint:thelper // a synctest body, not a helper; thelper v0.6.3 predates synctest support
		capture := &logCapture{}

		// Allow-agreement: the ACL grants the operation and the remote engine
		// allows it too (nil error).
		engine := &captureCoarseEngine{}
		ctx := remoteShadowContext(t, capture, engine, globalACL("candy", openapi.Read))

		require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))

		// Deny-agreement: the ACL lacks the operation and the remote engine
		// denies it too.
		denyEngine := &captureCoarseEngine{err: remoteErr(rbac.ErrPolicyDenied)}
		denyCtx := remoteShadowContext(t, capture, denyEngine, globalACL("candy", openapi.Read))

		err := rbac.AllowGlobalScope(denyCtx, "candy", openapi.Delete)
		require.True(t, coreerrors.IsForbidden(err))

		synctest.Wait()

		require.Equal(t, 1, engine.calls, "exactly one remote call per shadowed check")
		require.Equal(t, 1, denyEngine.calls)

		require.Empty(t, capture.messages(wantDivergenceMessage), "agreement must not log divergence")
		require.Empty(t, capture.messages(wantFailureMessage), "agreement must not log evaluation failure")
	})
}

func TestRemoteShadowDivergenceRemoteDenies(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) { //nolint:thelper // a synctest body, not a helper; thelper v0.6.3 predates synctest support
		capture := &logCapture{}

		// The remote engine denies what the ACL grants: a divergence, with the
		// legacy ALLOW still served.
		engine := &captureCoarseEngine{err: remoteErr(rbac.ErrPolicyDenied)}
		ctx := remoteShadowContext(t, capture, engine, globalACL("candy", openapi.Read))

		require.NoError(t, rbac.AllowOrganizationScope(ctx, "candy", openapi.Read, parityOrgA), "the served verdict must be the legacy allow")

		synctest.Wait()

		require.Equal(t, 1, engine.calls)

		records := capture.messages(wantDivergenceMessage)
		require.Len(t, records, 1)

		// The full record, and NOTHING but the record: no policy_hash (the
		// remote CoarseEngine has no local policy hasher to correlate against).
		attrs := logAttrs(t, records[0])
		require.Len(t, attrs, 9)
		require.Equal(t, parityAliceSubject, attrs["subject"])
		require.Equal(t, "user", attrs["actor_type"])
		require.Equal(t, "candy", attrs["endpoint"])
		require.Equal(t, "read", attrs["operation"])
		require.Equal(t, parityOrgA, attrs["organization_id"])
		require.Empty(t, attrs["project_id"])
		require.Equal(t, "allow", attrs["legacy_verdict"])
		require.Equal(t, "deny", attrs["remote_verdict"])
		require.Equal(t, "policy_denied", attrs["remote_class"])

		require.Empty(t, capture.messages(wantFailureMessage))
	})
}

func TestRemoteShadowDivergenceRemoteAllows(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) { //nolint:thelper // a synctest body, not a helper; thelper v0.6.3 predates synctest support
		capture := &logCapture{}

		// The remote engine allows what the ACL does not grant: a divergence,
		// with the legacy DENY still served.
		engine := &captureCoarseEngine{}
		ctx := remoteShadowContext(t, capture, engine, globalACL("candy", openapi.Read))

		err := rbac.AllowGlobalScope(ctx, "candy", openapi.Delete)
		require.True(t, coreerrors.IsForbidden(err), "the served verdict must be the legacy deny")

		synctest.Wait()

		require.Equal(t, 1, engine.calls)

		records := capture.messages(wantDivergenceMessage)
		require.Len(t, records, 1)

		attrs := logAttrs(t, records[0])
		require.Equal(t, "deny", attrs["legacy_verdict"])
		require.Equal(t, "allow", attrs["remote_verdict"])
		require.Equal(t, "allowed", attrs["remote_class"])

		require.Empty(t, capture.messages(wantFailureMessage))
	})
}

func TestRemoteShadowEvaluationFailureIsNotDivergence(t *testing.T) {
	t.Parallel()

	// The taxonomy split this test pins is what keeps the divergence
	// gate honest: a decision-endpoint outage (or an unclassified error)
	// during the shadow phase is infra signal and must NEVER register as
	// policy divergence.
	t.Run("RemoteUnavailable", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) { //nolint:thelper // a synctest body, not a helper; thelper v0.6.3 predates synctest support
			capture := &logCapture{}

			engine := &captureCoarseEngine{err: remoteErr(rbac.ErrDecisionUnavailable)}
			ctx := remoteShadowContext(t, capture, engine, globalACL("candy", openapi.Read))

			require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read), "a remote outage must not alter the served legacy verdict")

			synctest.Wait()

			require.Empty(t, capture.messages(wantDivergenceMessage), "unavailability is infra signal, never divergence")

			records := capture.messages(wantFailureMessage)
			require.Len(t, records, 1)
			require.Equal(t, "decision_unavailable", logAttrs(t, records[0])["remote_class"])
		})
	})

	t.Run("UnclassifiedError", func(t *testing.T) {
		t.Parallel()

		synctest.Test(t, func(t *testing.T) { //nolint:thelper // a synctest body, not a helper; thelper v0.6.3 predates synctest support
			capture := &logCapture{}

			// An error the taxonomy has no sentinel for: still NO verdict, so
			// still a failure, never a divergence — the "anything else" branch
			// of the verdict mapping must not require a specific sentinel.
			engine := &captureCoarseEngine{err: errFakeTransport}
			ctx := remoteShadowContext(t, capture, engine, globalACL("candy", openapi.Read))

			require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))

			synctest.Wait()

			require.Empty(t, capture.messages(wantDivergenceMessage))

			records := capture.messages(wantFailureMessage)
			require.Len(t, records, 1)

			attrs := logAttrs(t, records[0])
			require.Equal(t, "unclassified", attrs["remote_class"])
			require.Equal(t, errFakeTransport.Error(), attrs["error"])
		})
	})
}

func TestRemoteShadowPanicIsRecovered(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) { //nolint:thelper // a synctest body, not a helper; thelper v0.6.3 predates synctest support
		capture := &logCapture{}

		engine := &captureCoarseEngine{panics: true}
		ctx := remoteShadowContext(t, capture, engine, globalACL("candy", openapi.Read))

		// The zero-behaviour-change contract under the worst case: a panicking
		// remote evaluation must never escape the dispatcher, and both legacy
		// verdicts must be served untouched.
		require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))

		err := rbac.AllowGlobalScope(ctx, "candy", openapi.Delete)
		require.True(t, coreerrors.IsForbidden(err))

		synctest.Wait()

		require.Empty(t, capture.messages(wantDivergenceMessage), "a panic is an evaluation failure, never divergence")

		records := capture.messages(wantFailureMessage)
		require.Len(t, records, 2)

		attrs := logAttrs(t, records[0])
		require.Equal(t, "panic", attrs["remote_class"])
		require.Contains(t, attrs["panic"], "deliberate remote shadow test panic")
		require.NotEmpty(t, attrs["stack"])
	})
}

// TestRemoteShadowProjectScopeCreateIsCompared pins the remote half of the
// create shadow contract. Shadow's promise is that the legacy verdict is served
// unconditionally while the candidate engine is evaluated beside it, and a
// create is where that is easiest to break silently: this branch could serve the
// remote verdict, or skip the comparison altogether, and every other create test
// in the package would still pass. Then a soak would report zero divergence for
// creates off a path that never ran.
func TestRemoteShadowProjectScopeCreateIsCompared(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) { //nolint:thelper // a synctest body, not a helper; thelper v0.6.3 predates synctest support
		capture := &logCapture{}

		// The remote engine denies what the global ACL grants: a divergence, with
		// the legacy ALLOW still served.
		engine := &captureCoarseEngine{err: remoteErr(rbac.ErrPolicyDenied)}
		ctx := remoteShadowContext(t, capture, engine, globalACL("candy", openapi.Create))

		require.NoError(t, rbac.AllowProjectScopeCreate(ctx, nil, "candy", openapi.Create, organizationID, projectID),
			"the served verdict must be the legacy allow")

		synctest.Wait()

		require.Equal(t, 1, engine.calls, "a create must reach the remote comparator")

		records := capture.messages(wantDivergenceMessage)
		require.Len(t, records, 1)

		attrs := logAttrs(t, records[0])
		require.Equal(t, "candy", attrs["endpoint"])
		require.Equal(t, "create", attrs["operation"])
		require.Equal(t, organizationID, attrs["organization_id"])
		require.Equal(t, projectID, attrs["project_id"], "the divergence must name the body-supplied project")
		require.Equal(t, "allow", attrs["legacy_verdict"])
		require.Equal(t, "deny", attrs["remote_verdict"])

		require.Empty(t, capture.messages(wantFailureMessage))
	})
}

// TestRemoteShadowProjectScopeCreateSurvivesAnUnavailableEngine keeps the
// taxonomy honest for creates too: a decision endpoint outage during a soak is
// infrastructure signal, so it must neither change the served verdict nor
// register as policy divergence.
func TestRemoteShadowProjectScopeCreateSurvivesAnUnavailableEngine(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) { //nolint:thelper // a synctest body, not a helper; thelper v0.6.3 predates synctest support
		capture := &logCapture{}

		engine := &captureCoarseEngine{err: remoteErr(rbac.ErrDecisionUnavailable)}
		ctx := remoteShadowContext(t, capture, engine, globalACL("candy", openapi.Create))

		require.NoError(t, rbac.AllowProjectScopeCreate(ctx, nil, "candy", openapi.Create, organizationID, projectID),
			"an unavailable remote engine must not change the served verdict")

		synctest.Wait()

		require.Len(t, capture.messages(wantFailureMessage), 1)
		require.Empty(t, capture.messages(wantDivergenceMessage), "unavailability is infra signal, never divergence")
	})
}

func TestRemoteShadowServesBeforeTheCompare(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) { //nolint:thelper // a synctest body, not a helper; thelper v0.6.3 predates synctest support
		capture := &logCapture{}

		engine := &captureCoarseEngine{err: remoteErr(rbac.ErrPolicyDenied), release: make(chan struct{})}
		ctx := remoteShadowContext(t, capture, engine, globalACL("candy", openapi.Read))

		require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read), "the legacy allow is served while the remote engine is still busy")

		synctest.Wait()

		require.Equal(t, 1, engine.calls, "the compare has started")
		require.Empty(t, capture.messages(wantDivergenceMessage), "the compare has not finished")

		close(engine.release)
		synctest.Wait()

		require.Len(t, capture.messages(wantDivergenceMessage), 1, "the divergence is logged after the request is served")
	})
}

func TestRemoteShadowOutlivesTheRequest(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) { //nolint:thelper // a synctest body, not a helper; thelper v0.6.3 predates synctest support
		capture := &logCapture{}
		engine := &captureCoarseEngine{err: remoteErr(rbac.ErrPolicyDenied), release: make(chan struct{})}
		ctx, cancel := context.WithCancel(remoteShadowContext(t, capture, engine, globalACL("candy", openapi.Read)))

		require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))

		cancel()
		synctest.Wait()

		close(engine.release)
		synctest.Wait()

		require.Len(t, capture.messages(wantDivergenceMessage), 1, "the end of the request must not cancel the compare")
	})
}

func TestRemoteShadowSendsThePrincipalOfTheCheck(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) { //nolint:thelper // a synctest body, not a helper; thelper v0.6.3 predates synctest support
		engine := &captureCoarseEngine{}
		p := &principal.Principal{Actor: parityAliceSubject, OrganizationIDs: []string{parityOrgA}}
		ctx := principal.NewContext(remoteShadowContext(t, &logCapture{}, engine, globalACL("candy", openapi.Read)), p)

		require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))
		require.NoError(t, principal.EnrichUserPrincipalOrganizationScopeID(ctx, ids.MustParseOrganizationID(organizationID)))

		p.OrganizationIDs[0] = organizationID

		synctest.Wait()

		require.Equal(t, 1, engine.calls, "the compare must call the remote engine")
		require.NotNil(t, engine.principal, "the compare must send a principal")
		require.Equal(t, parityAliceSubject, engine.principal.Actor)
		require.Empty(t, engine.principal.OrganizationID, "the compare must send the principal as it was at the check")
		require.Equal(t, []string{parityOrgA}, engine.principal.OrganizationIDs, "a write to an organization ID after the check must not reach the compare")
	})
}

func TestRemoteShadowToleratesANilPrincipal(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) { //nolint:thelper // a synctest body, not a helper; thelper v0.6.3 predates synctest support
		capture := &logCapture{}

		engine := &captureCoarseEngine{err: remoteErr(rbac.ErrPolicyDenied)}
		ctx := principal.NewContext(remoteShadowContext(t, capture, engine, globalACL("candy", openapi.Read)), nil)

		require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read), "a nil principal must not fail the request")

		synctest.Wait()

		require.Len(t, capture.messages(wantDivergenceMessage), 1)
	})
}

//nolint:paralleltest // it fills the process-wide run slots and queue, so no other compare may run.
func TestRemoteShadowQueuesABurstAndSkipsOnlyWhenTheQueueIsFull(t *testing.T) {
	synctest.Test(t, func(t *testing.T) { //nolint:thelper // a synctest body, not a helper; thelper v0.6.3 predates synctest support
		const admitted = rbac.RemoteShadowRunLimitForTest + rbac.RemoteShadowQueueLimitForTest

		capture := &logCapture{}
		engine := &captureCoarseEngine{release: make(chan struct{})}
		release := sync.OnceFunc(func() { close(engine.release) })

		t.Cleanup(release)

		ctx := remoteShadowContext(t, capture, engine, globalACL("candy", openapi.Read))

		for range admitted {
			require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))
		}

		synctest.Wait()

		require.Empty(t, capture.messages(wantSkippedMessage), "the run slots and the queue hold the whole burst")
		require.Equal(t, rbac.RemoteShadowRunLimitForTest, engine.calls, "at most the run limit of compares call the remote engine at once")

		err := rbac.AllowGlobalScope(ctx, "candy", openapi.Delete)
		require.True(t, coreerrors.IsForbidden(err), "a skipped compare still serves the legacy deny")

		records := capture.messages(wantSkippedMessage)
		require.Len(t, records, 1)

		attrs := logAttrs(t, records[0])
		require.Len(t, attrs, 7)
		require.Equal(t, parityAliceSubject, attrs["subject"])
		require.Equal(t, "user", attrs["actor_type"])
		require.Equal(t, "candy", attrs["endpoint"])
		require.Equal(t, "delete", attrs["operation"])
		require.Equal(t, "deny", attrs["legacy_verdict"])

		release()
		synctest.Wait()

		require.Equal(t, admitted, engine.calls, "every queued compare runs when a run slot frees up")
		require.Empty(t, capture.messages(wantDivergenceMessage), "a skip is never divergence")
		require.Empty(t, capture.messages(wantFailureMessage), "a skip is never an evaluation failure")
	})
}

//nolint:paralleltest // it fills the process-wide run slots and queue, so no other compare may run.
func TestRemoteShadowSkipSurvivesAPanickingLogSink(t *testing.T) {
	synctest.Test(t, func(t *testing.T) { //nolint:thelper // a synctest body, not a helper; thelper v0.6.3 predates synctest support
		engine := &captureCoarseEngine{release: make(chan struct{})}
		release := sync.OnceFunc(func() { close(engine.release) })

		t.Cleanup(release)

		ctx := remoteShadowContext(t, &logCapture{}, engine, globalACL("candy", openapi.Read))

		for range rbac.RemoteShadowRunLimitForTest + rbac.RemoteShadowQueueLimitForTest {
			require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))
		}

		var logCalls atomic.Int32

		logger := funcr.New(func(_, _ string) {
			logCalls.Add(1)
			panic("deliberate log sink panic")
		}, funcr.Options{})

		skipCtx := rbac.NewContext(log.IntoContext(aliceContext(t), logger), globalACL("candy", openapi.Read))
		skipCtx = rbac.NewRemoteEngineContext(skipCtx, engine, rbac.RemoteShadow)

		var err error

		require.NotPanics(t, func() { err = rbac.AllowGlobalScope(skipCtx, "candy", openapi.Delete) }, "the skip line runs on the request goroutine")
		require.True(t, coreerrors.IsForbidden(err), "the skipped check still serves the legacy deny")
		require.Equal(t, int32(1), logCalls.Load(), "the skip line reached the sink")

		release()
		synctest.Wait()

		require.True(t, rbac.RemoteShadowIdleForTest())
	})
}

// principalReadPanicContext panics on a read that would return the principal.
type principalReadPanicContext struct {
	context.Context //nolint:containedctx // a context that changes Value must hold its parent.
}

func (c principalReadPanicContext) Value(key any) any {
	value := c.Context.Value(key)

	if _, ok := value.(*principal.Principal); ok {
		panic("deliberate principal read panic")
	}

	return value
}

// An admission slot that no compare goroutine owns is never released. Enough
// of them and every later check is skipped, so a panic before the goroutine
// starts must not hold one.
//
//nolint:paralleltest // it reads the process-wide slots, so no other compare may run.
func TestRemoteShadowTakesNoSlotBeforeItCanStartTheCompare(t *testing.T) {
	engine := &captureCoarseEngine{}
	ctx := remoteShadowContext(t, &logCapture{}, engine, globalACL("candy", openapi.Read))
	ctx = principalReadPanicContext{principal.NewContext(ctx, &principal.Principal{Actor: parityAliceSubject})}

	require.Panics(t, func() { _ = rbac.AllowGlobalScope(ctx, "candy", openapi.Read) })
	require.Zero(t, engine.callCount())
	require.True(t, rbac.RemoteShadowIdleForTest(), "the panic happened before the admission slot was taken")
}

//nolint:paralleltest // it reads the process-wide slots, so no other compare may run.
func TestRemoteShadowCompareWithoutARunSlotReleasesOnlyItsAdmissionSlot(t *testing.T) {
	engine := &captureCoarseEngine{}

	ctx, cancel := context.WithCancel(remoteShadowContext(t, &logCapture{}, engine, globalACL("candy", openapi.Read)))
	cancel()

	require.True(t, rbac.RemoteShadowAdmitAndRunForTest(ctx, engine))
	require.Zero(t, engine.callCount(), "a compare that gets no run slot does not call the engine")
	require.True(t, rbac.RemoteShadowIdleForTest(), "a compare that gets no run slot releases no run slot")
}

//nolint:paralleltest // it fills the process-wide run slots, so no other compare may run.
func TestRemoteShadowBackstopFreesTheRunSlotOfAHungCompare(t *testing.T) {
	synctest.Test(t, func(t *testing.T) { //nolint:thelper // a synctest body, not a helper; thelper v0.6.3 predates synctest support
		capture := &logCapture{}

		engine := &captureCoarseEngine{release: make(chan struct{})}
		ctx := remoteShadowContext(t, capture, engine, globalACL("candy", openapi.Read))

		for range rbac.RemoteShadowRunLimitForTest + 1 {
			require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))
		}

		synctest.Wait()

		require.Equal(t, rbac.RemoteShadowRunLimitForTest, engine.callCount(), "hung compares hold every run slot")

		time.Sleep(rbac.RemoteShadowBackstopForTest)
		synctest.Wait()

		require.Equal(t, rbac.RemoteShadowRunLimitForTest+1, engine.callCount(), "the backstop frees the run slots of the hung compares")
		require.Len(t, capture.messages(wantFailureMessage), rbac.RemoteShadowRunLimitForTest,
			"the backstop of the queued compare starts at its run slot, not at admission")

		time.Sleep(rbac.RemoteShadowBackstopForTest)
		synctest.Wait()

		require.Len(t, capture.messages(wantFailureMessage), rbac.RemoteShadowRunLimitForTest+1)
		require.True(t, rbac.RemoteShadowIdleForTest(), "a compare that the backstop ends frees both slots")
	})
}

//nolint:paralleltest // it reads the process-wide slots, so no other compare may run.
func TestRemoteShadowSurvivesAPanickingLogSink(t *testing.T) {
	synctest.Test(t, func(t *testing.T) { //nolint:thelper // a synctest body, not a helper; thelper v0.6.3 predates synctest support
		var logCalls atomic.Int32

		logger := funcr.New(func(_, _ string) {
			logCalls.Add(1)
			panic("deliberate log sink panic")
		}, funcr.Options{})

		engine := &captureCoarseEngine{err: remoteErr(rbac.ErrPolicyDenied)}
		ctx := rbac.NewContext(log.IntoContext(aliceContext(t), logger), globalACL("candy", openapi.Read))
		ctx = rbac.NewRemoteEngineContext(ctx, engine, rbac.RemoteShadow)

		require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))

		synctest.Wait()

		require.Equal(t, int32(2), logCalls.Load(), "the divergence line panics, then the failure line in the recover of remoteShadowCompare panics")
		require.True(t, rbac.RemoteShadowIdleForTest(), "a compare that panics past its recover frees both slots")
	})
}

//nolint:paralleltest // it reads the process-wide slots, so no other compare may run.
func TestRemoteShadowFreesItsSlotsOnEveryOutcome(t *testing.T) {
	outcomes := map[string]*captureCoarseEngine{
		"agreement":   {},
		"divergence":  {err: remoteErr(rbac.ErrPolicyDenied)},
		"unavailable": {err: remoteErr(rbac.ErrDecisionUnavailable)},
		"panic":       {panics: true},
	}

	for name, engine := range outcomes {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { //nolint:thelper // a synctest body, not a helper; thelper v0.6.3 predates synctest support
				ctx := remoteShadowContext(t, &logCapture{}, engine, globalACL("candy", openapi.Read))

				require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))

				synctest.Wait()

				require.Equal(t, 1, engine.calls)
				require.True(t, rbac.RemoteShadowIdleForTest(), "a finished compare frees both slots")
			})
		})
	}
}
