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

	coreerrors "github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// These tests pin the Task 7 remote-shadow comparator (remoteShadowed,
// remote_shadow.go): under RemoteShadow, dispatchCoarse (handler.go) serves
// the LEGACY verdict unconditionally while a remote CoarseEngine is consulted
// alongside it and disagreement is logged.  This is the same zero-behaviour-
// change contract the local Cerbos shadow comparator (shadow.go) applies to
// the local dispatch seam, mirrored onto the remote one: a policy deny, a
// decision-endpoint outage, or a panic in the remote engine may never alter
// the served verdict.
//
// The message taxonomy is load-bearing for Task 12's divergence gate: verdict
// disagreements are "divergence", failures to obtain a verdict are
// "evaluation failure", and the two must never blur — a decision-endpoint
// outage must not read as policy divergence. Both messages are deliberately
// DISTINCT from the local comparator's "cerbos shadow …" pair (shadow_test.go)
// so the two paths' signals never merge under the same grep.
//
// Records emit through the request-scoped logr logger, so tests capture them
// with the shared context-seeded sink (logCapture, see decision_log_test.go)
// — no global logger state, parallel-safe.

// remoteShadowDivergenceMessage and remoteShadowFailureMessage are duplicated
// from remote_shadow.go deliberately: the exact log messages are the
// divergence gate's observability contract, so a rename here breaks these
// tests.
const (
	remoteShadowDivergenceMessage = "remote shadow divergence"
	remoteShadowFailureMessage    = "remote shadow evaluation failure"
)

// captureCoarseEngine is a minimal rbac.CoarseEngine double for the remote
// shadow comparator: it records how many times AllowCoarse was called and
// echoes a canned error (nil == allow), optionally panicking instead — the
// worst-case shadow failure, mirroring shadow_test.go's panicPDP.
type captureCoarseEngine struct {
	err    error
	panics bool
	calls  int
}

func (f *captureCoarseEngine) AllowCoarse(_ context.Context, _ rbac.Resource, _ openapi.AclOperation) error {
	f.calls++

	if f.panics {
		panic("deliberate remote shadow test panic")
	}

	return f.err
}

func (f *captureCoarseEngine) AllowCoarseMany(_ context.Context, _ []rbac.Resource, _ openapi.AclOperation) ([]bool, error) {
	return nil, nil
}

var _ rbac.CoarseEngine = (*captureCoarseEngine)(nil)

// remoteShadowContext builds the exact context shape RemoteShadow dispatch
// expects: the request-scoped logger (the capture), an ACL for the legacy
// walk, and the remote engine seeded in RemoteShadow mode (Task 5's seam).
func remoteShadowContext(t *testing.T, capture *logCapture, engine rbac.CoarseEngine, acl *openapi.Acl) context.Context {
	t.Helper()

	ctx := rbac.NewContext(capture.into(aliceContext(t)), acl)

	return rbac.NewRemoteEngineContext(ctx, engine, rbac.RemoteShadow)
}

func TestRemoteShadowAgreementIsSilent(t *testing.T) {
	t.Parallel()

	capture := &logCapture{}

	// Allow-agreement: the ACL grants the operation and the remote engine
	// allows it too (nil error).
	engine := &captureCoarseEngine{}
	ctx := remoteShadowContext(t, capture, engine, globalACL("candy", openapi.Read))

	require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))
	require.Equal(t, 1, engine.calls, "exactly one remote call per shadowed check")

	// Deny-agreement: the ACL lacks the operation and the remote engine
	// denies it too.
	denyEngine := &captureCoarseEngine{err: rbac.CoarseForbidden(rbac.Resource{Kind: "candy"}, openapi.Delete, rbac.ErrPolicyDenied)}
	denyCtx := remoteShadowContext(t, capture, denyEngine, globalACL("candy", openapi.Read))

	err := rbac.AllowGlobalScope(denyCtx, "candy", openapi.Delete)
	require.True(t, coreerrors.IsForbidden(err))
	require.Equal(t, 1, denyEngine.calls)

	require.Empty(t, capture.messages(remoteShadowDivergenceMessage), "agreement must not log divergence")
	require.Empty(t, capture.messages(remoteShadowFailureMessage), "agreement must not log evaluation failure")
}

func TestRemoteShadowDivergenceRemoteDenies(t *testing.T) {
	t.Parallel()

	capture := &logCapture{}

	// The remote engine denies what the ACL grants: a divergence, with the
	// legacy ALLOW still served.
	engine := &captureCoarseEngine{err: rbac.CoarseForbidden(rbac.Resource{Kind: "candy"}, openapi.Read, rbac.ErrPolicyDenied)}
	ctx := remoteShadowContext(t, capture, engine, globalACL("candy", openapi.Read))

	require.NoError(t, rbac.AllowOrganizationScope(ctx, "candy", openapi.Read, parityOrgA), "the served verdict must be the legacy allow")
	require.Equal(t, 1, engine.calls)

	records := capture.messages(remoteShadowDivergenceMessage)
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

	require.Empty(t, capture.messages(remoteShadowFailureMessage))
}

func TestRemoteShadowDivergenceRemoteAllows(t *testing.T) {
	t.Parallel()

	capture := &logCapture{}

	// The remote engine allows what the ACL does not grant: a divergence,
	// with the legacy DENY still served.
	engine := &captureCoarseEngine{}
	ctx := remoteShadowContext(t, capture, engine, globalACL("candy", openapi.Read))

	err := rbac.AllowGlobalScope(ctx, "candy", openapi.Delete)
	require.True(t, coreerrors.IsForbidden(err), "the served verdict must be the legacy deny")
	require.Equal(t, 1, engine.calls)

	records := capture.messages(remoteShadowDivergenceMessage)
	require.Len(t, records, 1)

	attrs := logAttrs(t, records[0])
	require.Equal(t, "deny", attrs["legacy_verdict"])
	require.Equal(t, "allow", attrs["remote_verdict"])
	require.Equal(t, "allowed", attrs["remote_class"])

	require.Empty(t, capture.messages(remoteShadowFailureMessage))
}

func TestRemoteShadowEvaluationFailureIsNotDivergence(t *testing.T) {
	t.Parallel()

	// The taxonomy split this test pins is what keeps Task 12's divergence
	// gate honest: a decision-endpoint outage (or an unclassified error)
	// during the shadow phase is infra signal and must NEVER register as
	// policy divergence.
	t.Run("RemoteUnavailable", func(t *testing.T) {
		t.Parallel()

		capture := &logCapture{}

		engine := &captureCoarseEngine{err: rbac.CoarseForbidden(rbac.Resource{Kind: "candy"}, openapi.Read, rbac.ErrDecisionUnavailable)}
		ctx := remoteShadowContext(t, capture, engine, globalACL("candy", openapi.Read))

		require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read), "a remote outage must not alter the served legacy verdict")

		require.Empty(t, capture.messages(remoteShadowDivergenceMessage), "unavailability is infra signal, never divergence")

		records := capture.messages(remoteShadowFailureMessage)
		require.Len(t, records, 1)
		require.Equal(t, "decision_unavailable", logAttrs(t, records[0])["remote_class"])
	})

	t.Run("UnclassifiedError", func(t *testing.T) {
		t.Parallel()

		capture := &logCapture{}

		// An error the taxonomy has no sentinel for: still NO verdict, so
		// still a failure, never a divergence — the "anything else" branch
		// of the verdict mapping must not require a specific sentinel.
		engine := &captureCoarseEngine{err: errFakeTransport}
		ctx := remoteShadowContext(t, capture, engine, globalACL("candy", openapi.Read))

		require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))

		require.Empty(t, capture.messages(remoteShadowDivergenceMessage))

		records := capture.messages(remoteShadowFailureMessage)
		require.Len(t, records, 1)

		attrs := logAttrs(t, records[0])
		require.Equal(t, "unclassified", attrs["remote_class"])
		require.Equal(t, errFakeTransport.Error(), attrs["error"])
	})
}

func TestRemoteShadowPanicIsRecovered(t *testing.T) {
	t.Parallel()

	capture := &logCapture{}

	engine := &captureCoarseEngine{panics: true}
	ctx := remoteShadowContext(t, capture, engine, globalACL("candy", openapi.Read))

	// The zero-behaviour-change contract under the worst case: a panicking
	// remote evaluation must never escape the dispatcher, and both legacy
	// verdicts must be served untouched.
	require.NoError(t, rbac.AllowGlobalScope(ctx, "candy", openapi.Read))

	err := rbac.AllowGlobalScope(ctx, "candy", openapi.Delete)
	require.True(t, coreerrors.IsForbidden(err))

	require.Empty(t, capture.messages(remoteShadowDivergenceMessage), "a panic is an evaluation failure, never divergence")

	records := capture.messages(remoteShadowFailureMessage)
	require.Len(t, records, 2)

	attrs := logAttrs(t, records[0])
	require.Equal(t, "panic", attrs["remote_class"])
	require.Contains(t, attrs["panic"], "deliberate remote shadow test panic")
	require.NotEmpty(t, attrs["stack"])
}
