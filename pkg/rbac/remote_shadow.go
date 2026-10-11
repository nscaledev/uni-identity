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

package rbac

import (
	"context"
	goerrors "errors"
	"runtime/debug"
	"slices"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// This file is the remote-shadow comparator: under
// RemoteShadow (the remote-engine context seam), dispatchCoarse (handler.go)
// SERVES THE LEGACY VERDICT UNCONDITIONALLY and at once, while a background
// goroutine gets the remote CoarseEngine's coarse decision and logs
// disagreement.  Nothing the remote evaluation does — a policy
// deny, a decision-endpoint outage, a panic — may alter the served verdict:
// the comparison is recover-wrapped and its result is only ever a log line.
// This is the identical zero-behaviour-change contract the local Cerbos
// shadow comparator (shadow.go) applies to the local dispatch seam.
//
// The log taxonomy is load-bearing for the divergence gate:
//
//   - "remote shadow divergence" — the remote engine produced a VERDICT and
//     it differs from legacy's.  Comparison is on allow/deny alone, never on
//     error message strings.  This is the parity signal the divergence gate
//     reads.
//   - "remote shadow evaluation failure" — no verdict was obtained
//     (ErrDecisionUnavailable, an unclassified error, or a recovered panic).
//     This is infra signal, triaged separately: a decision-endpoint outage
//     during the shadow phase must never register as policy divergence.
//   - "remote shadow compare skipped" — the run slots and the queue were
//     full, so the remote engine was not called.  This is neither
//     divergence nor failure.  It is a gap in the comparison coverage.
//
// The messages are NEW and DISTINCT from shadow.go's "cerbos shadow …" pair,
// so the local and remote comparators' signals never blur together under the
// same grep.
//
// Records emit through the request-scoped logr logger (log.FromContext),
// the same sink shadow.go and decision_log.go use, at Info — logr has no
// warn level, and every record class must be unconditionally visible.
const (
	remoteShadowDivergenceMessage = "remote shadow divergence"
	remoteShadowFailureMessage    = "remote shadow evaluation failure"
	remoteShadowSkippedMessage    = "remote shadow compare skipped"
)

const (
	// remoteShadowRunLimit bounds the shadow compares that one process runs at
	// once.  Other calls to identity do not count against it.
	remoteShadowRunLimit = 32

	// remoteShadowQueueLimit bounds the compares that wait for a run slot.  If
	// the engine honours its context, the worst drain is
	// remoteShadowQueueLimit/remoteShadowRunLimit times the shorter of the check
	// timeout and remoteShadowBackstop: 8 s at the remote defaultCheckTimeout.
	// A cached passport can reach a handler with only about 10 s left
	// (cacheTTLFudge), and identity accepts a passport for 5 s after it expires,
	// so the 8 s worst drain stays inside that budget.  A passport that is not
	// cached can have less than 10 s left, and a compare late in the drain can
	// then get a 401 and log an evaluation failure.
	remoteShadowQueueLimit = 1024

	// remoteShadowBackstop ends a compare that the check timeout does not end,
	// for example with a zero check timeout.  It works through the context, so
	// an engine call that blocks on something else keeps its run slot.
	remoteShadowBackstop = time.Second
)

//nolint:gochecknoglobals // the limits apply to the whole process.
var (
	remoteShadowAdmitted = semaphore.NewWeighted(remoteShadowRunLimit + remoteShadowQueueLimit)
	remoteShadowRunning  = semaphore.NewWeighted(remoteShadowRunLimit)
)

func remoteShadowed(ctx context.Context, engine CoarseEngine, resource Resource, operation openapi.AclOperation, legacyErr error) error {
	legacyAllowed := legacyErr == nil

	if p, err := principal.FromContext(ctx); err == nil && p != nil {
		snapshot := *p
		snapshot.OrganizationIDs = slices.Clone(p.OrganizationIDs)
		ctx = principal.NewContext(ctx, &snapshot)
	}

	compareCtx := context.WithoutCancel(ctx)

	if !remoteShadowAdmitted.TryAcquire(1) {
		func() {
			defer recoverLogSinkPanic()

			log.FromContext(ctx).Info(remoteShadowSkippedMessage, shadowAttrs(ctx, resource, operation, legacyAllowed)...)
		}()

		return legacyErr
	}

	go runRemoteShadowCompare(compareCtx, engine, resource, operation, legacyAllowed)

	return legacyErr
}

// runRemoteShadowCompare owns one admission slot and releases it when it ends.
func runRemoteShadowCompare(ctx context.Context, engine CoarseEngine, resource Resource, operation openapi.AclOperation, legacyAllowed bool) {
	defer remoteShadowAdmitted.Release(1)
	defer recoverLogSinkPanic()

	if remoteShadowRunning.Acquire(ctx, 1) != nil {
		return
	}

	defer remoteShadowRunning.Release(1)

	ctx, cancel := context.WithTimeout(ctx, remoteShadowBackstop)
	defer cancel()

	remoteShadowCompare(ctx, engine, resource, operation, legacyAllowed)
}

func recoverLogSinkPanic() {
	_ = recover()
}

// remoteShadowCompare evaluates the remote CoarseEngine's coarse decision for
// one already-decided legacy verdict and logs disagreement.  It never
// returns anything.
func remoteShadowCompare(ctx context.Context, engine CoarseEngine, resource Resource, operation openapi.AclOperation, legacyAllowed bool) {
	var attrs []any

	defer func() {
		if value := recover(); value != nil {
			log.FromContext(ctx).Info(remoteShadowFailureMessage, append(attrs,
				"remote_class", "panic",
				"panic", value,
				"stack", string(debug.Stack()))...)
		}
	}()

	attrs = shadowAttrs(ctx, resource, operation, legacyAllowed)

	err := engine.AllowCoarse(ctx, resource, operation)

	switch {
	case err == nil, goerrors.Is(err, ErrPolicyDenied):
		// A verdict was obtained: compare allow/deny — NEVER error message
		// strings (a remote denial carries a generic message by design).
		remoteAllowed := err == nil

		if remoteAllowed == legacyAllowed {
			return
		}

		// No policy_hash correlate here: unlike the local Cerbos path, the
		// remote CoarseEngine has no local policy hasher to pin a store
		// revision against — the policy lives at identity, the remote side.
		log.FromContext(ctx).Info(remoteShadowDivergenceMessage, append(attrs,
			"remote_verdict", decisionVerdict(remoteAllowed),
			"remote_class", shadowClass(err))...)
	default:
		// No verdict was obtained (unavailability or an unclassified error):
		// infra signal, NEVER divergence — the divergence gate must not be
		// poisoned by a decision-endpoint outage.
		log.FromContext(ctx).Info(remoteShadowFailureMessage, append(attrs,
			"remote_class", shadowClass(err),
			"error", err)...)
	}
}
