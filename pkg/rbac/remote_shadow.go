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

	"github.com/unikorn-cloud/identity/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// This file is the Task 7 remote-shadow comparator (Cut #1,
// docs/plans/2026-07-14-downstream-remote-authorization-cut1.md): under
// RemoteShadow (Task 5's remote engine seam), dispatchCoarse (handler.go)
// evaluates the already-decided legacy verdict AND the remote CoarseEngine's
// coarse decision synchronously, SERVES THE LEGACY VERDICT UNCONDITIONALLY,
// and logs disagreement.  Nothing the remote evaluation does — a policy
// deny, a decision-endpoint outage, a panic — may alter the served verdict:
// the comparison is recover-wrapped and its result is only ever a log line.
// This is the identical zero-behaviour-change contract the local Cerbos
// shadow comparator (shadow.go) applies to the local dispatch seam.
//
// The log taxonomy is load-bearing for Task 12's divergence gate:
//
//   - "remote shadow divergence" — the remote engine produced a VERDICT and
//     it differs from legacy's.  Comparison is on allow/deny alone, never on
//     error message strings.  This is the parity signal the divergence gate
//     reads.
//   - "remote shadow evaluation failure" — no verdict was obtained
//     (ErrDecisionUnavailable, an unclassified error, or a recovered panic).
//     This is infra signal, triaged separately: a decision-endpoint outage
//     during the shadow phase must never register as policy divergence.
//
// Both messages are NEW and DISTINCT from shadow.go's "cerbos shadow …" pair,
// so the local and remote comparators' signals never blur together under the
// same grep.
//
// Records emit through the request-scoped logr logger (log.FromContext),
// the same sink shadow.go and decision_log.go use, at Info — logr has no
// warn level, and both record classes must be unconditionally visible.
const (
	remoteShadowDivergenceMessage = "remote shadow divergence"
	remoteShadowFailureMessage    = "remote shadow evaluation failure"
)

// remoteShadowed returns legacyErr UNCHANGED, first running the remote
// shadow comparison.  This is the zero-behaviour-change contract of remote
// shadow mode: the legacy verdict — already computed by the time this runs —
// is always the served verdict.
func remoteShadowed(ctx context.Context, engine CoarseEngine, resource Resource, operation openapi.AclOperation, legacyErr error) error {
	remoteShadowCompare(ctx, engine, resource, operation, legacyErr == nil)

	return legacyErr
}

// remoteShadowCompare evaluates the remote CoarseEngine's coarse decision for
// one already-decided legacy verdict and logs disagreement.  It never
// returns anything and never panics: the recover wrap is the worst-case half
// of the zero-behaviour-change contract — a panicking remote engine (or a
// bug in the comparison itself) is a log line, never a request failure.
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
			"remote_verdict", shadowVerdict(remoteAllowed),
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
