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
	"fmt"
)

// This file is the downstream remote-authorization context seam (Cut #1,
// docs/plans/2026-07-14-downstream-remote-authorization-cut1.md): a remote
// CoarseEngine (the decision-endpoint adapter in pkg/middleware/openapi/remote)
// plus a RemoteMode are carried in the request context for the Allow* dispatch
// forks to consult.  remoteEngineFromContext is consumed by the dispatchCoarse
// fork (handler.go) and the RemoteShadow comparator (remote_shadow.go), both
// delivered on this branch.  This seam is independent of the
// existing EngineMode/engineKey seam above: that one selects which engine
// serves the LOCAL decision (legacy ACL walk vs. Cerbos); this one selects
// whether a REMOTE engine is consulted at all.

// ErrInvalidRemoteMode rejects remote mode values outside the whitelist.
var ErrInvalidRemoteMode = goerrors.New("invalid remote engine mode")

// RemoteMode selects how a seeded remote CoarseEngine participates in Allow*
// dispatch.
type RemoteMode int

const (
	// RemoteOff never consults the remote engine; dispatch is unaffected by
	// its presence in context.  The zero value, so it is also what
	// remoteEngineFromContext reports for a context that was never seeded --
	// the same absence-default discipline as EngineFromContext.
	RemoteOff RemoteMode = iota

	// RemoteShadow consults the remote engine alongside the legacy verdict
	// for comparison (Task 7's remoteShadowed) without ever serving its
	// decision.
	RemoteShadow

	// RemoteEnforce serves the remote engine's decision, authoritatively.
	RemoteEnforce
)

// ParseRemoteMode parses the three whitelisted remote-mode strings, mirroring
// EngineMode.Set's whitelist validation.
func ParseRemoteMode(s string) (RemoteMode, error) {
	switch s {
	case "off":
		return RemoteOff, nil
	case "shadow":
		return RemoteShadow, nil
	case "enforce":
		return RemoteEnforce, nil
	default:
		return RemoteOff, fmt.Errorf("%w: %q (valid values: off, shadow, enforce)", ErrInvalidRemoteMode, s)
	}
}

type remoteEngineKeyType int

const remoteEngineKey remoteEngineKeyType = iota

// remoteEngineValue bundles the remote CoarseEngine with its RemoteMode as the
// single value stored under remoteEngineKey, so the pair is always seeded and
// read atomically -- a context can never carry an engine without a mode, or
// the reverse.
type remoteEngineValue struct {
	engine CoarseEngine
	mode   RemoteMode
}

// NewRemoteEngineContext seeds the remote CoarseEngine and its dispatch mode
// for the Task 6 dispatch fork.  Mirrors NewEngineContext exactly.
func NewRemoteEngineContext(ctx context.Context, engine CoarseEngine, mode RemoteMode) context.Context {
	return context.WithValue(ctx, remoteEngineKey, remoteEngineValue{engine: engine, mode: mode})
}

// remoteEngineFromContext returns the seeded remote CoarseEngine and its
// mode, or (nil, RemoteOff) when the context carries none -- the zero value
// of remoteEngineValue is already exactly that pair, so (as in
// EngineFromContext) a failed type assertion needs no explicit branch.
func remoteEngineFromContext(ctx context.Context) (CoarseEngine, RemoteMode) {
	value, _ := ctx.Value(remoteEngineKey).(remoteEngineValue)

	return value.engine, value.mode
}
