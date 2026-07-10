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

	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// This file is the A6 dual-path dispatch seam: the Allow* facade can serve
// its decisions either from the legacy in-process ACL walk (handler.go) or
// from the Cerbos decision API (check.go), selected by an engine seeded into
// the request context.  The legacy path is retained verbatim — A7's shadow
// comparator needs it live, and it only goes at the A12 cutover.

// ErrInvalidEngineMode rejects engine mode values outside the whitelist.
var ErrInvalidEngineMode = goerrors.New("invalid authorization engine mode")

// EngineMode selects which engine serves Allow* decisions.  A7 adds
// EngineShadow; A12 adds per-kind authoritative flags on top.
type EngineMode string

const (
	// EngineLegacy serves decisions from the local ACL walk.  The default.
	EngineLegacy EngineMode = "legacy"

	// EngineCerbos serves decisions from the Cerbos PDP via Check/CheckMany.
	EngineCerbos EngineMode = "cerbos"
)

var _ pflag.Value = (*EngineMode)(nil)

// Set implements pflag.Value with whitelist validation.
func (m *EngineMode) Set(value string) error {
	mode := EngineMode(value)

	if mode != EngineLegacy && mode != EngineCerbos {
		return fmt.Errorf("%w: %q (valid values: %s, %s)", ErrInvalidEngineMode, value, EngineLegacy, EngineCerbos)
	}

	*m = mode

	return nil
}

// String implements pflag.Value.
func (m *EngineMode) String() string {
	return string(*m)
}

// Type implements pflag.Value.
func (*EngineMode) Type() string {
	return "engineMode"
}

type engineKeyType int

const engineKey engineKeyType = iota

// NewEngineContext seeds the decision engine (and, through its options, the
// engine mode) for Allow* dispatch.  Contexts WITHOUT it — every downstream
// service (they never construct an RBAC, let alone a PDP), NewSuperContext,
// and every pre-existing test that seeds only an ACL — ALWAYS take the
// legacy path.  That absence-default is the compatibility contract of the
// migration: dispatch is a structural fail-safe, not a configuration one.
func NewEngineContext(ctx context.Context, engine *RBAC) context.Context {
	return context.WithValue(ctx, engineKey, engine)
}

// EngineFromContext returns the seeded decision engine, or nil when the
// context carries none (which means: legacy path, see NewEngineContext).
func EngineFromContext(ctx context.Context) *RBAC {
	engine, _ := ctx.Value(engineKey).(*RBAC)

	return engine
}

// mode returns the engine mode the RBAC was configured with, defaulting to
// legacy for a missing or unset option (downstream services never register
// the flag).
func (r *RBAC) mode() EngineMode {
	if r.options != nil && r.options.AuthorizationEngine == EngineCerbos {
		return EngineCerbos
	}

	return EngineLegacy
}

// engineForDispatch returns the context's decision engine when — and only
// when — the Cerbos path must serve the decision: an engine was seeded, its
// mode is cerbos, and the request is not impersonated.  Impersonated
// requests (the exact predicate refuseImpersonation uses) always take the
// legacy path regardless of mode: the Cerbos path refuses them outright
// until the A14 dual-check lands, and a hard deny here would break
// service-to-service impersonation.
func engineForDispatch(ctx context.Context) *RBAC {
	engine := EngineFromContext(ctx)

	if engine == nil || engine.mode() != EngineCerbos {
		return nil
	}

	if refuseImpersonation(ctx) != nil {
		return nil
	}

	return engine
}

// allowCoarse serves one coarse Allow* decision from the PDP, mapping every
// deny-shaped sentinel (ErrPolicyDenied, ErrDecisionUnavailable,
// ErrResolutionFailed — all fail-closed) to the same HTTPForbidden form the
// legacy walk produces: call sites branch on err == nil and the error mapper
// on the HTTP status, so the shape is load-bearing.  The sentinel stays
// visible through errors.Is for A7's comparator and A10's metrics.
func (r *RBAC) allowCoarse(ctx context.Context, resource Resource, operation openapi.AclOperation) error {
	if err := r.Check(ctx, resource, operation); err != nil {
		return errors.HTTPForbidden(fmt.Sprintf("operation is not allowed by rbac: operation '%s' on endpoint '%s' is not permitted", operation, resource.Kind)).WithError(err)
	}

	return nil
}
