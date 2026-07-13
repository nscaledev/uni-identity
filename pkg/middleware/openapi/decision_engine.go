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

package openapi

// NOTE: this deliberately lives outside interfaces.go — that file is the
// mockgen source, and this optional interface must not grow a generated
// mock (nothing should be forced to implement it).

import (
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// DecisionEngineProvider is optionally implemented by an Authorizer that can
// supply the Cerbos-capable decision engine for the Allow* facade's
// dual-path dispatch (rbac.NewEngineContext).  It is asserted at request
// handling time instead of widening Authorizer so external implementers —
// the generated mock included — keep compiling, and their requests
// structurally take the legacy path.
//
// Only the LOCAL authorizer implements it: it hands back identity's own RBAC,
// whose in-process PDP client can actually resolve bindings and decide.  The
// REMOTE authorizer deliberately does NOT — a remote DecisionEngineProvider
// is a designed follow-up, not delivered by A8.  A8 delivers the remote
// DECISION CALL (Authorizer.CheckMany over POST /authorization/check): a
// downstream service obtains a decision from identity.  Routing a downstream
// Allow* through that call would need a remote transport ABOVE rbac.decide()
// (a downstream RBAC cannot read identity's authorization resources — the
// Group/Role/Project/Organization CRDs binding resolution walks — so
// ResolveBindings would fail-closed-deny everything), which the
// DecisionEngine() seam — sitting
// BELOW binding resolution — cannot express.  See pkg/rbac/check.go and the
// migration plan's follow-up entries.
type DecisionEngineProvider interface {
	// DecisionEngine returns the decision engine to seed into handler
	// contexts, or nil when none is available.
	DecisionEngine() *rbac.RBAC
}
