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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// TestGetACLEngineModeIndependence is the A9 decoupling regression guard for
// the thin-Go ACL computation: GetACL's output must be identical whichever
// enforcement engine serves Allow* — legacy (no engine seeded, the plain
// pre-migration shape), a shadow-mode engine, or a cerbos-mode engine whose
// PDP would DENY EVERY action.  This is the plan's "pre/post" comparison:
// the legacy call is the pre-migration baseline, the engine-seeded calls are
// the post-migration deployments, and the deny-all PDP is the proof GetACL
// never consults Cerbos — were ACL computation coupled to the engine, the
// cerbos-mode ACL would collapse to nothing (and pdp.calls would count the
// consultation).  If a future change couples ACL computation to the
// enforcement engine, this fails.
func TestGetACLEngineModeIndependence(t *testing.T) {
	t.Parallel()

	// One dataset behind every receiver, so any output difference could only
	// come from the engine mode.  Frank's single group grants two roles with
	// organization- and project-scope permissions, so the compared ACL is
	// non-trivial (scoped organization + project sections plus the unscoped
	// organization list) and, coming from one group, deterministically
	// ordered — safe for whole-value equality.
	fx := newParityFixture(t)

	// The deny-all PDP (capturePDP's zero value denies every action), shared
	// by the shadow- and cerbos-mode engines.
	pdp := &capturePDP{}

	shadowEngine := rbac.New(fx.client, parityNamespace, &rbac.Options{AuthorizationEngine: rbac.EngineShadow}).WithCerbos(pdp)
	cerbosEngine := rbac.New(fx.client, parityNamespace, &rbac.Options{AuthorizationEngine: rbac.EngineCerbos}).WithCerbos(pdp)

	frankInfo := parityUserInfo(parityFrankSubject, parityOrgA)

	// Legacy baseline: no engine in context, the fixture's legacy-mode RBAC —
	// exactly the pre-migration configuration.
	legacyACL, err := fx.rbac.GetACL(authorization.NewContext(t.Context(), frankInfo), parityOrgA)
	require.NoError(t, err)

	// The comparison is only meaningful over a non-trivial ACL.
	require.NotNil(t, legacyACL.Organization, "fixture principal must yield organization-scope permissions")
	require.NotNil(t, legacyACL.Projects, "fixture principal must yield project-scope permissions")
	require.NotNil(t, legacyACL.Organizations, "fixture principal must yield the unscoped organization list")

	// Each post-migration deployment shape: the mode's RBAC is both the
	// GetACL receiver and the engine seeded into the request context, as the
	// identity server wires it.
	shadowACL, err := shadowEngine.GetACL(rbac.NewEngineContext(authorization.NewContext(t.Context(), frankInfo), shadowEngine), parityOrgA)
	require.NoError(t, err)

	cerbosACL, err := cerbosEngine.GetACL(rbac.NewEngineContext(authorization.NewContext(t.Context(), frankInfo), cerbosEngine), parityOrgA)
	require.NoError(t, err)

	require.Equal(t, legacyACL, shadowACL, "shadow-mode GetACL must equal the legacy baseline")
	require.Equal(t, legacyACL, cerbosACL, "cerbos-mode GetACL must equal the legacy baseline even under a deny-all PDP")
	require.Zero(t, pdp.calls, "GetACL must never consult the PDP")
}
