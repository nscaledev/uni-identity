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

	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

func TestRBACImplementsCoarseEngine(t *testing.T) {
	t.Parallel()

	var _ rbac.CoarseEngine = (*rbac.RBAC)(nil) // compile-time contract

	// AllowCoarse: single, cached path (allow).
	engine := newDispatchEngine(t, rbac.EngineCerbos, &capturePDP{allow: true})
	ctx := rbac.NewEngineContext(rbac.NewContext(aliceContext(t), globalACL("identity:groups", openapi.Read)), engine)
	require.NoError(t, engine.AllowCoarse(ctx, rbac.Resource{Kind: "identity:groups"}, openapi.Read))

	// AllowCoarseMany: batch, verdicts in order (allow, deny).
	pdp := &capturePDP{results: []bool{true, false}}
	engine2 := newDispatchEngine(t, rbac.EngineCerbos, pdp)
	ctx2 := rbac.NewEngineContext(rbac.NewContext(aliceContext(t), globalACLBoth("a:x", "a:y")), engine2)
	got, err := engine2.AllowCoarseMany(ctx2, []rbac.Resource{{Kind: "a:x"}, {Kind: "a:y"}}, openapi.Read)
	require.NoError(t, err)
	require.Equal(t, []bool{true, false}, got)
}
