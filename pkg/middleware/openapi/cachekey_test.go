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

//nolint:testpackage // We intentionally exercise the unexported cache-key helper directly.
package openapi

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
)

func TestACLCacheKey(t *testing.T) {
	t.Parallel()

	// directInfo models a direct bearer-token call. The same cache key shape is
	// also used for attributed service-to-service calls where the principal
	// header is audit-only and RBAC still resolves against the authenticated
	// caller.
	directInfo := &authorization.Info{
		Userinfo: &identityapi.Userinfo{
			Sub: "user-1",
		},
	}

	serviceInfo := &authorization.Info{
		Userinfo: &identityapi.Userinfo{
			Sub: "compute-service",
		},
		SystemAccount: true,
	}

	t.Run("DirectIncludesOrganizationScope", func(t *testing.T) {
		t.Parallel()

		global, err := aclCacheKey(t.Context(), directInfo, "")
		require.NoError(t, err)

		scoped, err := aclCacheKey(t.Context(), directInfo, "org-1")
		require.NoError(t, err)

		require.Equal(t, "direct|user-1|_global", global)
		require.Equal(t, "direct|user-1|org-1", scoped)
		require.NotEqual(t, global, scoped)
	})

	t.Run("AttributedCallUsesDirectKeyShape", func(t *testing.T) {
		t.Parallel()

		ctx := principal.NewContext(t.Context(), &principal.Principal{
			Actor: "someone-else",
		})

		key, err := aclCacheKey(ctx, serviceInfo, "org-1")
		require.NoError(t, err)

		require.Equal(t, "direct|compute-service|org-1", key)
	})

	t.Run("ImpersonatedDiffersFromDirect", func(t *testing.T) {
		t.Parallel()

		ctx := principal.NewContext(t.Context(), &principal.Principal{
			Actor: "user-1",
		})
		ctx = principal.NewImpersonateContext(ctx)

		direct, err := aclCacheKey(t.Context(), serviceInfo, "org-1")
		require.NoError(t, err)

		impersonated, err := aclCacheKey(ctx, serviceInfo, "org-1")
		require.NoError(t, err)

		require.Equal(t, "direct|compute-service|org-1", direct)
		require.Equal(t, "impersonated|compute-service|user-1|org-1", impersonated)
		require.NotEqual(t, direct, impersonated)
	})

	t.Run("ImpersonatedIncludesCallingService", func(t *testing.T) {
		t.Parallel()

		ctx := principal.NewContext(t.Context(), &principal.Principal{
			Actor: "user-1",
		})
		ctx = principal.NewImpersonateContext(ctx)

		otherServiceInfo := &authorization.Info{
			Userinfo: &identityapi.Userinfo{
				Sub: "region-service",
			},
			SystemAccount: true,
		}

		computeKey, err := aclCacheKey(ctx, serviceInfo, "org-1")
		require.NoError(t, err)

		regionKey, err := aclCacheKey(ctx, otherServiceInfo, "org-1")
		require.NoError(t, err)

		require.NotEqual(t, computeKey, regionKey)
		require.Equal(t, "impersonated|compute-service|user-1|org-1", computeKey)
		require.Equal(t, "impersonated|region-service|user-1|org-1", regionKey)
	})

	t.Run("ImpersonatedIncludesOrganizationScope", func(t *testing.T) {
		t.Parallel()

		ctx := principal.NewContext(t.Context(), &principal.Principal{
			Actor: "user-1",
		})
		ctx = principal.NewImpersonateContext(ctx)

		global, err := aclCacheKey(ctx, serviceInfo, "")
		require.NoError(t, err)

		scoped, err := aclCacheKey(ctx, serviceInfo, "org-1")
		require.NoError(t, err)

		require.Equal(t, "impersonated|compute-service|user-1|_global", global)
		require.Equal(t, "impersonated|compute-service|user-1|org-1", scoped)
		require.NotEqual(t, global, scoped)
	})

	t.Run("SyntheticImpersonationWithoutActorErrors", func(t *testing.T) {
		t.Parallel()

		// Defensive unit test for the helper itself. The HTTP middleware rejects
		// this state at the boundary before aclCacheKey is reached.
		ctx := principal.NewContext(t.Context(), &principal.Principal{})
		ctx = principal.NewImpersonateContext(ctx)

		_, err := aclCacheKey(ctx, serviceInfo, "org-1")

		require.Error(t, err)
	})
}
