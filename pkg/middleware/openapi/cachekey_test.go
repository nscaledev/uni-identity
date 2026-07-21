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

		require.Equal(t, "direct|user-1|||_global", global)
		require.Equal(t, "direct|user-1|||org-1", scoped)
		require.NotEqual(t, global, scoped)
	})

	t.Run("AttributedCallUsesDirectKeyShape", func(t *testing.T) {
		t.Parallel()

		ctx := principal.NewContext(t.Context(), &principal.Principal{
			Actor: "someone-else",
		})

		key, err := aclCacheKey(ctx, serviceInfo, "org-1")
		require.NoError(t, err)

		require.Equal(t, "direct|compute-service|||org-1", key)
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

		require.Equal(t, "direct|compute-service|||org-1", direct)
		require.Equal(t, "impersonated|compute-service|user-1|||org-1", impersonated)
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
		require.Equal(t, "impersonated|compute-service|user-1|||org-1", computeKey)
		require.Equal(t, "impersonated|region-service|user-1|||org-1", regionKey)
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

		require.Equal(t, "impersonated|compute-service|user-1|||_global", global)
		require.Equal(t, "impersonated|compute-service|user-1|||org-1", scoped)
		require.NotEqual(t, global, scoped)
	})

	t.Run("ImpersonatedTypeDistinguishesTheKey", func(t *testing.T) {
		t.Parallel()

		// The impersonated ACL is resolved from the actor's principal TYPE
		// (getSystemAccountACL -> processImpersonatedPrincipalACL switches on
		// p.Type: User subjects vs Service-account IDs), so it changes the ACL
		// and MUST change the key. A User actor and a Service actor sharing an
		// actor string must never collide on one cached ACL.
		userCtx := principal.NewImpersonateContext(principal.NewContext(t.Context(), &principal.Principal{Actor: "user-1", Type: identityapi.User}))
		serviceCtx := principal.NewImpersonateContext(principal.NewContext(t.Context(), &principal.Principal{Actor: "user-1", Type: identityapi.Service}))

		userKey, err := aclCacheKey(userCtx, serviceInfo, "org-1")
		require.NoError(t, err)

		serviceKey, err := aclCacheKey(serviceCtx, serviceInfo, "org-1")
		require.NoError(t, err)

		require.NotEqual(t, userKey, serviceKey)
	})

	t.Run("ImpersonatedOrgSetDistinguishesTheKey", func(t *testing.T) {
		t.Parallel()

		// The impersonated ACL is resolved from the actor's organization set
		// (getSystemAccountACL reads p.OrganizationIDs to scope membership), so
		// it changes the ACL and MUST change the key; order does not (it is
		// sorted), so a semantically identical set always yields one key.
		orgsAB := principal.NewImpersonateContext(principal.NewContext(t.Context(), &principal.Principal{Actor: "user-1", Type: identityapi.User, OrganizationIDs: []string{"org-a", "org-b"}}))
		orgsA := principal.NewImpersonateContext(principal.NewContext(t.Context(), &principal.Principal{Actor: "user-1", Type: identityapi.User, OrganizationIDs: []string{"org-a"}}))
		orgsBA := principal.NewImpersonateContext(principal.NewContext(t.Context(), &principal.Principal{Actor: "user-1", Type: identityapi.User, OrganizationIDs: []string{"org-b", "org-a"}}))

		keyAB, err := aclCacheKey(orgsAB, serviceInfo, "org-1")
		require.NoError(t, err)

		keyA, err := aclCacheKey(orgsA, serviceInfo, "org-1")
		require.NoError(t, err)

		keyBA, err := aclCacheKey(orgsBA, serviceInfo, "org-1")
		require.NoError(t, err)

		require.NotEqual(t, keyAB, keyA, "a different org set must be a different key")
		require.Equal(t, keyAB, keyBA, "org-set order must not change the key (sorted)")
	})

	t.Run("DirectAccountTypeAndOrgSetDistinguishTheKey", func(t *testing.T) {
		t.Parallel()

		// A direct principal's ACL is resolved from its account type and org set
		// too, not just its subject, so both key the entry: two callers sharing
		// a subject but asserting different claims must not collide.
		base := &authorization.Info{Userinfo: &identityapi.Userinfo{
			Sub:                       "user-1",
			HttpsunikornCloudOrgauthz: &identityapi.AuthClaims{Acctype: identityapi.User, OrgIds: []string{"org-a"}},
		}}
		otherType := &authorization.Info{Userinfo: &identityapi.Userinfo{
			Sub:                       "user-1",
			HttpsunikornCloudOrgauthz: &identityapi.AuthClaims{Acctype: identityapi.Service, OrgIds: []string{"org-a"}},
		}}
		otherOrgs := &authorization.Info{Userinfo: &identityapi.Userinfo{
			Sub:                       "user-1",
			HttpsunikornCloudOrgauthz: &identityapi.AuthClaims{Acctype: identityapi.User, OrgIds: []string{"org-b"}},
		}}

		baseKey, err := aclCacheKey(t.Context(), base, "org-1")
		require.NoError(t, err)

		typeKey, err := aclCacheKey(t.Context(), otherType, "org-1")
		require.NoError(t, err)

		orgKey, err := aclCacheKey(t.Context(), otherOrgs, "org-1")
		require.NoError(t, err)

		require.NotEqual(t, baseKey, typeKey, "account type must key the direct entry")
		require.NotEqual(t, baseKey, orgKey, "org set must key the direct entry")
	})

	t.Run("ImpersonatedSingularOrganizationIsKeyed", func(t *testing.T) {
		t.Parallel()

		// A caller that sets only the singular OrganizationID (no OrganizationIDs)
		// resolves the impersonated ACL from that org via the defensive fallback
		// (principal.ResolvedOrganizationIDs), so the key must reflect it: two
		// such principals differing only in the singular org must not collide.
		orgA := principal.NewImpersonateContext(principal.NewContext(t.Context(), &principal.Principal{Actor: "user-1", Type: identityapi.User, OrganizationID: "org-a"}))
		orgB := principal.NewImpersonateContext(principal.NewContext(t.Context(), &principal.Principal{Actor: "user-1", Type: identityapi.User, OrganizationID: "org-b"}))

		keyA, err := aclCacheKey(orgA, serviceInfo, "org-1")
		require.NoError(t, err)

		keyB, err := aclCacheKey(orgB, serviceInfo, "org-1")
		require.NoError(t, err)

		require.NotEqual(t, keyA, keyB, "the singular OrganizationID fallback must key the entry")
		require.Contains(t, keyA, "org-a")
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
