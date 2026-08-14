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
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
)

// tokenDigest mirrors the digest computation inside aclCacheKey so the
// literal expectations below stay readable without duplicating the hash
// algorithm choice as an opaque magic string.
func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))

	return base64.RawStdEncoding.EncodeToString(sum[:])
}

func TestACLCacheKey(t *testing.T) {
	t.Parallel()

	// d is the digest of the empty token, shared by every fixture below that
	// does not set Token explicitly.
	d := tokenDigest("")

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

		require.Equal(t, fmt.Sprintf("direct|6:user-1|0:|%d:%s|_global", len(d), d), global)
		require.Equal(t, fmt.Sprintf("direct|6:user-1|0:|%d:%s|org-1", len(d), d), scoped)
		require.NotEqual(t, global, scoped)
	})

	t.Run("AttributedCallUsesDirectKeyShape", func(t *testing.T) {
		t.Parallel()

		ctx := principal.NewContext(t.Context(), &principal.Principal{
			Actor: "someone-else",
		})

		key, err := aclCacheKey(ctx, serviceInfo, "org-1")
		require.NoError(t, err)

		require.Equal(t, fmt.Sprintf("direct|15:compute-service|0:|%d:%s|org-1", len(d), d), key)
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

		require.Equal(t, fmt.Sprintf("direct|15:compute-service|0:|%d:%s|org-1", len(d), d), direct)
		require.Equal(t, fmt.Sprintf("impersonated|15:compute-service|0:|6:user-1|%d:%s|org-1", len(d), d), impersonated)
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
		require.Equal(t, fmt.Sprintf("impersonated|15:compute-service|0:|6:user-1|%d:%s|org-1", len(d), d), computeKey)
		require.Equal(t, fmt.Sprintf("impersonated|14:region-service|0:|6:user-1|%d:%s|org-1", len(d), d), regionKey)
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

		require.Equal(t, fmt.Sprintf("impersonated|15:compute-service|0:|6:user-1|%d:%s|_global", len(d), d), global)
		require.Equal(t, fmt.Sprintf("impersonated|15:compute-service|0:|6:user-1|%d:%s|org-1", len(d), d), scoped)
		require.NotEqual(t, global, scoped)
	})

	t.Run("DirectIncludesSrcIss", func(t *testing.T) {
		t.Parallel()

		issA := &authorization.Info{Userinfo: &identityapi.Userinfo{Sub: "alice@x.com"}, SrcIss: "https://a.com/"}
		issB := &authorization.Info{Userinfo: &identityapi.Userinfo{Sub: "alice@x.com"}, SrcIss: "https://b.com/"}

		keyA, err := aclCacheKey(t.Context(), issA, "")
		require.NoError(t, err)

		keyB, err := aclCacheKey(t.Context(), issB, "")
		require.NoError(t, err)

		// Same email from two issuers must never share an ACL (ID-367 finding 6).
		require.NotEqual(t, keyA, keyB)
	})

	t.Run("SubjectContainingDelimiterCannotForgeAnotherIdentity", func(t *testing.T) {
		t.Parallel()

		// Auth0 subjects look like "auth0|507f1f77bcf86cd799439011": the
		// subject itself contains the "|" join delimiter. Under the old
		// unescaped "sub|srcIss" concatenation, this pair and the pair below
		// render to the identical string "auth0|abc|def" for the sub+srcIss
		// segment even though they are two different (subject, issuer)
		// tuples. Length-prefixing must keep them apart.
		infoA := &authorization.Info{Userinfo: &identityapi.Userinfo{Sub: "auth0|abc"}, SrcIss: "def"}
		infoB := &authorization.Info{Userinfo: &identityapi.Userinfo{Sub: "auth0"}, SrcIss: "abc|def"}

		keyA, err := aclCacheKey(t.Context(), infoA, "org-1")
		require.NoError(t, err)

		keyB, err := aclCacheKey(t.Context(), infoB, "org-1")
		require.NoError(t, err)

		require.NotEqual(t, keyA, keyB)
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
