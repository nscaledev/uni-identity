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
	"strconv"
	"strings"
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

// digestSegment extracts the token-digest segment from a real aclCacheKey
// return value, rather than recomputing the digest independently. The key
// is "<mode>|" followed by a run of length-prefixed "<len>:<value>" segments
// and a terminal, unprefixed scope segment; the digest is always the last
// length-prefixed segment, immediately before scope.
//
// Only the direct shape is parsed: it has three length-prefixed segments
// (sub, srcIss, digest). The impersonated shape's digest position is pinned
// by the exact-key assertions elsewhere in this file, so teaching this helper
// to parse a shape nothing here builds would be untested code in a helper
// whose whole job is to model the real format faithfully.
func digestSegment(t *testing.T, key string) string {
	t.Helper()

	mode, rest, ok := strings.Cut(key, "|")
	require.True(t, ok, "key %q missing mode tag", key)
	require.Equal(t, "direct", mode, "digestSegment only parses direct-shape keys, got %q", key)

	const segmentCount = 3

	var digest string

	for i := range segmentCount {
		colon := strings.IndexByte(rest, ':')
		require.GreaterOrEqual(t, colon, 0, "segment %d missing length prefix in key %q", i, key)

		length, err := strconv.Atoi(rest[:colon])
		require.NoError(t, err, "segment %d length prefix in key %q", i, key)

		value := rest[colon+1 : colon+1+length]
		digest = value
		rest = rest[colon+1+length:]

		require.True(t, strings.HasPrefix(rest, "|"), "segment %d not followed by a delimiter in key %q", i, key)
		rest = rest[1:]
	}

	return digest
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

	// There is deliberately no "craft a colliding (scope, token) pair" test at
	// the digest/scope boundary, unlike SubjectContainingDelimiterCannotForgeAnotherIdentity
	// above. That test needs a real crafted collision because sub and srcIss
	// are attacker-controlled, variable-length strings that could otherwise be
	// shifted across the "|" delimiter. The token digest cannot be shifted the
	// same way: sha256.Sum256 output, base64.RawStdEncoding-encoded, is always
	// exactly 43 bytes and drawn from an alphabet that never contains "|". So
	// for any two calls, the first 43 characters of the digest segment are
	// unambiguously the digest and nothing else can borrow that space,
	// regardless of what scope (the unprefixed terminal segment) contains.
	// This makes the boundary safe by construction, not merely by the
	// length-prefix convention used for the other segments; there is no
	// adversarial (scope, token) pair that can be constructed to defeat it, so
	// no such test is written here. DigestSegmentEncodingInvariant below pins
	// the encoding facts (fixed 43-character length, "|"-free alphabet) that
	// this construction argument rests on, without attempting the dropped
	// collision proof. It reads the digest out of aclCacheKey's actual
	// returned key via digestSegment rather than recomputing it, so a change
	// to the real encoding is what the assertions below observe.

	t.Run("DigestSegmentEncodingInvariant", func(t *testing.T) {
		t.Parallel()

		const base64StdAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

		// Token content varies in length and character set; the digest segment
		// must not. A switch to base64.URLEncoding (which pads with "=" and
		// swaps "+/" for "-_") or a truncated digest would change the length or
		// alphabet asserted below.
		for _, token := range []string{"", "short-token", "a much longer token value with unicode: héllo wörld"} {
			info := &authorization.Info{
				Token:    token,
				Userinfo: &identityapi.Userinfo{Sub: "user-1"},
			}

			key, err := aclCacheKey(t.Context(), info, "org-1")
			require.NoError(t, err)

			digest := digestSegment(t, key)

			require.Len(t, digest, 43, "digest for token %q", token)

			for _, c := range digest {
				require.True(t, strings.ContainsRune(base64StdAlphabet, c),
					"digest character %q for token %q is outside base64.RawStdEncoding's alphabet", c, token)
			}

			require.NotContains(t, digest, "|")
		}
	})

	t.Run("DistinctTokensSameSubjectGetDistinctKeys", func(t *testing.T) {
		t.Parallel()

		a := &authorization.Info{Token: "token-with-group", Userinfo: &identityapi.Userinfo{Sub: "user-1"}}
		b := &authorization.Info{Token: "token-without-group", Userinfo: &identityapi.Userinfo{Sub: "user-1"}}

		keyA, err := aclCacheKey(t.Context(), a, "org-1")
		require.NoError(t, err)

		keyB, err := aclCacheKey(t.Context(), b, "org-1")
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
