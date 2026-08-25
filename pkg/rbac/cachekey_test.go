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
package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/principal"
)

// This is the coarse-decision cache-key test, analogous to
// pkg/middleware/openapi/cachekey_test.go.  decisionCacheKey is the coarse
// decision cache's whole correctness surface: it must key injectively on every
// binding-resolution input, the FULL coarse authorization scope and the
// policy-store hash. A republish (hash change) can never serve a stale verdict,
// distinct identities cannot share a cached denial, and the cache must bypass
// (ok=false) whenever the hash is unavailable.

const (
	keySubject = "compute-service"
	keyActor   = "alice@example.com"
	keyHash    = "hash-1"
)

// fixedHasher is a canned PolicyStoreHasher returning one hash (or
// unavailable), so the key's hash dimension can be pinned and flipped.
type fixedHasher struct {
	hash string
	ok   bool
}

func (h fixedHasher) Current(context.Context) (string, bool) {
	return h.hash, h.ok
}

// keyEngine builds an RBAC whose ONLY configured surface is the hasher — the
// cache-key helper reads nothing else.
func keyEngine(h PolicyStoreHasher) *RBAC {
	return New(nil, "", &Options{}).WithPolicyStoreHash(h)
}

// subjectContext seeds the authorization info decisionCacheKey reads the
// subject from (the same source the decision path resolves against).
func subjectContext(t *testing.T) context.Context {
	t.Helper()

	return authorization.NewContext(t.Context(), &authorization.Info{
		Userinfo: &openapi.Userinfo{Sub: keySubject},
	})
}

// directClaimsContext seeds authorization info for a DIRECT principal carrying
// the given account type and organization set — the claims decisionCacheKey
// folds into a direct key (mirroring what ResolveBindings reads for a direct
// request), so the key can never be coarser than the resolution input.
func directClaimsContext(t *testing.T, acctype openapi.AuthClaimsAcctype, orgs []string) context.Context {
	t.Helper()

	return authorization.NewContext(t.Context(), &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub:                       keySubject,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{Acctype: acctype, OrgIds: orgs},
		},
	})
}

// impersonate marks ctx as impersonating keyActor, exactly as the middleware
// does at the request boundary.
func impersonate(ctx context.Context) context.Context {
	ctx = principal.NewContext(ctx, &principal.Principal{Actor: keyActor, Type: openapi.User})

	return principal.NewImpersonateContext(ctx)
}

// The table is the point: every field of the key gets a row, so the
// function is long by design and splitting it would hide the matrix.
//
//nolint:maintidx
func TestDecisionCacheKey(t *testing.T) {
	t.Parallel()

	orgResource := Resource{Kind: "identity:groups", OrganizationID: "org-1"}

	t.Run("DirectShape", func(t *testing.T) {
		t.Parallel()

		key, ok := keyEngine(fixedHasher{hash: keyHash, ok: true}).decisionCacheKey(subjectContext(t), orgResource, openapi.Read)

		require.True(t, ok)
		// The direct key carries the complete caller resolution input. The
		// length-prefixed shape also pins the absent claims and empty collection
		// encodings used by subjectContext.
		require.Equal(t, "6:direct|15:compute-service|0:|1:0|0:|1:0|1:0|15:identity:groups|5:org-1|0:|4:read|6:hash-1|", key)
	})

	t.Run("DirectClaimsPresenceDistinguishesTheKey", func(t *testing.T) {
		t.Parallel()

		engine := keyEngine(fixedHasher{hash: keyHash, ok: true})
		withoutClaims := subjectContext(t)
		withEmptyClaims := authorization.NewContext(t.Context(), &authorization.Info{
			Userinfo: &openapi.Userinfo{Sub: keySubject, HttpsunikornCloudOrgauthz: &openapi.AuthClaims{}},
		})

		withoutClaimsKey, ok := engine.decisionCacheKey(withoutClaims, orgResource, openapi.Read)
		require.True(t, ok)
		withEmptyClaimsKey, ok := engine.decisionCacheKey(withEmptyClaims, orgResource, openapi.Read)
		require.True(t, ok)

		require.NotEqual(t, withoutClaimsKey, withEmptyClaimsKey, "nil claims fail resolution while present empty claims resolve to no bindings")
	})

	t.Run("DirectAccountTypeDistinguishesTheKey", func(t *testing.T) {
		t.Parallel()

		// A direct request resolves its bindings via a path chosen by account
		// type (User vs Service — bindings.go), so two principals sharing a
		// subject but asserting different types must never collide on one
		// cached verdict.
		engine := keyEngine(fixedHasher{hash: keyHash, ok: true})

		userKey, ok := engine.decisionCacheKey(directClaimsContext(t, openapi.User, nil), orgResource, openapi.Read)
		require.True(t, ok)

		serviceKey, ok := engine.decisionCacheKey(directClaimsContext(t, openapi.Service, nil), orgResource, openapi.Read)
		require.True(t, ok)

		require.NotEqual(t, userKey, serviceKey)
	})

	t.Run("DirectOrgSetDistinguishesTheKey", func(t *testing.T) {
		t.Parallel()

		// A direct request's org set scopes its membership resolution, so it
		// keys the entry; order does not (it is sorted).
		engine := keyEngine(fixedHasher{hash: keyHash, ok: true})

		keyA, ok := engine.decisionCacheKey(directClaimsContext(t, openapi.User, []string{"org-a"}), orgResource, openapi.Read)
		require.True(t, ok)

		keyAB, ok := engine.decisionCacheKey(directClaimsContext(t, openapi.User, []string{"org-a", "org-b"}), orgResource, openapi.Read)
		require.True(t, ok)

		keyBA, ok := engine.decisionCacheKey(directClaimsContext(t, openapi.User, []string{"org-b", "org-a"}), orgResource, openapi.Read)
		require.True(t, ok)

		require.NotEqual(t, keyA, keyAB, "a different org set must be a different key")
		require.Equal(t, keyAB, keyBA, "org-set order must not change the key (sorted)")
	})

	t.Run("ImpersonatedShapeIncludesSubjectAndActor", func(t *testing.T) {
		t.Parallel()

		ctx := impersonate(subjectContext(t))

		key, ok := keyEngine(fixedHasher{hash: keyHash, ok: true}).decisionCacheKey(ctx, orgResource, openapi.Read)

		require.True(t, ok)
		// The calling subject, the impersonated actor, the actor's principal
		// type and org set all appear, behind a distinct discriminator, so an
		// impersonated result can never be served to a direct call or vice
		// versa (impersonate() sets Type=user and no orgs — hence the empty
		// org field).
		require.Equal(t, "12:impersonated|15:compute-service|0:|1:0|0:|1:0|1:0|17:alice@example.com|0:|4:user|1:0|15:identity:groups|5:org-1|0:|4:read|6:hash-1|", key)
		require.Contains(t, key, keySubject)
		require.Contains(t, key, keyActor)
	})

	t.Run("DirectAndImpersonatedDiffer", func(t *testing.T) {
		t.Parallel()

		engine := keyEngine(fixedHasher{hash: keyHash, ok: true})

		direct, ok := engine.decisionCacheKey(subjectContext(t), orgResource, openapi.Read)
		require.True(t, ok)

		impersonated, ok := engine.decisionCacheKey(impersonate(subjectContext(t)), orgResource, openapi.Read)
		require.True(t, ok)

		require.NotEqual(t, direct, impersonated)
	})

	t.Run("ImpersonatedTypeDistinguishesTheKey", func(t *testing.T) {
		t.Parallel()

		// The impersonated principal's TYPE selects the binding resolution
		// source (User subjects vs Service-account IDs), so it changes the
		// verdict and MUST change the key: a User actor and a Service actor
		// sharing an actor string must never collide on one cached verdict.
		engine := keyEngine(fixedHasher{hash: keyHash, ok: true})

		userCtx := principal.NewImpersonateContext(principal.NewContext(subjectContext(t), &principal.Principal{Actor: keyActor, Type: openapi.User}))
		serviceCtx := principal.NewImpersonateContext(principal.NewContext(subjectContext(t), &principal.Principal{Actor: keyActor, Type: openapi.Service}))

		userKey, ok := engine.decisionCacheKey(userCtx, orgResource, openapi.Read)
		require.True(t, ok)

		serviceKey, ok := engine.decisionCacheKey(serviceCtx, orgResource, openapi.Read)
		require.True(t, ok)

		require.NotEqual(t, userKey, serviceKey)
	})

	t.Run("ImpersonatedOrgSetDistinguishesTheKey", func(t *testing.T) {
		t.Parallel()

		// The impersonated org set scopes membership resolution, so it changes
		// the verdict and MUST change the key; order does not (it is sorted).
		engine := keyEngine(fixedHasher{hash: keyHash, ok: true})

		orgsAB := principal.NewImpersonateContext(principal.NewContext(subjectContext(t), &principal.Principal{Actor: keyActor, Type: openapi.User, OrganizationIDs: []string{"org-a", "org-b"}}))
		orgsA := principal.NewImpersonateContext(principal.NewContext(subjectContext(t), &principal.Principal{Actor: keyActor, Type: openapi.User, OrganizationIDs: []string{"org-a"}}))
		orgsBA := principal.NewImpersonateContext(principal.NewContext(subjectContext(t), &principal.Principal{Actor: keyActor, Type: openapi.User, OrganizationIDs: []string{"org-b", "org-a"}}))

		keyAB, ok := engine.decisionCacheKey(orgsAB, orgResource, openapi.Read)
		require.True(t, ok)

		keyA, ok := engine.decisionCacheKey(orgsA, orgResource, openapi.Read)
		require.True(t, ok)

		keyBA, ok := engine.decisionCacheKey(orgsBA, orgResource, openapi.Read)
		require.True(t, ok)

		require.NotEqual(t, keyAB, keyA, "a different org set must be a different key")
		require.Equal(t, keyAB, keyBA, "org-set order must not change the key (sorted)")
	})

	t.Run("IssuerDistinguishesDirectAndImpersonatedKeys", func(t *testing.T) {
		t.Parallel()

		engine := keyEngine(fixedHasher{hash: keyHash, ok: true})

		directA := authorization.NewContext(t.Context(), &authorization.Info{SrcIss: "https://a.example.com/", Userinfo: &openapi.Userinfo{Sub: keySubject, HttpsunikornCloudOrgauthz: &openapi.AuthClaims{Acctype: openapi.User}}})
		directB := authorization.NewContext(t.Context(), &authorization.Info{SrcIss: "https://b.example.com/", Userinfo: &openapi.Userinfo{Sub: keySubject, HttpsunikornCloudOrgauthz: &openapi.AuthClaims{Acctype: openapi.User}}})

		directKeyA, ok := engine.decisionCacheKey(directA, orgResource, openapi.Read)
		require.True(t, ok)
		directKeyB, ok := engine.decisionCacheKey(directB, orgResource, openapi.Read)
		require.True(t, ok)
		require.NotEqual(t, directKeyA, directKeyB, "the same direct subject from different issuers must not share a decision")

		impersonatedA := principal.NewImpersonateContext(principal.NewContext(subjectContext(t), &principal.Principal{Actor: keyActor, Issuer: "https://a.example.com/", Type: openapi.User}))
		impersonatedB := principal.NewImpersonateContext(principal.NewContext(subjectContext(t), &principal.Principal{Actor: keyActor, Issuer: "https://b.example.com/", Type: openapi.User}))

		impersonatedKeyA, ok := engine.decisionCacheKey(impersonatedA, orgResource, openapi.Read)
		require.True(t, ok)
		impersonatedKeyB, ok := engine.decisionCacheKey(impersonatedB, orgResource, openapi.Read)
		require.True(t, ok)
		require.NotEqual(t, impersonatedKeyA, impersonatedKeyB, "the same impersonated actor from different issuers must not share a decision")
	})

	t.Run("CallerGroupsDistinguishDirectAndImpersonatedKeys", func(t *testing.T) {
		t.Parallel()

		engine := keyEngine(fixedHasher{hash: keyHash, ok: true})
		newContext := func(groups []string) context.Context {
			return authorization.NewContext(t.Context(), &authorization.Info{
				SrcIss: "https://idp.example.com/",
				Groups: groups,
				Userinfo: &openapi.Userinfo{
					Sub:                       keySubject,
					HttpsunikornCloudOrgauthz: &openapi.AuthClaims{Acctype: openapi.User, OrgIds: []string{"org-1"}},
				},
			})
		}

		groupsAB := newContext([]string{"group-a", "group-b"})
		groupsBA := newContext([]string{"group-b", "group-a"})
		groupsAC := newContext([]string{"group-a", "group-c"})

		directAB, ok := engine.decisionCacheKey(groupsAB, orgResource, openapi.Read)
		require.True(t, ok)
		directBA, ok := engine.decisionCacheKey(groupsBA, orgResource, openapi.Read)
		require.True(t, ok)
		directAC, ok := engine.decisionCacheKey(groupsAC, orgResource, openapi.Read)
		require.True(t, ok)

		require.Equal(t, directAB, directBA, "group order does not change resolved bindings")
		require.NotEqual(t, directAB, directAC, "different direct groups must not share a cached denial")

		impersonatedAB, ok := engine.decisionCacheKey(impersonate(groupsAB), orgResource, openapi.Read)
		require.True(t, ok)
		impersonatedAC, ok := engine.decisionCacheKey(impersonate(groupsAC), orgResource, openapi.Read)
		require.True(t, ok)

		require.NotEqual(t, impersonatedAB, impersonatedAC, "caller groups also resolve the service side of an impersonated decision")
	})

	t.Run("DirectDelimiterValuesCannotShiftFieldBoundaries", func(t *testing.T) {
		t.Parallel()

		engine := keyEngine(fixedHasher{hash: keyHash, ok: true})
		first := authorization.NewContext(t.Context(), &authorization.Info{SrcIss: "def", Userinfo: &openapi.Userinfo{Sub: "auth0|abc"}})
		second := authorization.NewContext(t.Context(), &authorization.Info{SrcIss: "abc|def", Userinfo: &openapi.Userinfo{Sub: "auth0"}})

		firstKey, ok := engine.decisionCacheKey(first, orgResource, openapi.Read)
		require.True(t, ok)
		secondKey, ok := engine.decisionCacheKey(second, orgResource, openapi.Read)
		require.True(t, ok)

		require.NotEqual(t, firstKey, secondKey, "length prefixes must distinguish values that collide under raw delimiter joining")
	})

	t.Run("ImpersonatedDelimiterValuesCannotShiftFieldBoundaries", func(t *testing.T) {
		t.Parallel()

		engine := keyEngine(fixedHasher{hash: keyHash, ok: true})
		first := principal.NewImpersonateContext(principal.NewContext(subjectContext(t), &principal.Principal{Actor: "alice|issuer", Issuer: "external", Type: openapi.User}))
		second := principal.NewImpersonateContext(principal.NewContext(subjectContext(t), &principal.Principal{Actor: "alice", Issuer: "issuer|external", Type: openapi.User}))

		firstKey, ok := engine.decisionCacheKey(first, orgResource, openapi.Read)
		require.True(t, ok)
		secondKey, ok := engine.decisionCacheKey(second, orgResource, openapi.Read)
		require.True(t, ok)

		require.NotEqual(t, firstKey, secondKey, "actor and issuer delimiters must not produce the same impersonated key")
	})

	t.Run("ScopeActionAndHashEachDistinguishTheKey", func(t *testing.T) {
		t.Parallel()

		engine := keyEngine(fixedHasher{hash: keyHash, ok: true})
		ctx := subjectContext(t)

		base, ok := engine.decisionCacheKey(ctx, orgResource, openapi.Read)
		require.True(t, ok)

		// A different organization is a different key.
		otherOrg, ok := engine.decisionCacheKey(ctx, Resource{Kind: "identity:groups", OrganizationID: "org-2"}, openapi.Read)
		require.True(t, ok)
		require.NotEqual(t, base, otherOrg)

		// Adding a project attribute is a different key (a project check must
		// not collide with the org check that omits it).
		withProject, ok := engine.decisionCacheKey(ctx, Resource{Kind: "identity:groups", OrganizationID: "org-1", ProjectID: "proj-1"}, openapi.Read)
		require.True(t, ok)
		require.NotEqual(t, base, withProject)

		// A different action is a different key.
		otherAction, ok := engine.decisionCacheKey(ctx, orgResource, openapi.Delete)
		require.True(t, ok)
		require.NotEqual(t, base, otherAction)

		// A different policy hash is a different key: THIS is the republish
		// bust guarantee — a new store hash makes every prior entry
		// unreachable.
		otherHash, ok := keyEngine(fixedHasher{hash: "hash-2", ok: true}).decisionCacheKey(ctx, orgResource, openapi.Read)
		require.True(t, ok)
		require.NotEqual(t, base, otherHash)
	})

	t.Run("ImpersonationWithoutActorCollapsesToDirect", func(t *testing.T) {
		t.Parallel()

		// The impersonation marker without an actor is NOT impersonation
		// (impersonationFromContext treats it as direct), so the key must take
		// the direct shape — never an error — matching how decide serves it.
		ctx := principal.NewContext(subjectContext(t), &principal.Principal{Type: openapi.User})
		ctx = principal.NewImpersonateContext(ctx)

		key, ok := keyEngine(fixedHasher{hash: keyHash, ok: true}).decisionCacheKey(ctx, orgResource, openapi.Read)

		require.True(t, ok)
		require.Equal(t, "6:direct|15:compute-service|0:|1:0|0:|1:0|1:0|15:identity:groups|5:org-1|0:|4:read|6:hash-1|", key)
	})

	t.Run("NoHasherBypasses", func(t *testing.T) {
		t.Parallel()

		// No hasher configured at all: the cache is inert.
		_, ok := New(nil, "", &Options{}).decisionCacheKey(subjectContext(t), orgResource, openapi.Read)
		require.False(t, ok)
	})

	t.Run("UnavailableHashBypasses", func(t *testing.T) {
		t.Parallel()

		// A hasher that has no hash yet (fail-safe: no successful read) must
		// bypass rather than key on a bogus hash.
		_, ok := keyEngine(fixedHasher{ok: false}).decisionCacheKey(subjectContext(t), orgResource, openapi.Read)
		require.False(t, ok)
	})

	t.Run("MissingSubjectBypasses", func(t *testing.T) {
		t.Parallel()

		// No authorization info in the context: bypass (the miss path fails
		// closed in Check anyway).
		_, ok := keyEngine(fixedHasher{hash: keyHash, ok: true}).decisionCacheKey(t.Context(), orgResource, openapi.Read)
		require.False(t, ok)
	})
}
