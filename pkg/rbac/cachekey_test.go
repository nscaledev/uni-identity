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

// This is the A15 cache-key test, analogous to
// pkg/middleware/openapi/cachekey_test.go.  decisionCacheKey is the coarse
// decision cache's whole correctness surface: it must key on the FULL coarse
// authorization scope plus the policy-store hash, so a republish (hash change)
// can never serve a stale verdict and an impersonated request can never
// collide with a direct one — and it must bypass (ok=false) whenever the hash
// is unavailable.

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

// impersonate marks ctx as impersonating keyActor, exactly as the middleware
// does at the request boundary.
func impersonate(ctx context.Context) context.Context {
	ctx = principal.NewContext(ctx, &principal.Principal{Actor: keyActor, Type: openapi.User})

	return principal.NewImpersonateContext(ctx)
}

func TestDecisionCacheKey(t *testing.T) {
	t.Parallel()

	orgResource := Resource{Kind: "identity:groups", OrganizationID: "org-1"}

	t.Run("DirectShape", func(t *testing.T) {
		t.Parallel()

		key, ok := keyEngine(fixedHasher{hash: keyHash, ok: true}).decisionCacheKey(subjectContext(t), orgResource, openapi.Read)

		require.True(t, ok)
		require.Equal(t, "direct|compute-service|identity:groups|org-1||read|hash-1", key)
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
		require.Equal(t, "impersonated|compute-service|alice@example.com|user||identity:groups|org-1||read|hash-1", key)
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
		require.Equal(t, "direct|compute-service|identity:groups|org-1||read|hash-1", key)
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
