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

package oauth2

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/oauth2/auth0"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/cache"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// auth0LegacyProviderName is the synthetic provider name used for the
// auth0-legacy entry derived from --auth0-exchange-* flags.
const auth0LegacyProviderName = "auth0-legacy"

// validatorCacheTTL is the lifetime of a cached validator entry. go-oidc's
// RemoteKeySet handles JWKS rotation transparently, so the TTL only bounds how
// long a stale fingerprint stays in the cache before being rebuilt on next
// use — it does not affect revocation (providers absent from the List are
// never reached regardless of TTL).
const validatorCacheTTL = 5 * time.Minute

var (
	// ErrCacheNotReady is returned when the provider List fails (e.g. informer
	// not yet synced). Callers on the JWS dispatch path surface this as HTTP 503
	// Service Unavailable, signaling a transient warm-up condition.
	ErrCacheNotReady = errors.New("provider list unavailable")

	// ErrUnknownIssuer is returned when no trusted provider's issuer matches the
	// token's iss claim. This is an expected outcome (an untrusted or unrecognized
	// issuer), not a lookup failure — callers surface it as HTTP 401, distinct from
	// the transient/config errors handleValidatorError otherwise handles.
	ErrUnknownIssuer = errors.New("no trusted provider matches issuer")
)

// validatorCacheEntry pairs a built validator with the fingerprint computed
// from the provider spec at build time.
type validatorCacheEntry struct {
	validator   *auth0.Validator
	fingerprint string
}

// bearerTrustProviders returns the subset of items that have BearerTrust set,
// name-sorted, plus a synthetic auth0-legacy entry when Auth0ExchangeIssuer is
// configured, always last. Name-sorting the CRD subset makes first-match
// resolution deterministic when two providers declare the same issuer — the
// cache-backed List order is not stable across calls, so without it the
// effective winner could vary per request. The sort freezes what was
// intermittent: a duplicate-issuer misconfiguration (one broken provider, one
// good) now fails or works consistently, and becomes permanently dead if the
// broken provider sorts first. Deliberate — a stable hard failure plus the
// duplicate-skip boot log beats a flaky one.
// The synthetic entry's BearerTrust sets RequireAuthzClaim=true to preserve
// the prior unconditional authz-claim enforcement of the legacy --auth0-exchange-*
// path; SkipEmailVerification stays false (safe default).
func (a *Authenticator) bearerTrustProviders(items []unikornv1.OAuth2Provider) []unikornv1.OAuth2Provider {
	candidates := make([]unikornv1.OAuth2Provider, 0, len(items)+1)

	for i := range items {
		if items[i].Spec.BearerTrust != nil {
			candidates = append(candidates, items[i])
		}
	}

	slices.SortFunc(candidates, func(a, b unikornv1.OAuth2Provider) int { return strings.Compare(a.Name, b.Name) })

	if a.options.Auth0ExchangeIssuer != "" {
		// Issuer is used verbatim; a malformed value just never matches a token's
		// iss (dispatch is an exact string compare), so it is inert, not unsafe.
		synthetic := unikornv1.OAuth2Provider{
			ObjectMeta: metav1.ObjectMeta{
				Name: auth0LegacyProviderName,
			},
			Spec: unikornv1.OAuth2ProviderSpec{
				Issuer: a.options.Auth0ExchangeIssuer,
				BearerTrust: &unikornv1.BearerTrustSpec{
					Audience:              a.options.Auth0ExchangeAudience,
					RequireAuthzClaim:     true,
					SkipEmailVerification: false,
				},
			},
		}

		candidates = append(candidates, synthetic)
	}

	return candidates
}

// validatorFingerprint produces a deterministic string that uniquely identifies
// the effective validator configuration for a provider, including groupsClaim.
// When the fingerprint changes, the cache discards the validator and rebuilds
// it.
func validatorFingerprint(rawIss, audience string, signingAlgorithms []string, skipEmail, requireAuthz bool, groupsClaim string) string {
	algs := make([]string, len(signingAlgorithms))
	copy(algs, signingAlgorithms)
	sort.Strings(algs)

	// groupsClaim is joined unprefixed, like rawIss and audience above. Nothing
	// keeps "|" out of the claim name, so a name containing it could in theory
	// collide with a different configuration. The worst case is a spurious
	// cache rebuild, not a security issue.
	return strings.Join([]string{
		rawIss,
		audience,
		strings.Join(algs, ","),
		strconv.FormatBool(skipEmail),
		strconv.FormatBool(requireAuthz),
		groupsClaim,
	}, "|")
}

// cachedValidator returns a cached *auth0.Validator for the provider, rebuilding
// it when absent or when the provider spec has changed (fingerprint mismatch).
// The cache is keyed by provider Name so a rename is treated as a new provider.
//
// The validator is built with the provider's issuer verbatim (p.Spec.Issuer):
// both dispatch selection and token verification match the `iss` by exact string
// comparison (OIDC §3.1.3.7). Operators must set spec.issuer to the exact `iss`
// their IdP emits — for Auth0 that includes the trailing slash.
func (a *Authenticator) cachedValidator(p *unikornv1.OAuth2Provider) (*auth0.Validator, error) {
	fp := validatorFingerprint(
		p.Spec.Issuer,
		p.Spec.BearerTrust.Audience,
		p.Spec.BearerTrust.SigningAlgorithms,
		p.Spec.BearerTrust.SkipEmailVerification,
		p.Spec.BearerTrust.RequireAuthzClaim,
		p.Spec.BearerTrust.GroupsClaim,
	)

	if raw, ok := a.validatorCache.Get(p.Name); ok {
		entry, ok := raw.(validatorCacheEntry)
		if ok && entry.fingerprint == fp {
			return entry.validator, nil
		}
	}

	v, err := auth0.NewValidator(auth0.Options{
		Issuer:                     p.Spec.Issuer,
		Audience:                   p.Spec.BearerTrust.Audience,
		TokenVerificationLeeway:    a.options.TokenVerificationLeeway,
		SupportedSigningAlgorithms: p.Spec.BearerTrust.SigningAlgorithms,
		SkipEmailVerification:      p.Spec.BearerTrust.SkipEmailVerification,
		RequireAuthzClaim:          p.Spec.BearerTrust.RequireAuthzClaim,
		GroupsClaim:                p.Spec.BearerTrust.GroupsClaim,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build validator for provider %q: %w", p.Name, err)
	}

	a.validatorCache.Add(p.Name, validatorCacheEntry{validator: v, fingerprint: fp}, validatorCacheTTL)

	return v, nil
}

// validatedIssuer is the resolved trust-list match for an issuer lookup. A
// non-nil result means a match; ErrUnknownIssuer means no trusted provider
// matches (an expected, non-fatal outcome); any other error means the lookup
// itself failed (cache not ready, or a config error on the matching provider).
type validatedIssuer struct {
	Validator    *auth0.Validator
	Trust        *unikornv1.BearerTrustSpec
	ProviderName string
}

// validatorForIssuer returns the validator whose provider issuer exactly equals
// rawIss, from the bearerTrust-enabled OAuth2Providers in the identity namespace,
// plus the
// synthetic auth0-legacy provider derived from the deprecated flags. Providers
// in other (org) namespaces are never trusted. Validators are cached per
// provider name + spec fingerprint; go-oidc's RemoteKeySet handles JWKS
// rotation, so a rebuild does not refetch keys.
//
// Trust membership is always the per-request List result — never read from the
// validator cache. The cache memoizes only the built *auth0.Validator for
// providers present in the current List. A deleted provider drops out of the
// next List, so revocation takes effect immediately regardless of TTL.
func (a *Authenticator) validatorForIssuer(ctx context.Context, rawIss string) (*validatedIssuer, error) {
	var providers unikornv1.OAuth2ProviderList

	if err := a.client.List(ctx, &providers, &client.ListOptions{Namespace: a.namespace}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCacheNotReady, err)
	}

	candidates := a.bearerTrustProviders(providers.Items)

	for i := range candidates {
		p := &candidates[i]

		if p.Spec.Issuer != rawIss {
			continue
		}

		if p.Spec.BearerTrust.Audience == "" {
			return nil, fmt.Errorf("%w: bearerTrust provider %q has empty audience", auth0.ErrInvalidConfig, p.Name)
		}

		v, err := a.cachedValidator(p)
		if err != nil {
			return nil, err
		}

		return &validatedIssuer{Validator: v, Trust: p.Spec.BearerTrust, ProviderName: p.Name}, nil
	}

	return nil, ErrUnknownIssuer
}

// GroupsClaimByIssuer returns the effective groupsClaim for every trusted bearer
// issuer, resolved first-match exactly like validatorForIssuer. The map includes
// the synthetic legacy auth0-exchange provider, which comes from flags, carries
// no claim, and is always the last candidate — so its issuer maps to "" unless a
// CRD provider declares the same issuer, in which case that provider wins and
// supplies the claim. The map is audience-blind: validatorForIssuer additionally
// hard-errors on an empty-audience winner, which this lookup does not see. The
// rbac Options.Validate advisory consumes this map.
func (a *Authenticator) GroupsClaimByIssuer(ctx context.Context) (map[string]string, error) {
	var providers unikornv1.OAuth2ProviderList

	if err := a.client.List(ctx, &providers, &client.ListOptions{Namespace: a.namespace}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCacheNotReady, err)
	}

	out := map[string]string{}

	for _, p := range a.bearerTrustProviders(providers.Items) {
		if _, ok := out[p.Spec.Issuer]; ok {
			// First-match wins, same as validatorForIssuer; with name-sorted
			// candidates the winner is the first provider by name. This is the
			// boot advisory path, so the line fires once per boot.
			log.FromContext(ctx).Info("duplicate issuer among bearer trust providers, skipping later candidate",
				"issuer", p.Spec.Issuer, "skippedProvider", p.Name)

			continue
		}

		out[p.Spec.Issuer] = p.Spec.BearerTrust.GroupsClaim
	}

	return out, nil
}

// newValidatorCache creates an LRU cache for built validators. size is
// typically Options.ValidatorCacheSize.
func newValidatorCache(size int) *cache.LRUExpireCache {
	return cache.NewLRUExpireCache(size)
}
