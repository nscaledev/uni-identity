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

package auth0

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/sync/singleflight"
)

var (
	// ErrUnknownKID is returned when a token's key ID is absent from the cache
	// even after a bounded refetch. It is deliberately terminal: the caller
	// rejects the token rather than retrying, so an attacker cannot drive
	// repeated upstream fetches with a stream of unknown kids.
	ErrUnknownKID = errors.New("no JWKS key matches the token key ID")

	// ErrJWKSFetch is returned when the upstream JWKS cannot be fetched or
	// parsed.
	ErrJWKSFetch = errors.New("failed to fetch JWKS")
)

// keySet is a JWKS cache that verifies tokens with go-jose. It owns the
// discovery side of validation: it fetches and caches the issuer's public keys
// and bounds the unknown-kid refetch path (platform identity architecture
// §3.1.1) so attacker-supplied key IDs cannot drive a refetch storm.
//
//   - Concurrent refreshes are coalesced into a single upstream fetch via
//     singleflight (one in-flight refresh per issuer).
//   - The fetch rate is bounded by the throttledTransport on the HTTP client
//     (the cooldown), so a refetch demanded inside the window fails without
//     contacting the issuer.
//   - A kid still absent after exactly one refetch is rejected (ErrUnknownKID),
//     never retried.
//
// Signature verification itself is performed by the caller with go-jose using
// the *jose.JSONWebKey returned here — this type never performs validation,
// only discovery, so no OIDC ID-token verification semantics leak in.
type keySet struct {
	url    string
	client *http.Client
	group  singleflight.Group

	mu     sync.RWMutex
	cached *jose.JSONWebKeySet
}

func newKeySet(url string, client *http.Client) *keySet {
	return &keySet{
		url:    url,
		client: client,
	}
}

// key returns the verification key for kid, fetching the JWKS at most once if
// the kid is not already cached.
func (k *keySet) key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	if key := k.lookup(kid); key != nil {
		return key, nil
	}

	// Coalesce concurrent misses onto one fetch. singleflight gives us the
	// "single in-flight refresh"; the HTTP transport's throttle gives us the
	// cooldown. We do not key on kid: a miss means the cache is stale, so one
	// refresh serves every concurrent miss.
	if _, err, _ := k.group.Do("refresh", func() (any, error) {
		return nil, k.fetch(ctx)
	}); err != nil {
		return nil, err
	}

	if key := k.lookup(kid); key != nil {
		return key, nil
	}

	// Rejected after exactly one refetch — never retried.
	return nil, fmt.Errorf("%w: %q", ErrUnknownKID, kid)
}

func (k *keySet) lookup(kid string) *jose.JSONWebKey {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.cached == nil {
		return nil
	}

	keys := k.cached.Key(kid)
	if len(keys) == 0 {
		return nil
	}

	return &keys[0]
}

func (k *keySet) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrJWKSFetch, err)
	}

	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrJWKSFetch, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: unexpected status %d", ErrJWKSFetch, resp.StatusCode)
	}

	keySet := &jose.JSONWebKeySet{}
	if err := json.NewDecoder(resp.Body).Decode(keySet); err != nil {
		return fmt.Errorf("%w: %w", ErrJWKSFetch, err)
	}

	k.mu.Lock()
	k.cached = keySet
	k.mu.Unlock()

	return nil
}
