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

package passport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/sync/singleflight"
)

//nolint:gochecknoglobals
var jwksCacheRefreshTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "identity_passport_jwks_cache_refresh_total",
		Help: "Total number of JWKS cache refresh attempts, labeled by trigger and result.",
	},
	[]string{"trigger", "result"},
)

// CachedHTTPKeySource fetches and caches the identity service's public JWKS.
// It refreshes on TTL expiry or on a key-ID miss. Zero network calls on the
// hot path when a valid cached key is present.
type CachedHTTPKeySource struct {
	httpClient *http.Client
	jwksURI    string
	ttl        time.Duration
	mutex      sync.RWMutex
	keySet     jose.JSONWebKeySet
	fetchedAt  time.Time
	refreshSF  singleflight.Group
}

var _ KeySource = (*CachedHTTPKeySource)(nil)

// NewCachedHTTPKeySource returns a new HTTP-backed JWKS cache key source.
// httpClient should already be configured for TLS (re-use the identity HTTP client).
func NewCachedHTTPKeySource(httpClient *http.Client, jwksURI string, ttl time.Duration) *CachedHTTPKeySource {
	return &CachedHTTPKeySource{
		httpClient: httpClient,
		jwksURI:    jwksURI,
		ttl:        ttl,
	}
}

// Get returns the public key identified by kid, refreshing the cache if necessary.
func (c *CachedHTTPKeySource) Get(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	key, isFresh := c.load(kid)
	if isFresh && key != nil {
		return key, nil
	}

	trigger := "ttl"
	if isFresh {
		trigger = "kid_miss"
	}

	if err := c.refreshSingleFlight(ctx, trigger); err != nil {
		return nil, err
	}

	key, _ = c.load(kid)
	if key == nil {
		return nil, fmt.Errorf("%w: kid %q not found after refresh", ErrJWKSUnavailable, kid)
	}

	return key, nil
}

func (c *CachedHTTPKeySource) refreshSingleFlight(ctx context.Context, trigger string) error {
	_, err, _ := c.refreshSF.Do(c.jwksURI, func() (any, error) {
		return nil, c.refresh(ctx, trigger)
	})

	return err
}

// load returns the cached key for kid and whether the cache is within its TTL.
func (c *CachedHTTPKeySource) load(kid string) (*jose.JSONWebKey, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	matches := c.keySet.Key(kid)

	var key *jose.JSONWebKey
	if len(matches) > 0 {
		key = &matches[0]
	}

	return key, time.Since(c.fetchedAt) < c.ttl
}

// refresh fetches the JWKS from the remote endpoint and updates the cache.
// trigger labels what caused refresh ("ttl" or "kid_miss").
// result labels outcome ("success" or "error").
func (c *CachedHTTPKeySource) refresh(ctx context.Context, trigger string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.jwksURI, nil)
	if err != nil {
		jwksCacheRefreshTotal.WithLabelValues(trigger, "error").Inc()
		return fmt.Errorf("%w: failed to build JWKS request: %w", ErrJWKSUnavailable, err)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		jwksCacheRefreshTotal.WithLabelValues(trigger, "error").Inc()
		return fmt.Errorf("%w: JWKS fetch failed: %w", ErrJWKSUnavailable, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		jwksCacheRefreshTotal.WithLabelValues(trigger, "error").Inc()
		return fmt.Errorf("%w: JWKS endpoint returned status %d", ErrJWKSUnavailable, response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		jwksCacheRefreshTotal.WithLabelValues(trigger, "error").Inc()
		return fmt.Errorf("%w: failed to read JWKS response body: %w", ErrJWKSUnavailable, err)
	}

	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		jwksCacheRefreshTotal.WithLabelValues(trigger, "error").Inc()
		return fmt.Errorf("%w: failed to decode JWKS: %w", ErrJWKSUnavailable, err)
	}

	c.store(keySet)
	jwksCacheRefreshTotal.WithLabelValues(trigger, "success").Inc()

	return nil
}

// store stores the fetched key set under the write lock.
func (c *CachedHTTPKeySource) store(keySet jose.JSONWebKeySet) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.keySet = keySet
	c.fetchedAt = time.Now()
}
