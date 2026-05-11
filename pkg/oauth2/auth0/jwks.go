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
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/unikorn-cloud/identity/pkg/jwks"
)

//nolint:gochecknoglobals
var jwksCacheRefreshTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "identity_auth0_jwks_cache_refresh_total",
		Help: "Total number of Auth0 JWKS cache refresh attempts, labeled by trigger and result.",
	},
	[]string{"trigger", "result"},
)

// KeySource resolves Auth0 public keys by kid.
type KeySource interface {
	Get(ctx context.Context, kid string) (*jose.JSONWebKey, error)
}

// CachedHTTPKeySource fetches and caches an Auth0 JWKS over HTTP.
// It refreshes on TTL expiry or on a kid miss, and uses singleflight to
// suppress refresh stampedes. Hot path performs zero network calls when a
// matching key is in cache.
type CachedHTTPKeySource struct {
	inner *jwks.CachedHTTPSource
}

var _ KeySource = (*CachedHTTPKeySource)(nil)

// NewCachedHTTPKeySource returns a JWKS-backed key source that caches keys
// across requests. httpClient should already be configured with the desired
// timeout — the cache does not impose its own per-request deadline.
func NewCachedHTTPKeySource(httpClient *http.Client, jwksURL string, ttl time.Duration) *CachedHTTPKeySource {
	return &CachedHTTPKeySource{
		inner: jwks.NewCachedHTTPSource(httpClient, jwksURL, ttl, func(trigger, result string) {
			jwksCacheRefreshTotal.WithLabelValues(trigger, result).Inc()
		}),
	}
}

// Get returns the public key identified by kid. Refreshes on TTL expiry or kid miss.
func (s *CachedHTTPKeySource) Get(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	publicKey, err := s.inner.Get(ctx, kid)
	if err == nil {
		return publicKey, nil
	}

	if errors.Is(err, jwks.ErrUnavailable) {
		return nil, fmt.Errorf("%w: %w", ErrJWKSUnavailable, err)
	}

	return nil, err
}
