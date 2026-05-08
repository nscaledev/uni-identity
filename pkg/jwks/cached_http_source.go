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

package jwks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/sync/singleflight"
)

var ErrUnavailable = errors.New("JWKS unavailable")

// RefreshObserver is invoked for each refresh attempt outcome.
// trigger values: "ttl", "kid_miss".
// result values: "success", "error".
type RefreshObserver func(trigger, result string)

// CachedHTTPSource fetches and caches a JWKS over HTTP.
// It refreshes on TTL expiry or on a kid miss, and uses singleflight to
// suppress refresh stampedes.
type CachedHTTPSource struct {
	httpClient      *http.Client
	jwksURI         string
	ttl             time.Duration
	refreshObserver RefreshObserver
	mutex           sync.RWMutex
	keySet          jose.JSONWebKeySet
	fetchedAt       time.Time
	refreshSF       singleflight.Group
}

// NewCachedHTTPSource returns a JWKS-backed source that caches keys across requests.
// httpClient should already be configured with the desired timeout.
func NewCachedHTTPSource(httpClient *http.Client, jwksURI string, ttl time.Duration, refreshObserver RefreshObserver) *CachedHTTPSource {
	return &CachedHTTPSource{
		httpClient:      httpClient,
		jwksURI:         jwksURI,
		ttl:             ttl,
		refreshObserver: refreshObserver,
	}
}

// Get returns the public key identified by kid. Refreshes on TTL expiry or kid miss.
func (s *CachedHTTPSource) Get(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	key, isFresh := s.load(kid)
	if isFresh && key != nil {
		return key, nil
	}

	trigger := "ttl"
	if isFresh {
		trigger = "kid_miss"
	}

	if err := s.refreshSingleFlight(ctx, trigger); err != nil {
		return nil, err
	}

	key, _ = s.load(kid)
	if key == nil {
		return nil, fmt.Errorf("%w: kid %q not found after refresh", ErrUnavailable, kid)
	}

	return key, nil
}

func (s *CachedHTTPSource) refreshSingleFlight(ctx context.Context, trigger string) error {
	_, err, _ := s.refreshSF.Do(s.jwksURI, func() (any, error) {
		return nil, s.refresh(ctx, trigger)
	})

	return err
}

func (s *CachedHTTPSource) load(kid string) (*jose.JSONWebKey, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	matches := s.keySet.Key(kid)

	var key *jose.JSONWebKey
	if len(matches) > 0 {
		key = &matches[0]
	}

	return key, time.Since(s.fetchedAt) < s.ttl
}

func (s *CachedHTTPSource) refresh(ctx context.Context, trigger string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.jwksURI, nil)
	if err != nil {
		s.observeRefresh(trigger, "error")
		return fmt.Errorf("%w: failed to build JWKS request: %w", ErrUnavailable, err)
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		s.observeRefresh(trigger, "error")
		return fmt.Errorf("%w: JWKS fetch failed: %w", ErrUnavailable, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		s.observeRefresh(trigger, "error")
		return fmt.Errorf("%w: JWKS endpoint returned status %d", ErrUnavailable, response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		s.observeRefresh(trigger, "error")
		return fmt.Errorf("%w: failed to read JWKS response body: %w", ErrUnavailable, err)
	}

	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		s.observeRefresh(trigger, "error")
		return fmt.Errorf("%w: failed to decode JWKS: %w", ErrUnavailable, err)
	}

	s.store(keySet)
	s.observeRefresh(trigger, "success")

	return nil
}

func (s *CachedHTTPSource) observeRefresh(trigger, result string) {
	if s.refreshObserver == nil {
		return
	}

	s.refreshObserver(trigger, result)
}

func (s *CachedHTTPSource) store(keySet jose.JSONWebKeySet) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.keySet = keySet
	s.fetchedAt = time.Now()
}
