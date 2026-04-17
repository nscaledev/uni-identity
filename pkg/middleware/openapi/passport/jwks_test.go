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

package passport //nolint:testpackage

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newJWKSServer(t *testing.T, keySet *jose.JSONWebKeySet) (*httptest.Server, *atomic.Int32) {
	t.Helper()

	var fetchCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(keySet); err != nil {
			t.Errorf("failed to encode key set: %v", err)
		}
	}))

	t.Cleanup(server.Close)

	return server, &fetchCount
}

func TestJWKSCache_Get(t *testing.T) {
	t.Parallel()

	t.Run("fetches lazily on first call", func(t *testing.T) {
		t.Parallel()

		keyPair := newTestKeyPair(t, "test-kid")
		keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{keyPair.pub}}
		server, fetchCount := newJWKSServer(t, &keySet)

		cache := NewJWKSCache(server.Client(), server.URL+"/oauth2/v2/jwks", time.Minute)

		key, err := cache.Get(t.Context(), "test-kid")
		require.NoError(t, err)
		assert.Equal(t, "test-kid", key.KeyID)
		assert.Equal(t, int32(1), fetchCount.Load())
	})

	t.Run("returns cached key without refetch", func(t *testing.T) {
		t.Parallel()

		keyPair := newTestKeyPair(t, "test-kid")
		keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{keyPair.pub}}
		server, fetchCount := newJWKSServer(t, &keySet)

		cache := NewJWKSCache(server.Client(), server.URL+"/oauth2/v2/jwks", time.Minute)

		_, err := cache.Get(t.Context(), "test-kid")
		require.NoError(t, err)

		_, err = cache.Get(t.Context(), "test-kid")
		require.NoError(t, err)

		assert.Equal(t, int32(1), fetchCount.Load())
	})

	t.Run("refreshes after TTL expiry", func(t *testing.T) {
		t.Parallel()

		keyPair := newTestKeyPair(t, "test-kid")
		keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{keyPair.pub}}
		server, fetchCount := newJWKSServer(t, &keySet)

		cache := NewJWKSCache(server.Client(), server.URL+"/oauth2/v2/jwks", time.Nanosecond)

		_, err := cache.Get(t.Context(), "test-kid")
		require.NoError(t, err)

		time.Sleep(10 * time.Millisecond)

		_, err = cache.Get(t.Context(), "test-kid")
		require.NoError(t, err)

		assert.GreaterOrEqual(t, fetchCount.Load(), int32(2))
	})

	t.Run("refreshes on kid miss", func(t *testing.T) {
		t.Parallel()

		keyPair := newTestKeyPair(t, "test-kid")
		otherKeyPair := newTestKeyPair(t, "other-kid")
		keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{otherKeyPair.pub}}
		server, fetchCount := newJWKSServer(t, &keySet)

		cache := NewJWKSCache(server.Client(), server.URL+"/oauth2/v2/jwks", time.Minute)

		// Prime cache with other-kid.
		_, err := cache.Get(t.Context(), "other-kid")
		require.NoError(t, err)
		require.Equal(t, int32(1), fetchCount.Load())

		// Server now exposes test-kid.
		keySet.Keys = []jose.JSONWebKey{keyPair.pub}

		key, err := cache.Get(t.Context(), "test-kid")
		require.NoError(t, err)
		assert.Equal(t, "test-kid", key.KeyID)
		assert.Equal(t, int32(2), fetchCount.Load())
	})

	t.Run("returns jwks unavailable error on persistent kid miss", func(t *testing.T) {
		t.Parallel()

		keyPair := newTestKeyPair(t, "test-kid")
		keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{keyPair.pub}}
		server, _ := newJWKSServer(t, &keySet)

		cache := NewJWKSCache(server.Client(), server.URL+"/oauth2/v2/jwks", time.Minute)

		_, err := cache.Get(t.Context(), "nonexistent-kid")
		assert.ErrorIs(t, err, ErrJWKSUnavailable)
	})

	t.Run("returns jwks unavailable error on unreachable endpoint", func(t *testing.T) {
		t.Parallel()

		cache := NewJWKSCache(http.DefaultClient, "http://127.0.0.1:0/jwks", time.Minute)

		_, err := cache.Get(t.Context(), "test-kid")
		assert.ErrorIs(t, err, ErrJWKSUnavailable)
	})
}
