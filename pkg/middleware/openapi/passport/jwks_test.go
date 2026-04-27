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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errForcedRead = errors.New("forced read error")

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type errorReadCloser struct{}

func (errorReadCloser) Read(_ []byte) (int, error) {
	return 0, errForcedRead
}

func (errorReadCloser) Close() error {
	return nil
}

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

	t.Run("returns jwks unavailable error when request cannot be created", func(t *testing.T) {
		t.Parallel()

		cache := NewJWKSCache(http.DefaultClient, "://bad-url", time.Minute)

		_, err := cache.Get(t.Context(), "test-kid")
		assert.ErrorIs(t, err, ErrJWKSUnavailable)
	})

	t.Run("returns jwks unavailable error on non-200 status", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		cache := NewJWKSCache(server.Client(), server.URL+"/oauth2/v2/jwks", time.Minute)

		_, err := cache.Get(t.Context(), "test-kid")
		assert.ErrorIs(t, err, ErrJWKSUnavailable)
	})

	t.Run("returns jwks unavailable error on malformed response", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, err := io.WriteString(w, `{`)
			assert.NoError(t, err)
		}))
		defer server.Close()

		cache := NewJWKSCache(server.Client(), server.URL+"/oauth2/v2/jwks", time.Minute)

		_, err := cache.Get(t.Context(), "test-kid")
		assert.ErrorIs(t, err, ErrJWKSUnavailable)
	})

	t.Run("returns jwks unavailable error on response body read failure", func(t *testing.T) {
		t.Parallel()

		httpClient := &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       errorReadCloser{},
				}, nil
			}),
		}

		cache := NewJWKSCache(httpClient, "https://example.com/oauth2/v2/jwks", time.Minute)

		_, err := cache.Get(t.Context(), "test-kid")
		assert.ErrorIs(t, err, ErrJWKSUnavailable)
	})

	t.Run("coalesces concurrent refreshes", func(t *testing.T) {
		t.Parallel()

		keyPair := newTestKeyPair(t, "test-kid")
		keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{keyPair.pub}}

		release := make(chan struct{})

		var fetchCount atomic.Int32

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fetchCount.Add(1)
			<-release

			w.Header().Set("Content-Type", "application/json")
			assert.NoError(t, json.NewEncoder(w).Encode(&keySet))
		}))
		defer server.Close()

		cache := NewJWKSCache(server.Client(), server.URL+"/oauth2/v2/jwks", time.Minute)

		const goroutines = 8

		start := make(chan struct{})
		errCh := make(chan error, goroutines)

		var wg sync.WaitGroup
		for range goroutines {
			wg.Add(1)

			go func() {
				defer wg.Done()
				<-start

				_, err := cache.Get(t.Context(), "test-kid")
				errCh <- err
			}()
		}

		close(start)

		require.Eventually(t, func() bool {
			return fetchCount.Load() >= 1
		}, time.Second, 10*time.Millisecond)

		time.Sleep(20 * time.Millisecond)
		close(release)

		wg.Wait()
		close(errCh)

		for err := range errCh {
			require.NoError(t, err)
		}

		assert.Equal(t, int32(1), fetchCount.Load())
	})
}
