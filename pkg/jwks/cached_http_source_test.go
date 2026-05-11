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

package jwks_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/jwks"
)

func testJWK(t *testing.T, kid string) jose.JSONWebKey {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	return jose.JSONWebKey{Key: privateKey.Public(), KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}
}

func TestCachedHTTPSource_Get(t *testing.T) {
	t.Parallel()

	t.Run("returns cached key after initial fetch", func(t *testing.T) {
		t.Parallel()

		key := testJWK(t, "kid-1")
		keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}}

		var fetchCount atomic.Int32

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fetchCount.Add(1)
			w.Header().Set("Content-Type", "application/json")

			if err := json.NewEncoder(w).Encode(&keySet); err != nil {
				t.Errorf("failed to encode key set: %v", err)
			}
		}))
		defer server.Close()

		source := jwks.NewCachedHTTPSource(server.Client(), server.URL, time.Minute, nil)

		got, err := source.Get(t.Context(), "kid-1")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "kid-1", got.KeyID)

		got, err = source.Get(t.Context(), "kid-1")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "kid-1", got.KeyID)

		assert.Equal(t, int32(1), fetchCount.Load())
	})

	t.Run("refreshes on kid miss", func(t *testing.T) {
		t.Parallel()

		first := testJWK(t, "kid-1")
		second := testJWK(t, "kid-2")
		keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{first}}

		var fetchCount atomic.Int32

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fetchCount.Add(1)
			w.Header().Set("Content-Type", "application/json")

			if err := json.NewEncoder(w).Encode(&keySet); err != nil {
				t.Errorf("failed to encode key set: %v", err)
			}
		}))
		defer server.Close()

		source := jwks.NewCachedHTTPSource(server.Client(), server.URL, time.Minute, nil)

		_, err := source.Get(t.Context(), "kid-1")
		require.NoError(t, err)
		require.Equal(t, int32(1), fetchCount.Load())

		keySet.Keys = []jose.JSONWebKey{second}

		got, err := source.Get(t.Context(), "kid-2")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "kid-2", got.KeyID)
		assert.Equal(t, int32(2), fetchCount.Load())
	})

	t.Run("coalesces concurrent refreshes", func(t *testing.T) {
		t.Parallel()

		key := testJWK(t, "kid-1")
		keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}}

		release := make(chan struct{})

		var fetchCount atomic.Int32

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fetchCount.Add(1)
			<-release
			w.Header().Set("Content-Type", "application/json")

			if err := json.NewEncoder(w).Encode(&keySet); err != nil {
				t.Errorf("failed to encode key set: %v", err)
			}
		}))
		defer server.Close()

		source := jwks.NewCachedHTTPSource(server.Client(), server.URL, time.Minute, nil)

		const goroutines = 8

		start := make(chan struct{})
		errCh := make(chan error, goroutines)

		var wg sync.WaitGroup
		for range goroutines {
			wg.Add(1)

			go func() {
				defer wg.Done()
				<-start

				_, err := source.Get(t.Context(), "kid-1")
				errCh <- err
			}()
		}

		close(start)

		require.Eventually(t, func() bool {
			return fetchCount.Load() >= 1
		}, time.Second, 10*time.Millisecond)

		close(release)

		wg.Wait()
		close(errCh)

		for err := range errCh {
			require.NoError(t, err)
		}

		assert.Equal(t, int32(1), fetchCount.Load())
	})

	t.Run("returns unavailable on fetch failure", func(t *testing.T) {
		t.Parallel()

		source := jwks.NewCachedHTTPSource(http.DefaultClient, "http://127.0.0.1:0/jwks", time.Minute, nil)

		_, err := source.Get(t.Context(), "kid-1")
		require.Error(t, err)
		assert.ErrorIs(t, err, jwks.ErrUnavailable)
	})
}
