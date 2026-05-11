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

package auth0 //nolint:testpackage

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUserinfoVerifier(t *testing.T) {
	t.Parallel()

	t.Run("rejects nil options", func(t *testing.T) {
		t.Parallel()

		_, err := NewUserinfoVerifier(http.DefaultClient, nil)
		require.ErrorIs(t, err, ErrNotConfigured)
	})

	t.Run("rejects missing userinfo URL", func(t *testing.T) {
		t.Parallel()

		_, err := NewUserinfoVerifier(http.DefaultClient, &Options{})
		require.ErrorIs(t, err, ErrNotConfigured)
	})
}

func TestUserinfoVerifier_Verify(t *testing.T) {
	t.Parallel()

	t.Run("valid opaque token returns subject and email", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if value := r.Header.Get("Authorization"); value != "Bearer opaque-token" {
				t.Errorf("unexpected authorization header: %q", value)
			}

			w.WriteHeader(http.StatusOK)

			if err := json.NewEncoder(w).Encode(map[string]any{
				"sub":   "auth0|user-1",
				"email": "user@example.com",
			}); err != nil {
				t.Errorf("failed to encode userinfo response: %v", err)
			}
		}))
		t.Cleanup(server.Close)

		verifier, err := NewUserinfoVerifier(server.Client(), &Options{
			Issuer:              "https://tenant.auth0.com/",
			UserinfoURL:         server.URL,
			UserinfoHTTPTimeout: 300 * time.Millisecond,
		})
		require.NoError(t, err)

		claims, err := verifier.Verify(t.Context(), "opaque-token")
		require.NoError(t, err)
		require.NotNil(t, claims)
		assert.Equal(t, "auth0|user-1", claims.Subject)
		assert.Equal(t, "user@example.com", claims.Email)
	})

	t.Run("userinfo unauthorized returns invalid token", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		t.Cleanup(server.Close)

		verifier, err := NewUserinfoVerifier(server.Client(), &Options{
			Issuer:      "https://tenant.auth0.com/",
			UserinfoURL: server.URL,
		})
		require.NoError(t, err)

		_, err = verifier.Verify(t.Context(), "opaque-token")
		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("userinfo timeout returns unavailable", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(80 * time.Millisecond)
			w.WriteHeader(http.StatusOK)

			if err := json.NewEncoder(w).Encode(map[string]any{"sub": "auth0|user-1"}); err != nil {
				t.Errorf("failed to encode userinfo response: %v", err)
			}
		}))
		t.Cleanup(server.Close)

		verifier, err := NewUserinfoVerifier(server.Client(), &Options{
			Issuer:              "https://tenant.auth0.com/",
			UserinfoURL:         server.URL,
			UserinfoHTTPTimeout: 20 * time.Millisecond,
			UserinfoMaxRetries:  0,
		})
		require.NoError(t, err)

		_, err = verifier.Verify(t.Context(), "opaque-token")
		require.ErrorIs(t, err, ErrUserinfoUnavailable)
	})

	t.Run("circuit breaker opens after configured failures", func(t *testing.T) {
		t.Parallel()

		var calls atomic.Int64

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		t.Cleanup(server.Close)

		verifier, err := NewUserinfoVerifier(server.Client(), &Options{
			Issuer:                      "https://tenant.auth0.com/",
			UserinfoURL:                 server.URL,
			UserinfoHTTPTimeout:         200 * time.Millisecond,
			UserinfoMaxRetries:          0,
			UserinfoCircuitFailures:     1,
			UserinfoCircuitOpenDuration: time.Second,
		})
		require.NoError(t, err)

		_, err = verifier.Verify(t.Context(), "opaque-token")
		require.ErrorIs(t, err, ErrUserinfoUnavailable)

		_, err = verifier.Verify(t.Context(), "opaque-token")
		require.ErrorIs(t, err, ErrUserinfoCircuitOpen)
		assert.Equal(t, int64(1), calls.Load())
	})
}
