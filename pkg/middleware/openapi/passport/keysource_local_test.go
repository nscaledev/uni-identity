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
	"context"
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type keyLookupServiceFunc func(ctx context.Context, keyID string) (*jose.JSONWebKey, *jose.JSONWebKey, error)

func (f keyLookupServiceFunc) GetKeyByID(ctx context.Context, keyID string) (*jose.JSONWebKey, *jose.JSONWebKey, error) {
	return f(ctx, keyID)
}

func TestLocalKeySource(t *testing.T) {
	t.Parallel()

	t.Run("returns public key on success", func(t *testing.T) {
		t.Parallel()

		expected := &jose.JSONWebKey{KeyID: "kid-1"}
		service := keyLookupServiceFunc(func(_ context.Context, keyID string) (*jose.JSONWebKey, *jose.JSONWebKey, error) {
			assert.Equal(t, "kid-1", keyID)
			return expected, &jose.JSONWebKey{KeyID: "priv"}, nil
		})

		source := NewLocalKeySource(service)
		key, err := source.Get(t.Context(), "kid-1")
		require.NoError(t, err)
		assert.Equal(t, expected, key)
	})

	t.Run("maps service errors to jwks unavailable", func(t *testing.T) {
		t.Parallel()

		service := keyLookupServiceFunc(func(_ context.Context, _ string) (*jose.JSONWebKey, *jose.JSONWebKey, error) {
			return nil, nil, fmt.Errorf("lookup failed")
		})

		source := NewLocalKeySource(service)
		_, err := source.Get(t.Context(), "kid-1")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrJWKSUnavailable)
	})

	t.Run("returns unavailable when source is not configured", func(t *testing.T) {
		t.Parallel()

		source := NewLocalKeySource(nil)
		_, err := source.Get(t.Context(), "kid-1")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrJWKSUnavailable)
	})
}
