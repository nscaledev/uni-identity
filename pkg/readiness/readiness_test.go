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

package readiness_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/readiness"
)

var errNoKey = errors.New("secrets is forbidden: User \"system:serviceaccount:ns:sa\"")

// keys fails while err is set, and counts reads.
type keys struct {
	err   error
	reads int
}

func (k *keys) GetPrimaryKey(context.Context) (*jose.JSONWebKey, *jose.JSONWebKey, error) {
	k.reads++

	if k.err != nil {
		return nil, nil, k.err
	}

	return &jose.JSONWebKey{}, &jose.JSONWebKey{}, nil
}

func probe(checker *readiness.Checker) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	checker.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	return w
}

func TestChecker(t *testing.T) {
	t.Parallel()

	t.Run("ready when the key is readable", func(t *testing.T) {
		t.Parallel()

		w := probe(readiness.New(readiness.SigningKeyAvailable(&keys{})))
		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	})

	t.Run("not ready without the signing key, and the cause is not served", func(t *testing.T) {
		t.Parallel()

		checker := readiness.New(readiness.SigningKeyAvailable(&keys{err: errNoKey}))
		require.ErrorIs(t, checker.Check(t.Context()), errNoKey)

		w := probe(checker)
		require.Equal(t, http.StatusServiceUnavailable, w.Code)
		require.Equal(t, "not ready\n", w.Body.String())
	})

	t.Run("stays ready once the key has been read", func(t *testing.T) {
		t.Parallel()

		k := &keys{}
		checker := readiness.New(readiness.SigningKeyAvailable(k))
		require.NoError(t, checker.Check(t.Context()))

		k.err = errNoKey

		require.NoError(t, checker.Check(t.Context()))
		require.Equal(t, 1, k.reads)
	})

	t.Run("not ready once stopping, whatever the conditions say", func(t *testing.T) {
		t.Parallel()

		checker := readiness.New(readiness.SigningKeyAvailable(&keys{}))
		checker.Stopping()
		require.ErrorIs(t, checker.Check(t.Context()), readiness.ErrStopping)
		require.Equal(t, http.StatusServiceUnavailable, probe(checker).Code)
	})
}
