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
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/readiness"
)

var (
	errNoKey = errors.New("secrets is forbidden: User \"system:serviceaccount:ns:sa\"")

	errSourceClosed = errors.New("x509source: source is closed")
)

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

// svidSource returns svid, or err when it is set.
type svidSource struct {
	svid *x509svid.SVID
	err  error
}

func (s *svidSource) GetX509SVID() (*x509svid.SVID, error) {
	if s.err != nil {
		return nil, s.err
	}

	return s.svid, nil
}

func svidExpiringAt(notAfter time.Time) *x509svid.SVID {
	return &x509svid.SVID{Certificates: []*x509.Certificate{{NotAfter: notAfter}}}
}

func TestSVIDAvailable(t *testing.T) {
	t.Parallel()

	t.Run("follows the SVID expiry on each probe", func(t *testing.T) {
		t.Parallel()

		expiredAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

		source := &svidSource{svid: svidExpiringAt(time.Now().Add(time.Hour))}
		checker := readiness.New(readiness.SVIDAvailable(source))
		require.NoError(t, checker.Check(t.Context()))

		source.svid = svidExpiringAt(expiredAt)

		err := checker.Check(t.Context())
		require.ErrorIs(t, err, readiness.ErrSVIDExpired)
		require.ErrorContains(t, err, "2026-01-02T03:04:05Z", "the not-ready reason names the expiry time")
		require.Equal(t, http.StatusServiceUnavailable, probe(checker).Code)

		source.svid = svidExpiringAt(time.Now().Add(time.Hour))

		require.NoError(t, checker.Check(t.Context()), "a renewed SVID returns the replica to service")
	})

	t.Run("not ready when the source fails", func(t *testing.T) {
		t.Parallel()

		checker := readiness.New(readiness.SVIDAvailable(&svidSource{err: errSourceClosed}))
		require.ErrorIs(t, checker.Check(t.Context()), errSourceClosed)
	})
}
