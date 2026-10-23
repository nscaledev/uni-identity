/*
Copyright 2022-2024 EscherCloud.
Copyright 2024-2025 the Unikorn Authors.
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
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/readiness"
)

var errNoKey = errors.New("no key")

type syncer bool

func (s syncer) WaitForCacheSync(ctx context.Context) bool {
	if s {
		return true
	}

	<-ctx.Done()

	return false
}

type keys struct {
	err error
}

func (k keys) GetPrimaryKey(context.Context) (*jose.JSONWebKey, *jose.JSONWebKey, error) {
	if k.err != nil {
		return nil, nil, k.err
	}

	return &jose.JSONWebKey{}, &jose.JSONWebKey{}, nil
}

func TestChecker(t *testing.T) {
	t.Parallel()

	t.Run("ready when the cache is synced and the key is readable", func(t *testing.T) {
		t.Parallel()

		checker := readiness.New(readiness.CacheSynced(syncer(true)))
		checker.Require(readiness.SigningKeyAvailable(keys{}))
		require.NoError(t, checker.Check(t.Context()))
	})

	t.Run("not ready until the cache has synced", func(t *testing.T) {
		t.Parallel()

		checker := readiness.New(readiness.CacheSynced(syncer(false)))
		require.ErrorIs(t, checker.Check(t.Context()), readiness.ErrCacheNotSynced)
	})

	t.Run("not ready without the signing key", func(t *testing.T) {
		t.Parallel()

		checker := readiness.New(readiness.SigningKeyAvailable(keys{err: errNoKey}))
		require.ErrorIs(t, checker.Check(t.Context()), errNoKey)
	})

	t.Run("not ready once stopping, whatever the conditions say", func(t *testing.T) {
		t.Parallel()

		checker := readiness.New(readiness.CacheSynced(syncer(true)))
		checker.Stopping()
		require.ErrorIs(t, checker.Check(t.Context()), readiness.ErrStopping)
	})
}
