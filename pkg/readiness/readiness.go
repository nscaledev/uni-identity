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

// Package readiness decides whether this server replica can serve requests.
package readiness

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

var (
	ErrStopping       = errors.New("server is shutting down")
	ErrCacheNotSynced = errors.New("read cache has not synced")
)

// cacheSyncProbe bounds the cache check. A synced cache answers at once.
const cacheSyncProbe = 100 * time.Millisecond

// Condition is one requirement for serving requests.
type Condition func(ctx context.Context) error

// CacheSyncer is the part of the read cache that reports sync.
type CacheSyncer interface {
	WaitForCacheSync(ctx context.Context) bool
}

// KeyGetter is the part of the JWT issuer that reads the signing key.
type KeyGetter interface {
	GetPrimaryKey(ctx context.Context) (*jose.JSONWebKey, *jose.JSONWebKey, error)
}

// Checker answers whether this replica can serve requests. Conditions are
// added while the server is assembled, before it listens; Stopping may be
// called from any goroutine.
type Checker struct {
	stopping   atomic.Bool
	conditions []Condition
}

func New(conditions ...Condition) *Checker {
	return &Checker{conditions: conditions}
}

// Require adds a condition. Call it before the server listens.
func (c *Checker) Require(condition Condition) {
	c.conditions = append(c.conditions, condition)
}

// Stopping takes the replica out of service for the rest of its life.
func (c *Checker) Stopping() {
	c.stopping.Store(true)
}

// Check returns nil when the server is not stopping and every condition holds.
func (c *Checker) Check(ctx context.Context) error {
	if c.stopping.Load() {
		return ErrStopping
	}

	for _, condition := range c.conditions {
		if err := condition(ctx); err != nil {
			return err
		}
	}

	return nil
}

// CacheSynced holds once the read cache has synced.
func CacheSynced(cache CacheSyncer) Condition {
	return func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, cacheSyncProbe)
		defer cancel()

		if !cache.WaitForCacheSync(ctx) {
			return ErrCacheNotSynced
		}

		return nil
	}
}

// SigningKeyAvailable holds once this replica can read the primary signing key,
// without which it can neither issue nor verify a token.
func SigningKeyAvailable(keys KeyGetter) Condition {
	return func(ctx context.Context) error {
		if _, _, err := keys.GetPrimaryKey(ctx); err != nil {
			return fmt.Errorf("signing key unavailable: %w", err)
		}

		return nil
	}
}
