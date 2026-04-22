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

package passportexchange

import (
	"sync"
	"time"
)

type cacheEntry struct {
	response  ExchangeResponse
	expiresAt time.Time
}

type responseCache struct {
	mu         sync.RWMutex
	entries    map[string]cacheEntry
	defaultTTL time.Duration
}

func newResponseCache(config CacheConfig) *responseCache {
	if !config.Enabled {
		return nil
	}

	defaultTTL := config.DefaultTTL
	if defaultTTL <= 0 {
		defaultTTL = defaultCacheTTL
	}

	return &responseCache{
		entries:    map[string]cacheEntry{},
		defaultTTL: defaultTTL,
	}
}

func (c *responseCache) get(key string, now time.Time) (*ExchangeResponse, bool) {
	if c == nil {
		return nil, false
	}

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}

	if !entry.expiresAt.After(now) {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()

		return nil, false
	}

	out := entry.response
	out.Cached = true

	return &out, true
}

func (c *responseCache) set(key string, response ExchangeResponse, now time.Time) {
	if c == nil {
		return
	}

	ttl := c.defaultTTL
	if response.ExpiresIn > 0 {
		ttl = time.Duration(response.ExpiresIn) * time.Second
	}

	if ttl <= 0 {
		return
	}

	entry := cacheEntry{
		response:  response,
		expiresAt: now.Add(ttl),
	}

	c.mu.Lock()
	c.entries[key] = entry
	c.mu.Unlock()
}
