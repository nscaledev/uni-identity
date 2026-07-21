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

package cerbos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// PolicyStoreHasher is a read-through provider of the current policy-store
// fingerprint, used by pkg/rbac's coarse-decision cache as the cache-key
// dimension that busts every entry on a policy republish.
//
// The fingerprint is derived from the controller-owned policies ConfigMap's
// KEY SET, not its values.  The policy controller publishes every generated
// file under a content-addressed key (`<base>-<sha256[:8]>.yaml`, see
// controller.hashKeyedData): any policy content change changes at least one
// key, so hashing the sorted key set yields a stable token that changes iff
// the store content changes.  Identity cannot obtain this from the PDP — the
// Cerbos response only echoes the REQUESTED policy version, which identity's
// coarse checks leave unset — so it read-throughs the ConfigMap directly.
//
// Availability is fail-safe: Current reports unavailable (ok=false) until the
// first successful read, so the cache stays bypassed rather than keyed on a
// bogus hash; after a first success it retains the last-good hash across a
// later failed refresh (a transient ConfigMap read blip must not fail-closed
// every decision — residual staleness is bounded by the decision cache TTL).
//
// Current never blocks on the API server: reads run on a background
// goroutine, detached from the caller that elects them, so a slow or hung
// API server degrades decisions to the fail-safe path instead of stalling
// them.
type PolicyStoreHasher struct {
	// client reads the ConfigMap.  It MUST be a direct (uncached) client: a
	// cache-backed client would spin up a cluster-wide ConfigMap informer,
	// which the chart's ConfigMap grant (a narrow get) deliberately does not
	// permit — the same reason the policy controller reads uncached.
	client client.Client

	// namespace and name locate the controller-owned policy store ConfigMap.
	namespace string
	name      string

	// refresh bounds how often the ConfigMap is re-read: at most one Get per
	// interval, memoized in between.
	refresh time.Duration

	// mu guards the memoized state below; Current is called on every
	// cerbos-mode decision, concurrently.
	mu sync.Mutex

	// hash is the last successfully computed fingerprint; haveHash records
	// whether any read has ever succeeded (the availability gate).
	hash     string
	haveHash bool

	// nextRead is the earliest wall-clock time the ConfigMap may be re-read.
	nextRead time.Time

	// readFailed tracks the last read outcome so a failure is logged at most
	// once per transition rather than once per decision.
	readFailed bool

	// refreshing is true while a background goroutine is reading the
	// ConfigMap, ensuring at most one read is ever in flight.  Callers never
	// wait on it: they serve the memoized state and move on.
	refreshing bool
}

// NewPolicyStoreHasher returns a hasher reading the ConfigMap named name in
// namespace through client, re-reading at most once per refresh interval.
func NewPolicyStoreHasher(client client.Client, namespace, name string, refresh time.Duration) *PolicyStoreHasher {
	return &PolicyStoreHasher{
		client:    client,
		namespace: namespace,
		name:      name,
		refresh:   refresh,
	}
}

// Current returns the current policy-store hash and whether it is available.
// It NEVER blocks beyond the memoizing mutex: Current is on the per-decision
// hot path (decisionCacheKey and recordDecisions both call it on every
// cerbos-mode decision), so an API-server read — however slow — must never
// stall a decision.  When a re-read is due it elects one background refresh,
// detached from the calling request, and returns the memoized state
// immediately: the last-good hash after a first success (a transient read
// blip must not fail-closed every decision; residual staleness is bounded by
// the decision cache TTL), or ("", false) during the cold-start window before
// the first read lands — the fail-safe that bypasses the coarse-decision
// cache rather than keying it on a bogus hash.
func (h *PolicyStoreHasher) Current(ctx context.Context) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Elect a refresh if one is due and none is in flight.  nextRead advances
	// at election so the interval rate-limits regardless of outcome; the read
	// itself runs on a background goroutine — no caller, not even the electing
	// one, performs it inline.
	if now := time.Now(); !h.refreshing && !now.Before(h.nextRead) {
		h.refreshing = true
		h.nextRead = now.Add(h.refresh)

		go h.refreshHash(ctx)
	}

	return h.hash, h.haveHash
}

// policyStoreReadTimeout bounds the background ConfigMap read.  The refresh
// context is detached from the electing caller, so this is the read's only
// bound: without it a hung API-server connection would pin the single refresh
// slot indefinitely.
const policyStoreReadTimeout = 10 * time.Second

// refreshHash performs one ConfigMap read and publishes the outcome.  It runs
// on its own goroutine with a context that inherits the electing caller's
// values (the logger) but NOT its cancellation: the refresh is a shared,
// once-per-interval resource, and binding it to whichever request happened to
// elect it would let a routine client disconnect burn the interval's only
// attempt for the whole process.
func (h *PolicyStoreHasher) refreshHash(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), policyStoreReadTimeout)
	defer cancel()

	configMap := &corev1.ConfigMap{}
	err := h.client.Get(ctx, types.NamespacedName{Namespace: h.namespace, Name: h.name}, configMap)

	h.mu.Lock()
	defer h.mu.Unlock()

	h.refreshing = false

	if err != nil {
		// Fail-safe: keep serving the last-good hash (if any) rather than
		// forcing every decision to bypass the cache on a transient blip; the
		// decision cache TTL bounds the resulting staleness.  Log once per
		// failure transition to avoid per-decision spam.
		if !h.readFailed {
			log.FromContext(ctx).Error(err, "policy store hash refresh failed; retaining last-good hash",
				"namespace", h.namespace, "name", h.name, "haveHash", h.haveHash)

			h.readFailed = true
		}

		return
	}

	h.readFailed = false
	h.hash = storeHash(configMap.Data)
	h.haveHash = true
}

// storeHash fingerprints the ConfigMap's key set: sha256 of the sorted keys
// joined by newlines, hex-encoded.  Values are ignored — the controller's
// content-addressed keys already encode content, so the key set alone changes
// iff any policy content changes.  An empty store hashes to a fixed non-empty
// token (the hash of the empty string), which is a valid, stable fingerprint.
func storeHash(data map[string]string) string {
	keys := slices.Sorted(maps.Keys(data))
	sum := sha256.Sum256([]byte(strings.Join(keys, "\n")))

	return hex.EncodeToString(sum[:])
}
