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

package cerbos_test

import (
	"context"
	goerrors "errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/authz/cerbos"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// These tests pin the A15 policy-store hasher: a read-through fingerprint of
// the controller-owned policies ConfigMap key set, with the fail-safe
// availability contract the coarse-decision cache depends on, and the
// non-blocking hot-path contract: Current never waits on an API-server read —
// the refresh runs in the background, detached from the caller that starts it.

const (
	hashNamespace = "identity-system"
	hashConfigMap = "identity-cerbos-policies"
)

var errPolicyStoreRead = goerrors.New("policy store read failure")

// policyConfigMap builds the controller-owned policy store ConfigMap with the
// given content-addressed keys (values are irrelevant to the hash).
func policyConfigMap(keys ...string) *corev1.ConfigMap {
	data := make(map[string]string, len(keys))
	for _, key := range keys {
		data[key] = "policy-content-for-" + key
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: hashNamespace, Name: hashConfigMap},
		Data:       data,
	}
}

func hashScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, scheme.AddToScheme(s))

	return s
}

func hashClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	return fake.NewClientBuilder().WithScheme(hashScheme(t)).WithObjects(objects...).Build()
}

// countingClient counts ConfigMap Gets, can be switched to fail, and can be
// gated so a Get parks until the gate is closed — a hung API server.  Unlike
// the embedded fake it honours context cancellation the way the real
// API-server client does; the detached-refresh contract is observable only
// against a client that does.
type countingClient struct {
	client.Client

	mu   sync.Mutex
	gets int
	err  error
	gate chan struct{}
}

func (c *countingClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	c.mu.Lock()
	c.gets++
	failure := c.err
	gate := c.gate
	c.mu.Unlock()

	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if failure != nil {
		return failure
	}

	return c.Client.Get(ctx, key, obj, opts...)
}

func (c *countingClient) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.gets
}

func (c *countingClient) failWith(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.err = err
}

func (c *countingClient) setGate(gate chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.gate = gate
}

// waitForHash spins until the background read lands and the hasher reports
// available, returning the hash.  Current never blocks — a cold-start caller
// gets ("", false) until the first read completes — so tests await
// availability rather than assuming the call that starts the read returns it.
func waitForHash(t *testing.T, hasher *cerbos.PolicyStoreHasher) string {
	t.Helper()

	var hash string

	require.Eventually(t, func() bool {
		var ok bool

		hash, ok = hasher.Current(t.Context())

		return ok
	}, 10*time.Second, time.Millisecond, "the background refresh must eventually deliver availability")

	return hash
}

// currentPrompt calls Current and fails the test if it does not return
// promptly.  This is the hot-path contract: Current is called on every
// cerbos-mode decision and must never stall behind an API-server read,
// whatever state that read is in.
func currentPrompt(t *testing.T, hasher *cerbos.PolicyStoreHasher) (string, bool) {
	t.Helper()

	type result struct {
		hash string
		ok   bool
	}

	results := make(chan result, 1)

	go func() {
		hash, ok := hasher.Current(t.Context())

		results <- result{hash: hash, ok: ok}
	}()

	select {
	case r := <-results:
		return r.hash, r.ok
	case <-time.After(5 * time.Second):
		t.Fatal("Current blocked behind an API-server read; the hot-path contract is that it returns the memoized state immediately")

		return "", false
	}
}

func TestPolicyStoreHasherStableNonEmpty(t *testing.T) {
	t.Parallel()

	hasher := cerbos.NewPolicyStoreHasher(
		hashClient(t, policyConfigMap("identity_groups-0a1b2c3d.yaml", "uni_roles-8c9d0e1f.yaml")),
		hashNamespace, hashConfigMap, time.Hour)

	hash := waitForHash(t, hasher)
	require.NotEmpty(t, hash)

	again, ok := hasher.Current(t.Context())
	require.True(t, ok)
	require.Equal(t, hash, again)
}

func TestPolicyStoreHasherColdStartDoesNotBlockOnSlowRead(t *testing.T) {
	t.Parallel()

	// A hung API server during cold start must not stall decisions: the
	// fail-safe for the no-hash state is ("", false) — the coarse-decision
	// cache is bypassed and the decision proceeds uncached — never a wait on
	// the in-flight first read.
	counting := &countingClient{Client: hashClient(t, policyConfigMap("identity_groups-0a1b2c3d.yaml"))}

	gate := make(chan struct{})
	counting.setGate(gate)

	hasher := cerbos.NewPolicyStoreHasher(counting, hashNamespace, hashConfigMap, time.Hour)

	hash, ok := currentPrompt(t, hasher)
	require.False(t, ok, "no read has succeeded yet: the fail-safe is unavailable, not a wait")
	require.Empty(t, hash)

	// Releasing the hung read delivers availability in the background.
	close(gate)
	waitForHash(t, hasher)
}

func TestPolicyStoreHasherServesLastGoodDuringSlowRefresh(t *testing.T) {
	t.Parallel()

	counting := &countingClient{Client: hashClient(t, policyConfigMap("identity_groups-0a1b2c3d.yaml"))}

	// A zero interval makes every call due, so a refresh — gated, simulating a
	// hung API server — starts as soon as one is not already running.
	hasher := cerbos.NewPolicyStoreHasher(counting, hashNamespace, hashConfigMap, 0)

	good := waitForHash(t, hasher)

	counting.setGate(make(chan struct{}))

	// Every caller — including the one whose call starts the hung refresh —
	// must serve the last-good hash immediately rather than stalling behind
	// the read for its whole request lifetime.
	for range 3 {
		hash, ok := currentPrompt(t, hasher)
		require.True(t, ok, "a caller with a last-good hash must be served during a hung refresh")
		require.Equal(t, good, hash)
	}
}

func TestPolicyStoreHasherRefreshSurvivesCallerCancellation(t *testing.T) {
	t.Parallel()

	// The once-per-interval refresh is a shared, process-wide resource: it
	// must not ride on the lifetime of whichever request happens to start it,
	// or one disconnecting client burns the interval's only attempt for the
	// whole process (cache bypassed and audit correlate lost fleet-wide until
	// the next interval).
	counting := &countingClient{Client: hashClient(t, policyConfigMap("identity_groups-0a1b2c3d.yaml"))}

	hasher := cerbos.NewPolicyStoreHasher(counting, hashNamespace, hashConfigMap, time.Hour)

	cancelled, cancel := context.WithCancel(t.Context())
	cancel()

	_, ok := hasher.Current(cancelled)
	require.False(t, ok, "no hash is available before the first read lands")

	// With an hour-long interval there is no second attempt inside this test:
	// availability arriving at all proves the read outlived its caller.
	waitForHash(t, hasher)
	require.Equal(t, 1, counting.count(), "the interval's single refresh attempt must have succeeded")
}

func TestPolicyStoreHasherNoReReadWithinInterval(t *testing.T) {
	t.Parallel()

	counting := &countingClient{Client: hashClient(t, policyConfigMap("identity_groups-0a1b2c3d.yaml"))}

	// A long interval: only the first call elects a read; once it lands the
	// rest return the memoized hash without a further Get.
	hasher := cerbos.NewPolicyStoreHasher(counting, hashNamespace, hashConfigMap, time.Hour)

	first := waitForHash(t, hasher)

	for range 5 {
		hash, ok := hasher.Current(t.Context())
		require.True(t, ok)
		require.Equal(t, first, hash)
	}

	require.Equal(t, 1, counting.count(), "the ConfigMap must be read at most once per refresh interval")
}

func TestPolicyStoreHasherKeySetChangeChangesHash(t *testing.T) {
	t.Parallel()

	c := hashClient(t, policyConfigMap("identity_groups-0a1b2c3d.yaml", "uni_roles-8c9d0e1f.yaml"))

	// A zero interval re-reads on every call, so a republish is observed
	// as soon as the next background read lands.
	hasher := cerbos.NewPolicyStoreHasher(c, hashNamespace, hashConfigMap, 0)

	before := waitForHash(t, hasher)

	// Simulate a republish: the controller's content-addressed keys change
	// when policy content changes (here one file's hash suffix flips).
	updated := &corev1.ConfigMap{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Namespace: hashNamespace, Name: hashConfigMap}, updated))
	updated.Data = policyConfigMap("identity_groups-ffffffff.yaml", "uni_roles-8c9d0e1f.yaml").Data
	require.NoError(t, c.Update(t.Context(), updated))

	require.Eventually(t, func() bool {
		after, ok := hasher.Current(t.Context())

		return ok && after != before
	}, 10*time.Second, time.Millisecond, "a changed policy-store key set must change the hash (the bust signal)")
}

func TestPolicyStoreHasherUnavailableBeforeFirstSuccess(t *testing.T) {
	t.Parallel()

	// No ConfigMap published yet: the Get fails (NotFound), and with no prior
	// success the hasher reports unavailable so the cache stays bypassed
	// rather than keying on a bogus hash.
	counting := &countingClient{Client: hashClient(t)}

	hasher := cerbos.NewPolicyStoreHasher(counting, hashNamespace, hashConfigMap, time.Hour)

	_, ok := hasher.Current(t.Context())
	require.False(t, ok)

	// Still unavailable once the failed background read has landed — failure
	// must not publish a hash.
	require.Eventually(t, func() bool {
		return counting.count() >= 1
	}, 10*time.Second, time.Millisecond)

	_, ok = hasher.Current(t.Context())
	require.False(t, ok, "a failed first read must leave the hasher unavailable (fail-safe), not publish a bogus hash")
}

func TestPolicyStoreHasherConcurrentCurrentIsRaceFree(t *testing.T) {
	t.Parallel()

	// Current is invoked on every cerbos-mode decision, concurrently.  Its
	// mutex-guarded read-through must be data-race-free, and any caller that
	// observes an available hash must observe the same one; callers racing the
	// first read get the fail-safe ("", false) rather than a wait.
	hasher := cerbos.NewPolicyStoreHasher(
		hashClient(t, policyConfigMap("identity_groups-0a1b2c3d.yaml", "uni_roles-8c9d0e1f.yaml")),
		hashNamespace, hashConfigMap, time.Hour)

	ctx := t.Context()

	const goroutines = 64

	hashes := make([]string, goroutines)
	oks := make([]bool, goroutines)

	var wg sync.WaitGroup

	for i := range hashes {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			hashes[i], oks[i] = hasher.Current(ctx)
		}(i)
	}

	wg.Wait()

	available := waitForHash(t, hasher)

	for i := range hashes {
		if !oks[i] {
			require.Empty(t, hashes[i], "an unavailable observation must carry no hash")

			continue
		}

		require.Equal(t, available, hashes[i], "all available observations must agree on one consistent hash")
	}
}

func TestPolicyStoreHasherRetainsLastGoodAfterFailedRefresh(t *testing.T) {
	t.Parallel()

	counting := &countingClient{Client: hashClient(t, policyConfigMap("identity_groups-0a1b2c3d.yaml"))}

	// A zero interval re-reads on every call, so a failing refresh is
	// triggered as soon as the client is switched to fail.
	hasher := cerbos.NewPolicyStoreHasher(counting, hashNamespace, hashConfigMap, 0)

	good := waitForHash(t, hasher)

	// A later refresh fails transiently.
	counting.failWith(errPolicyStoreRead)

	base := counting.count()

	// Trigger refreshes until at least one failed read has landed; every
	// intervening call must keep serving the last-good hash.
	require.Eventually(t, func() bool {
		hash, ok := hasher.Current(t.Context())
		if !ok || hash != good {
			return false
		}

		return counting.count() > base
	}, 10*time.Second, time.Millisecond)

	retained, ok := hasher.Current(t.Context())
	require.True(t, ok, "a failed refresh after a prior success must retain the last-good hash, not fail closed")
	require.Equal(t, good, retained)
}
