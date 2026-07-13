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
// availability contract the coarse-decision cache depends on.

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

// countingClient counts ConfigMap Gets and can be switched to fail, so the
// refresh cadence and the last-good retention contract are observable.
type countingClient struct {
	client.Client

	mu   sync.Mutex
	gets int
	err  error
}

func (c *countingClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	c.mu.Lock()
	c.gets++
	err := c.err
	c.mu.Unlock()

	if err != nil {
		return err
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

func TestPolicyStoreHasherStableNonEmpty(t *testing.T) {
	t.Parallel()

	hasher := cerbos.NewPolicyStoreHasher(
		hashClient(t, policyConfigMap("identity_groups-0a1b2c3d.yaml", "uni_roles-8c9d0e1f.yaml")),
		hashNamespace, hashConfigMap, time.Hour)

	hash, ok := hasher.Current(t.Context())
	require.True(t, ok)
	require.NotEmpty(t, hash)
}

func TestPolicyStoreHasherNoReReadWithinInterval(t *testing.T) {
	t.Parallel()

	counting := &countingClient{Client: hashClient(t, policyConfigMap("identity_groups-0a1b2c3d.yaml"))}

	// A long interval: only the first Current reads the ConfigMap; the rest
	// return the memoized hash without a further Get.
	hasher := cerbos.NewPolicyStoreHasher(counting, hashNamespace, hashConfigMap, time.Hour)

	first, ok := hasher.Current(t.Context())
	require.True(t, ok)

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
	// immediately.
	hasher := cerbos.NewPolicyStoreHasher(c, hashNamespace, hashConfigMap, 0)

	before, ok := hasher.Current(t.Context())
	require.True(t, ok)

	// Simulate a republish: the controller's content-addressed keys change
	// when policy content changes (here one file's hash suffix flips).
	updated := &corev1.ConfigMap{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Namespace: hashNamespace, Name: hashConfigMap}, updated))
	updated.Data = policyConfigMap("identity_groups-ffffffff.yaml", "uni_roles-8c9d0e1f.yaml").Data
	require.NoError(t, c.Update(t.Context(), updated))

	after, ok := hasher.Current(t.Context())
	require.True(t, ok)

	require.NotEqual(t, before, after, "a changed policy-store key set must change the hash (the bust signal)")
}

func TestPolicyStoreHasherUnavailableBeforeFirstSuccess(t *testing.T) {
	t.Parallel()

	// No ConfigMap published yet: the Get fails (NotFound), and with no prior
	// success the hasher reports unavailable so the cache stays bypassed
	// rather than keying on a bogus hash.
	hasher := cerbos.NewPolicyStoreHasher(hashClient(t), hashNamespace, hashConfigMap, time.Hour)

	_, ok := hasher.Current(t.Context())
	require.False(t, ok)
}

func TestPolicyStoreHasherConcurrentCurrentIsRaceFree(t *testing.T) {
	t.Parallel()

	// Current is invoked on every cerbos-mode decision, concurrently.  Its
	// mutex-guarded read-through must be data-race-free and hand every caller
	// one consistent hash.
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

	for i := range hashes {
		require.True(t, oks[i])
		require.Equal(t, hashes[0], hashes[i], "all concurrent callers must observe one consistent hash")
	}
}

func TestPolicyStoreHasherRetainsLastGoodAfterFailedRefresh(t *testing.T) {
	t.Parallel()

	counting := &countingClient{Client: hashClient(t, policyConfigMap("identity_groups-0a1b2c3d.yaml"))}

	// A zero interval forces a re-read on the second call, which we make fail.
	hasher := cerbos.NewPolicyStoreHasher(counting, hashNamespace, hashConfigMap, 0)

	good, ok := hasher.Current(t.Context())
	require.True(t, ok)
	require.NotEmpty(t, good)

	// A later refresh fails transiently.
	counting.failWith(errPolicyStoreRead)

	retained, ok := hasher.Current(t.Context())
	require.True(t, ok, "a failed refresh after a prior success must retain the last-good hash, not fail closed")
	require.Equal(t, good, retained)
}
