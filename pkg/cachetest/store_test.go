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

package cachetest_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/cachetest"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	return scheme
}

func configMap(namespace, name, tier string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    map[string]string{"tier": tier},
		},
	}
}

func names(list *corev1.ConfigMapList) []string {
	out := make([]string, len(list.Items))

	for i := range list.Items {
		out[i] = list.Items[i].Name
	}

	return out
}

func TestListAppliesOptions(t *testing.T) {
	t.Parallel()

	store := cachetest.New(t, newScheme(t),
		configMap("a", "one", "web"),
		configMap("a", "two", "db"),
		configMap("b", "three", "web"),
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "secret"}},
	)

	list := &corev1.ConfigMapList{}
	require.NoError(t, store.Client().List(t.Context(), list, client.InNamespace("a")))
	require.ElementsMatch(t, []string{"one", "two"}, names(list))

	list = &corev1.ConfigMapList{}
	require.NoError(t, store.Client().List(t.Context(), list, client.MatchingLabelsSelector{Selector: labels.SelectorFromSet(labels.Set{"tier": "web"})}))
	require.ElementsMatch(t, []string{"one", "three"}, names(list))

	options := store.ListOptions()
	require.Len(t, options, 2)
	require.Equal(t, "a", options[0].Namespace)
	require.NotNil(t, options[1].LabelSelector)
}

func TestListRejectsLimitAndContinue(t *testing.T) {
	t.Parallel()

	store := cachetest.New(t, newScheme(t), configMap("a", "one", "web"))

	err := store.Client().List(t.Context(), &corev1.ConfigMapList{}, client.Limit(1))
	require.ErrorIs(t, err, cachetest.ErrUnsupported)

	err = store.Client().List(t.Context(), &corev1.ConfigMapList{}, client.Continue("token"))
	require.ErrorIs(t, err, cachetest.ErrUnsupported)
}

func TestListShufflesFromSeed(t *testing.T) {
	t.Parallel()

	objects := make([]client.Object, 8)
	for i := range objects {
		objects[i] = configMap("a", string(rune('a'+i)), "web")
	}

	orders := func(seed [32]byte) [][]string {
		store := cachetest.NewSeeded(newScheme(t), seed, objects...)

		var out [][]string

		for range 10 {
			list := &corev1.ConfigMapList{}
			require.NoError(t, store.Client().List(t.Context(), list))

			out = append(out, names(list))
		}

		return out
	}

	first := orders([32]byte{1})
	require.Equal(t, first, orders([32]byte{1}))

	distinct := map[string]bool{}
	for _, order := range first {
		distinct[fmt.Sprint(order)] = true
	}

	require.Greater(t, len(distinct), 1)
}

func TestForBenchmarkKeepsOrderAndRecordsNothing(t *testing.T) {
	t.Parallel()

	objects := make([]client.Object, 8)
	want := make([]string, len(objects))

	for i := range objects {
		want[i] = string(rune('a' + i))
		objects[i] = configMap("a", want[i], "web")
	}

	store := cachetest.New(t, newScheme(t), objects...).ForBenchmark()

	for range 10 {
		list := &corev1.ConfigMapList{}
		require.NoError(t, store.Client().List(t.Context(), list))
		require.Equal(t, want, names(list))
	}

	require.NoError(t, store.Client().Get(t.Context(), client.ObjectKey{Namespace: "a", Name: "a"}, &corev1.ConfigMap{}))
	require.Empty(t, store.ListOptions())
	require.Empty(t, store.GetOptions())
}

func TestListCopies(t *testing.T) {
	t.Parallel()

	t.Run("deep copies by default", func(t *testing.T) {
		t.Parallel()

		store := cachetest.New(t, newScheme(t), configMap("a", "one", "web"))

		list := &corev1.ConfigMapList{}
		require.NoError(t, store.Client().List(t.Context(), list))
		list.Items[0].Labels["tier"] = "changed"

		store.RequireUnchanged(t)
	})

	t.Run("shares maps without deep copies", func(t *testing.T) {
		t.Parallel()

		backing := configMap("a", "one", "web")
		store := cachetest.New(t, newScheme(t), backing)

		list := &corev1.ConfigMapList{}
		require.NoError(t, store.Client().List(t.Context(), list, client.UnsafeDisableDeepCopy))

		// The struct is a copy.  Its map is shared.
		list.Items[0].Name = "renamed"
		list.Items[0].Labels["tier"] = "changed"

		require.Equal(t, "one", backing.Name)
		require.Equal(t, "changed", backing.Labels["tier"])
	})
}

func TestGetCopies(t *testing.T) {
	t.Parallel()

	backing := configMap("a", "one", "web")
	store := cachetest.New(t, newScheme(t), backing)
	key := client.ObjectKey{Namespace: "a", Name: "one"}

	deep := &corev1.ConfigMap{}
	require.NoError(t, store.Client().Get(t.Context(), key, deep))
	deep.Labels["tier"] = "changed"

	require.Equal(t, "web", backing.Labels["tier"])

	shallow := &corev1.ConfigMap{}
	require.NoError(t, store.Client().Get(t.Context(), key, shallow, client.UnsafeDisableDeepCopy))
	shallow.Name = "renamed"
	shallow.Labels["tier"] = "changed"

	require.Equal(t, "one", backing.Name)
	require.Equal(t, "changed", backing.Labels["tier"])

	options := store.GetOptions()
	require.Len(t, options, 2)
	require.Nil(t, options[0].UnsafeDisableDeepCopy)
	require.True(t, *options[1].UnsafeDisableDeepCopy)

	err := store.Client().Get(t.Context(), client.ObjectKey{Namespace: "a", Name: "missing"}, &corev1.ConfigMap{})
	require.True(t, kerrors.IsNotFound(err))

	err = store.Client().Get(t.Context(), key, &corev1.Secret{})
	require.True(t, kerrors.IsNotFound(err))
}
