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

// Package cachetest serves objects to unit tests the way the
// controller-runtime informer cache does.  Only test code may import it.
//
// The real cache and the controller-runtime fake client differ.  The fake
// client ignores UnsafeDisableDeepCopy, always deep copies and sorts lists
// by name.  The cache returns list items in no fixed order.  With
// UnsafeDisableDeepCopy, it returns shallow struct copies whose maps,
// slices and pointers stay shared with the informer store.  A Store models
// the cache, so a test fails when code mutates shared state, drops the
// option or relies on the order.
package cachetest

import (
	"cmp"
	"context"
	cryptorand "crypto/rand"
	"errors"
	"math/rand/v2"
	"reflect"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// ErrUnsupported is returned for a list option the store does not model.
var ErrUnsupported = errors.New("cachetest: unsupported option")

// Store holds the backing objects and records the options of each read.
type Store struct {
	client   client.Client
	objects  []client.Object
	snapshot []runtime.Object

	// benchmark disables shuffling and option recording.
	benchmark bool

	lock        sync.Mutex
	random      *rand.ChaCha8
	listOptions []client.ListOptions
	getOptions  []client.GetOptions
}

// New returns a store that holds the objects, with a random shuffle seed.
// The test log shows the seed when the test fails.
func New(tb testing.TB, scheme *runtime.Scheme, objects ...client.Object) *Store {
	tb.Helper()

	var seed [32]byte

	_, _ = cryptorand.Read(seed[:])

	tb.Cleanup(func() {
		if tb.Failed() {
			tb.Logf("cachetest shuffle seed: %#v; replay with cachetest.NewSeeded(scheme, seed, objects...) using this seed", seed)
		}
	})

	return NewSeeded(scheme, seed, objects...)
}

// NewSeeded returns a store that holds the objects and shuffles lists
// from the given seed.
func NewSeeded(scheme *runtime.Scheme, seed [32]byte, objects ...client.Object) *Store {
	s := &Store{
		objects:  objects,
		snapshot: make([]runtime.Object, len(objects)),
		random:   rand.NewChaCha8(seed),
	}

	for i := range objects {
		s.snapshot[i] = objects[i].DeepCopyObject()
	}

	s.client = fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		List: s.list,
		Get:  s.get,
	}).Build()

	return s
}

// ForBenchmark disables shuffling and option recording, so a benchmark
// does not time the work of the test double.  Lists then return objects in
// construction order, and ListOptions and GetOptions return nothing.  Use
// it only in benchmarks, and call it before the first read.
func (s *Store) ForBenchmark() *Store {
	s.benchmark = true

	return s
}

// Client returns a client that reads from the store.  Other operations go
// to an empty fake client.
func (s *Store) Client() client.Client {
	return s.client
}

// ListOptions returns the options of every List call, in call order.
func (s *Store) ListOptions() []client.ListOptions {
	s.lock.Lock()
	defer s.lock.Unlock()

	return slices.Clone(s.listOptions)
}

// GetOptions returns the options of every Get call, in call order.
func (s *Store) GetOptions() []client.GetOptions {
	s.lock.Lock()
	defer s.lock.Unlock()

	return slices.Clone(s.getOptions)
}

// RequireUnchanged fails the test when a backing object differs from its
// state at construction.
func (s *Store) RequireUnchanged(tb testing.TB) {
	tb.Helper()

	for i := range s.objects {
		require.Equal(tb, s.snapshot[i], s.objects[i], "cachetest: backing object %d changed", i)
	}
}

func noCopy(flag *bool) bool {
	return flag != nil && *flag
}

// unsupportedListOption reports whether options names a filter the store
// does not model: a field selector, a result limit, or a continuation
// token.  The real cache truncates on Limit and errors on Continue, so the
// store must not silently ignore them.
func unsupportedListOption(options client.ListOptions) bool {
	return options.FieldSelector != nil || options.Limit != 0 || options.Continue != ""
}

func (s *Store) list(_ context.Context, _ client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
	options := client.ListOptions{}
	options.ApplyOptions(opts)

	if unsupportedListOption(options) {
		return ErrUnsupported
	}

	itemsPtr, err := apimeta.GetItemsPtr(list)
	if err != nil {
		return err
	}

	itemType := reflect.TypeOf(itemsPtr).Elem().Elem()

	matches := s.matchingObjects(itemType, options)

	if !s.benchmark {
		s.lock.Lock()
		s.listOptions = append(s.listOptions, options)
		s.shuffle(matches)
		s.lock.Unlock()
	}

	// SetList copies each struct into a fresh slice.  Without deep copies
	// this is what the cache does: the items share maps and pointers with
	// the backing objects.
	return apimeta.SetList(list, matches)
}

// matchingObjects returns the backing objects of itemType whose namespace
// and labels satisfy options, deep-copied unless UnsafeDisableDeepCopy is
// set.
func (s *Store) matchingObjects(itemType reflect.Type, options client.ListOptions) []runtime.Object {
	selector := options.LabelSelector
	if selector == nil {
		selector = labels.Everything()
	}

	var matches []runtime.Object

	for _, object := range s.objects {
		if reflect.TypeOf(object).Elem() != itemType {
			continue
		}

		if options.Namespace != "" && object.GetNamespace() != options.Namespace {
			continue
		}

		if !selector.Matches(labels.Set(object.GetLabels())) {
			continue
		}

		if noCopy(options.UnsafeDisableDeepCopy) {
			matches = append(matches, object)
		} else {
			matches = append(matches, object.DeepCopyObject())
		}
	}

	return matches
}

// shuffle reorders objects: it sorts them by one random key each.
func (s *Store) shuffle(objects []runtime.Object) {
	type keyed struct {
		key    uint64
		object runtime.Object
	}

	items := make([]keyed, len(objects))

	for i := range objects {
		items[i] = keyed{key: s.random.Uint64(), object: objects[i]}
	}

	slices.SortFunc(items, func(a, b keyed) int {
		return cmp.Compare(a.key, b.key)
	})

	for i := range items {
		objects[i] = items[i].object
	}
}

func (s *Store) get(_ context.Context, _ client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	options := client.GetOptions{}
	options.ApplyOptions(opts)

	if !s.benchmark {
		s.lock.Lock()
		s.getOptions = append(s.getOptions, options)
		s.lock.Unlock()
	}

	for _, object := range s.objects {
		if reflect.TypeOf(object) != reflect.TypeOf(obj) || object.GetNamespace() != key.Namespace || object.GetName() != key.Name {
			continue
		}

		var source runtime.Object = object

		if !noCopy(options.UnsafeDisableDeepCopy) {
			source = object.DeepCopyObject()
		}

		reflect.ValueOf(obj).Elem().Set(reflect.ValueOf(source).Elem())

		return nil
	}

	return kerrors.NewNotFound(schema.GroupResource{Resource: reflect.TypeOf(obj).Elem().Name()}, key.Name)
}
