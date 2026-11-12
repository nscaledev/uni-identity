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

// Package cachetest gives benchmarks a reader that costs what the informer
// cache costs.  A fake client cannot stand in: it scans every object for any
// selector, so it hides what an index saves.
package cachetest

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/unikorn-cloud/identity/pkg/userdb"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	toolscache "k8s.io/client-go/tools/cache"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ErrNotObject is returned for a type that is not a client.Object.
var ErrNotObject = errors.New("not a client object")

// Reader answers List the way the controller-runtime cache reader does, over a
// client-go indexer, the store the cache is built on.  A namespace or a field
// selector is one index lookup. Any other selector walks every object of the
// kind and copies the ones that match.
type Reader struct {
	client.Reader

	store toolscache.Indexer
}

// objectKey keys a stored object by kind, so one store can hold every kind.
func objectKey(object any) (string, error) {
	typed, ok := object.(client.Object)
	if !ok {
		return "", ErrNotObject
	}

	return fmt.Sprintf("%T/%s/%s", object, typed.GetNamespace(), typed.GetName()), nil
}

func key(object any, field string) string {
	return fmt.Sprintf("%T/%s", object, field)
}

// NewReader returns a Reader holding objects, with the given indexes.
func NewReader(objects []client.Object, indexes ...userdb.Index) (*Reader, error) {
	indexers := toolscache.Indexers{
		// The cache holds one store for each kind, so its namespace index
		// holds one kind; key it by kind to match.
		toolscache.NamespaceIndex: func(object any) ([]string, error) {
			typed, ok := object.(client.Object)
			if !ok {
				return nil, ErrNotObject
			}

			return []string{key(object, typed.GetNamespace())}, nil
		},
	}

	for _, index := range indexes {
		indexers[key(index.Object, index.Field)] = func(object any) ([]string, error) {
			typed, ok := object.(client.Object)
			if !ok {
				return nil, ErrNotObject
			}

			return index.Func(typed), nil
		}
	}

	store := toolscache.NewIndexer(objectKey, indexers)

	for _, object := range objects {
		if err := store.Add(object); err != nil {
			return nil, err
		}
	}

	return &Reader{store: store}, nil
}

// Get implements client.Reader.
func (r *Reader) Get(_ context.Context, name client.ObjectKey, object client.Object, _ ...client.GetOption) error {
	found, exists, err := r.store.GetByKey(fmt.Sprintf("%T/%s/%s", object, name.Namespace, name.Name))
	if err != nil {
		return err
	}

	if !exists || reflect.TypeOf(found) != reflect.TypeOf(object) {
		return kerrors.NewNotFound(schema.GroupResource{}, name.Name)
	}

	typed, ok := found.(client.Object)
	if !ok {
		return ErrNotObject
	}

	reflect.ValueOf(object).Elem().Set(reflect.ValueOf(typed.DeepCopyObject()).Elem())

	return nil
}

// candidates returns the stored objects a List must consider: one index lookup
// for a field selector or a namespace, otherwise every object.
func (r *Reader) candidates(itemType client.Object, options *client.ListOptions) ([]any, error) {
	switch {
	case options.FieldSelector != nil:
		field, value, _ := strings.Cut(options.FieldSelector.String(), "=")

		return r.store.ByIndex(key(itemType, field), value)
	case options.Namespace != "":
		return r.store.ByIndex(toolscache.NamespaceIndex, key(itemType, options.Namespace))
	default:
		return r.store.List(), nil
	}
}

// List implements client.Reader.
func (r *Reader) List(_ context.Context, list client.ObjectList, opts ...client.ListOption) error {
	options := client.ListOptions{}
	options.ApplyOptions(opts)

	itemType, err := listItemType(list)
	if err != nil {
		return err
	}

	candidates, err := r.candidates(itemType, &options)
	if err != nil {
		return err
	}

	matches := []runtime.Object{}

	for _, candidate := range candidates {
		object, ok := candidate.(client.Object)
		if !ok || reflect.TypeOf(candidate) != reflect.TypeOf(itemType) {
			continue
		}

		if options.LabelSelector != nil && !options.LabelSelector.Matches(labels.Set(object.GetLabels())) {
			continue
		}

		matches = append(matches, object.DeepCopyObject())
	}

	return meta.SetList(list, matches)
}

// listItemType returns an empty item of the kind a list holds.
func listItemType(list client.ObjectList) (client.Object, error) {
	items, err := meta.GetItemsPtr(list)
	if err != nil {
		return nil, err
	}

	element := reflect.TypeOf(items).Elem().Elem()

	object, ok := reflect.New(element).Interface().(client.Object)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotObject, element)
	}

	return object, nil
}
