//go:build integration

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

package region_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"

	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var errReadCacheSync = errors.New("read cache did not sync")

// cachedKind is a kind the server serves from its informer cache, and the
// namespace the cache is limited to ("" for all).
type cachedKind struct {
	object    client.Object
	list      client.ObjectList
	namespace string
}

// cachedKinds mirrors cmd/unikorn-identity readCacheOptions, which is package
// main and cannot be imported. Keep the two in step: ReaderFailOnMissingInformer
// fails a test that reads a kind that is missing here.
func cachedKinds() []cachedKind {
	return []cachedKind{
		{&unikornv1.Organization{}, &unikornv1.OrganizationList{}, TestNamespace},
		{&unikornv1.User{}, &unikornv1.UserList{}, TestNamespace},
		{&unikornv1.Role{}, &unikornv1.RoleList{}, TestNamespace},
		{&unikornv1.SigningKey{}, &unikornv1.SigningKeyList{}, TestNamespace},
		{&unikornv1.ServiceAccount{}, &unikornv1.ServiceAccountList{}, ""},
		{&unikornv1.OrganizationUser{}, &unikornv1.OrganizationUserList{}, ""},
		{&unikornv1.OAuth2Provider{}, &unikornv1.OAuth2ProviderList{}, ""},
		{&unikornv1.Group{}, &unikornv1.GroupList{}, ""},
		{&unikornv1.Quota{}, &unikornv1.QuotaList{}, ""},
		{&unikornv1.Allocation{}, &unikornv1.AllocationList{}, ""},
		{&unikornv1.Project{}, &unikornv1.ProjectList{}, ""},
	}
}

// newReadCache starts an informer cache of the kinds the server caches, with the
// user database's indexes registered before it starts, as production does. It
// stops with ctx.
func newReadCache(ctx context.Context, cfg *rest.Config, scheme *runtime.Scheme) (cache.Cache, error) {
	byObject := map[client.Object]cache.ByObject{}

	for _, kind := range cachedKinds() {
		config := cache.ByObject{}

		if kind.namespace != "" {
			config.Namespaces = map[string]cache.Config{kind.namespace: {}}
		}

		byObject[kind.object] = config
	}

	readCache, err := cache.New(cfg, cache.Options{
		Scheme:                      scheme,
		ReaderFailOnMissingInformer: true,
		ByObject:                    byObject,
	})
	if err != nil {
		return nil, err
	}

	for _, kind := range cachedKinds() {
		if _, err := readCache.GetInformer(ctx, kind.object); err != nil {
			return nil, err
		}
	}

	if err := userdb.IndexUsers(ctx, readCache); err != nil {
		return nil, err
	}

	go func() {
		_ = readCache.Start(ctx)
	}()

	if !readCache.WaitForCacheSync(ctx) {
		return nil, errReadCacheSync
	}

	return readCache, nil
}

// versions returns the resource version of every object a list returns.
func versions(ctx context.Context, reader client.Reader, kind cachedKind, namespace string) (map[client.ObjectKey]string, error) {
	list, ok := kind.list.DeepCopyObject().(client.ObjectList)
	if !ok {
		return nil, fmt.Errorf("%w: %T", errReadCacheSync, kind.list)
	}

	if err := reader.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil, err
	}

	items, err := meta.ExtractList(list)
	if err != nil {
		return nil, err
	}

	result := make(map[client.ObjectKey]string, len(items))

	for _, item := range items {
		object, ok := item.(client.Object)
		if !ok {
			return nil, fmt.Errorf("%w: %T", errReadCacheSync, item)
		}

		result[client.ObjectKeyFromObject(object)] = object.GetResourceVersion()
	}

	return result, nil
}

// waitForReadCache blocks until the cache holds every object the live client
// returns, at the same resource version, and no other. The cache lags writes,
// so a state that creates, changes or removes an object a request will read
// MUST wait here before it returns.
func waitForReadCache(ctx context.Context, live, cached client.Reader) error {
	return wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		for _, kind := range cachedKinds() {
			want, err := versions(ctx, live, kind, kind.namespace)
			if err != nil {
				return false, err
			}

			got, err := versions(ctx, cached, kind, kind.namespace)
			if err != nil {
				return false, err
			}

			if len(want) != len(got) {
				return false, nil
			}

			for key, version := range want {
				if got[key] != version {
					return false, nil
				}
			}
		}

		return true, nil
	})
}
