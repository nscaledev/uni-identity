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

package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"

	"sigs.k8s.io/controller-runtime/pkg/cache"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type testCacheRunner struct {
	started chan struct{}
	stopped chan struct{}
}

func (r *testCacheRunner) Start(ctx context.Context) error {
	close(r.started)
	<-ctx.Done()
	close(r.stopped)

	return nil
}

func (r *testCacheRunner) WaitForCacheSync(context.Context) bool {
	<-r.started

	return true
}

// unsyncedRunner never syncs: it waits for the context, as the cache does when
// it cannot list a kind.
type unsyncedRunner struct{}

func (unsyncedRunner) Start(ctx context.Context) error {
	<-ctx.Done()

	return nil
}

func (unsyncedRunner) WaitForCacheSync(ctx context.Context) bool {
	<-ctx.Done()

	return false
}

type testInformer struct {
	cache.Informer
	synced bool
}

func (i testInformer) HasSynced() bool { return i.synced }

func TestStartAndSyncCacheTimesOutNamingTheKinds(t *testing.T) {
	t.Parallel()

	informers := map[string]cache.Informer{
		"*v1alpha1.Group": testInformer{synced: true},
		"*v1alpha1.Role":  testInformer{},
		"*v1alpha1.User":  testInformer{},
	}

	err := startAndSyncCache(t.Context(), unsyncedRunner{}, 10*time.Millisecond, informers)
	require.ErrorIs(t, err, errReadCacheSync)
	require.ErrorContains(t, err, "*v1alpha1.Role, *v1alpha1.User")
	require.NotContains(t, err.Error(), "Group")
}

func TestConfigureKubernetesClient(t *testing.T) {
	t.Parallel()

	config := &rest.Config{}

	configureKubernetesClient(config)

	require.InDelta(t, kubernetesClientQPS, config.QPS, 0)
	require.Equal(t, kubernetesClientBurst, config.Burst)
}

func TestStartAndSyncCacheKeepsRunningCache(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	runner := &testCacheRunner{started: make(chan struct{}), stopped: make(chan struct{})}

	require.NoError(t, startAndSyncCache(ctx, runner, time.Minute, nil))

	select {
	case <-runner.stopped:
		t.Fatal("cache stopped after synchronization")
	default:
	}

	cancel()
	<-runner.stopped
}

// The cache holds the kinds the per-request path and the organization list
// read: identity-namespace kinds there only, the rest across all namespaces.
// It must watch nothing else, and never Secrets.
func TestReadCacheOptionsWatchOnlyTheKindsReadFromTheCache(t *testing.T) {
	t.Parallel()

	options := readCacheOptions(runtime.NewScheme(), "identity")

	require.True(t, options.ReaderFailOnMissingInformer)
	require.Empty(t, options.DefaultNamespaces)
	require.NotNil(t, options.DefaultTransform)
	require.NotNil(t, options.DefaultWatchErrorHandler)

	namespaces := map[string]map[string]cache.Config{}

	for object, byObject := range options.ByObject {
		namespaces[fmt.Sprintf("%T", object)] = byObject.Namespaces
	}

	require.Equal(t, map[string]map[string]cache.Config{
		fmt.Sprintf("%T", &unikornv1.Organization{}):     {"identity": {}},
		fmt.Sprintf("%T", &unikornv1.User{}):             {"identity": {}},
		fmt.Sprintf("%T", &unikornv1.Role{}):             {"identity": {}},
		fmt.Sprintf("%T", &unikornv1.SigningKey{}):       {"identity": {}},
		fmt.Sprintf("%T", &unikornv1.ServiceAccount{}):   nil,
		fmt.Sprintf("%T", &unikornv1.OrganizationUser{}): nil,
		fmt.Sprintf("%T", &unikornv1.OAuth2Provider{}):   nil,
		fmt.Sprintf("%T", &unikornv1.Group{}):            nil,
		fmt.Sprintf("%T", &unikornv1.Quota{}):            nil,
		fmt.Sprintf("%T", &unikornv1.Allocation{}):       nil,
		fmt.Sprintf("%T", &unikornv1.Project{}):          nil,
	}, namespaces)
}

type testRegistry struct {
	informers []ctrlclient.Object
	indexes   []string
}

func (r *testRegistry) GetInformer(_ context.Context, obj ctrlclient.Object, _ ...cache.InformerGetOption) (cache.Informer, error) {
	r.informers = append(r.informers, obj)

	return nil, nil //nolint:nilnil // the test only counts informers
}

func (r *testRegistry) IndexField(_ context.Context, _ ctrlclient.Object, field string, _ ctrlclient.IndexerFunc) error {
	r.indexes = append(r.indexes, field)

	return nil
}

// Without its indexes, every user and membership lookup fails in production.
func TestRegisterReadCacheRegistersInformersAndUserIndexes(t *testing.T) {
	t.Parallel()

	registry := &testRegistry{}
	options := readCacheOptions(runtime.NewScheme(), "identity")

	informers, err := registerReadCache(t.Context(), registry, options)
	require.NoError(t, err)
	require.Len(t, informers, len(options.ByObject))
	require.Len(t, registry.informers, len(options.ByObject))
	require.Equal(t, []string{userdb.SubjectIndexField, userdb.SubjectLabelIndexField, userdb.MembershipUserIndexField}, registry.indexes)
}
