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

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/pflag"
	"go.opentelemetry.io/otel"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coreoptions "github.com/unikorn-cloud/core/pkg/options"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/readiness"
	"github.com/unikorn-cloud/identity/pkg/server"
	servermetrics "github.com/unikorn-cloud/identity/pkg/server/metrics"
	"github.com/unikorn-cloud/identity/pkg/userdb"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"

	"sigs.k8s.io/controller-runtime/pkg/cache"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	kubernetesClientQPS   = 100
	kubernetesClientBurst = 200
	watchFailureGrace     = 30 * time.Second
)

var (
	errReadCacheStopped = errors.New("read cache stopped before synchronization")
	errReadCacheSync    = errors.New("read cache failed to synchronize")
)

// cacheSyncTimeout bounds the startup sync. A cache that cannot list a kind
// (for example a missing list permission) would otherwise wait for ever.
const cacheSyncTimeout = 5 * time.Minute

type cacheRunner interface {
	Start(ctx context.Context) error
	WaitForCacheSync(ctx context.Context) bool
}

// start is the entry point to server.
func start() {
	s := &server.Server{}
	s.AddFlags(pflag.CommandLine)

	pflag.Parse()

	// Get logging going first, log sinks will expect JSON formatted output for everything.
	s.SetupLogging()

	logger := log.Log.WithName(constants.Application)

	// Hello World!
	logger.Info("service starting", "application", constants.Application, "version", constants.Version, "revision", constants.Revision)

	// Create a root context for things to hang off of.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := setupTelemetry(ctx, &s.CoreOptions); err != nil {
		logger.Error(err, "failed to setup telemetry")

		return
	}

	client, readCache, cacheReady, err := newKubernetesClients(ctx, s.CoreOptions.Namespace)
	if err != nil {
		logger.Error(err, "failed to create Kubernetes clients")

		return
	}

	ready := readiness.New(cacheReady)

	apiServer, err := s.GetServer(ctx, client, readCache, ready)
	if err != nil {
		logger.Error(err, "failed to setup Handler")

		return
	}

	metrics, err := servermetrics.New(otel.Meter(constants.Application), constants.ServiceDescriptor())
	if err != nil {
		logger.Error(err, "failed to setup server metrics")

		return
	}
	defer closeServerMetrics(metrics, logger)

	// Metrics outlive the root context, so the drain is scraped too.
	metricsCtx, stopMetrics := context.WithCancel(context.Background())
	defer stopMetrics()

	go func() {
		if err := s.CoreOptions.ServeMetrics(metricsCtx, ":8080"); err != nil {
			logger.Error(err, "metrics server error")
		}
	}()

	listener, err := net.Listen("tcp", apiServer.Addr)
	if err != nil {
		logger.Error(err, "failed to bind server listener")

		return
	}

	healthServer := server.NewHealthServer(ready)

	healthListener, err := net.Listen("tcp", healthServer.Addr)
	if err != nil {
		logger.Error(err, "failed to bind health listener")

		return
	}

	// The health server answers until the process exits, so the probe
	// keeps failing while the API server drains.
	go func() {
		if err := healthServer.Serve(healthListener); err != nil {
			logger.Error(err, "health server error")
		}
	}()

	sigterm, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stopSignals()

	serve := func() error { return metrics.Serve(apiServer, listener) }

	if err := server.Serve(serve, apiServer, ready, cancel, stopMetrics, sigterm.Done()); err != nil {
		logger.Error(err, "server error")
	}
}

// setupTelemetry runs before GetServer creates any instruments, because they are
// bound to the meter provider current when they are created.
func setupTelemetry(ctx context.Context, o *coreoptions.CoreOptions) error {
	if err := o.SetupTracing(ctx, constants.Service); err != nil {
		return fmt.Errorf("setup tracing: %w", err)
	}

	if err := o.SetupMetrics(constants.Service); err != nil {
		return fmt.Errorf("setup metrics: %w", err)
	}

	return nil
}

// newKubernetesClients returns the live client, which writes and serves the
// reads that decide a write, and the synced informer cache, which serves every
// other read, with its readiness condition.
func newKubernetesClients(ctx context.Context, namespace string) (ctrlclient.Client, ctrlclient.Reader, readiness.Condition, error) {
	clientConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, nil, nil, err
	}

	configureKubernetesClient(clientConfig)

	scheme, err := coreclient.NewScheme(unikornv1.AddToScheme)
	if err != nil {
		return nil, nil, nil, err
	}

	kubernetesClient, err := ctrlclient.New(clientConfig, ctrlclient.Options{
		Scheme: scheme,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	watches := readiness.NewWatches(watchFailureGrace)
	options := readCacheOptions(scheme, namespace, watches)

	readCache, err := cache.New(clientConfig, options)
	if err != nil {
		return nil, nil, nil, err
	}

	informers, err := registerReadCache(ctx, readCache, options)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := startAndSyncCache(ctx, readCache, cacheSyncTimeout, informers); err != nil {
		return nil, nil, nil, err
	}

	return kubernetesClient, readCache, watches.Check, nil
}

// informerRegistry is the part of the cache that must be set up before it
// starts.
type informerRegistry interface {
	GetInformer(ctx context.Context, obj ctrlclient.Object, opts ...cache.InformerGetOption) (cache.Informer, error)
	ctrlclient.FieldIndexer
}

// registerReadCache creates an informer for every kind in options and
// registers the indexes the readers use. It MUST run before the cache starts:
// the user database fails every user and membership lookup without its indexes.
// It returns the informers by kind, for the startup sync report.
func registerReadCache(ctx context.Context, registry informerRegistry, options cache.Options) (map[string]cache.Informer, error) {
	informers := make(map[string]cache.Informer, len(options.ByObject))

	for object := range options.ByObject {
		informer, err := registry.GetInformer(ctx, object)
		if err != nil {
			return nil, err
		}

		informers[fmt.Sprintf("%T", object)] = informer
	}

	if err := userdb.IndexUsers(ctx, registry); err != nil {
		return nil, err
	}

	return informers, nil
}

// readCacheOptions limits the cache to the kinds that the server reads from
// it: every kind the per-request token check, ACL build and passport exchange
// read, plus the organization list includes. Kinds that live only in the
// identity namespace are cached there. OAuth2Providers are cached in all
// namespaces, but cached reads list the identity namespace only; reads in an
// organization's namespace use the live client. Keep this list in step with the server ClusterRole,
// which must grant watch on each kind.
func readCacheOptions(scheme *runtime.Scheme, namespace string, watches *readiness.Watches) cache.Options {
	identityNamespace := func() cache.ByObject {
		return cache.ByObject{Namespaces: map[string]cache.Config{namespace: {}}}
	}

	return cache.Options{
		Scheme:                      scheme,
		ReaderFailOnMissingInformer: true,
		DefaultTransform:            cache.TransformStripManagedFields(),
		DefaultWatchErrorHandler:    logWatchError,
		NewInformer:                 readCacheInformer(watches),
		ByObject: map[ctrlclient.Object]cache.ByObject{
			&unikornv1.Organization{}:     identityNamespace(),
			&unikornv1.User{}:             identityNamespace(),
			&unikornv1.Role{}:             identityNamespace(),
			&unikornv1.SigningKey{}:       identityNamespace(),
			&unikornv1.ServiceAccount{}:   {},
			&unikornv1.OrganizationUser{}: {},
			&unikornv1.OAuth2Provider{}:   {},
			&unikornv1.Group{}:            {},
			&unikornv1.Quota{}:            {},
			&unikornv1.Allocation{}:       {},
			&unikornv1.Project{}:          {},
		},
	}
}

// Quota and allocation snapshots supply response summaries; enforcement reads live.
func readCacheInformer(watches *readiness.Watches) func(toolscache.ListerWatcher, runtime.Object, time.Duration, toolscache.Indexers) toolscache.SharedIndexInformer {
	return func(lw toolscache.ListerWatcher, object runtime.Object, resync time.Duration, indexes toolscache.Indexers) toolscache.SharedIndexInformer {
		switch object.(type) {
		case *unikornv1.Quota, *unikornv1.Allocation:
			return toolscache.NewSharedIndexInformer(lw, object, resync, indexes)
		default:
			return watches.NewInformer(lw, object, resync, indexes)
		}
	}
}

// logWatchError logs a failed watch on the read cache. The reflector retries
// by itself, and the cache serves its last state until it recovers. A watch
// that closed normally, closed with an unexpected EOF or expired is routine, so
// it is not logged. This matches client-go's DefaultWatchErrorHandler, which
// compares EOF by identity ("case err == io.EOF:").
func logWatchError(_ context.Context, r *toolscache.Reflector, err error) {
	if err == io.EOF || err == io.ErrUnexpectedEOF || kerrors.IsResourceExpired(err) || kerrors.IsGone(err) { //nolint:errorlint,err113 // client-go compares by identity
		return
	}

	log.Log.WithName("read-cache").Error(err, "watch failed", "type", r.TypeDescription())
}

// startAndSyncCache starts the cache and waits for every informer to sync. It
// gives up after timeout, naming the kinds that had not synced.
func startAndSyncCache(ctx context.Context, resourceCache cacheRunner, timeout time.Duration, informers map[string]cache.Informer) error {
	cacheCtx, cancel := context.WithCancel(ctx)
	cancelOnError := true

	defer func() {
		if cancelOnError {
			cancel()
		}
	}()

	startResult := make(chan error, 1)
	syncResult := make(chan bool, 1)

	go func() {
		startResult <- resourceCache.Start(cacheCtx)
	}()
	go func() {
		syncCtx, syncCancel := context.WithTimeout(cacheCtx, timeout)
		defer syncCancel()

		syncResult <- resourceCache.WaitForCacheSync(syncCtx)
	}()

	select {
	case err := <-startResult:
		if err != nil {
			return err
		}

		return errReadCacheStopped
	case synced := <-syncResult:
		if synced {
			cancelOnError = false

			return nil
		}

		return fmt.Errorf("%w: kinds not synced after %v: %s", errReadCacheSync, timeout, unsyncedKinds(informers))
	case <-ctx.Done():
		return ctx.Err()
	}
}

func configureKubernetesClient(config *rest.Config) {
	config.QPS = kubernetesClientQPS
	config.Burst = kubernetesClientBurst
}

func closeServerMetrics(metrics *servermetrics.Reporter, logger logr.Logger) {
	if err := metrics.Close(); err != nil {
		logger.Error(err, "failed to close server metrics")
	}
}

func main() {
	start()
}

// unsyncedKinds names the kinds whose informers have not synced, sorted.
func unsyncedKinds(informers map[string]cache.Informer) string {
	kinds := []string{}

	for kind, informer := range informers {
		if !informer.HasSynced() {
			kinds = append(kinds, kind)
		}
	}

	slices.Sort(kinds)

	return strings.Join(kinds, ", ")
}
