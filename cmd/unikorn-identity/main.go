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
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/pflag"
	"go.opentelemetry.io/otel"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/server"
	servermetrics "github.com/unikorn-cloud/identity/pkg/server/metrics"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"

	"sigs.k8s.io/controller-runtime/pkg/cache"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	kubernetesClientQPS   = 100
	kubernetesClientBurst = 200
)

var (
	errReadCacheStopped = errors.New("read cache stopped before synchronization")
	errReadCacheSync    = errors.New("read cache failed to synchronize")
)

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

	if err := s.SetupOpenTelemetry(ctx); err != nil {
		logger.Error(err, "failed to setup OpenTelemetry")

		return
	}

	client, readCache, err := newKubernetesClients(ctx, s.CoreOptions.Namespace)
	if err != nil {
		logger.Error(err, "failed to create Kubernetes clients")

		return
	}

	server, err := s.GetServer(client, readCache)
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

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		logger.Error(err, "failed to bind server listener")

		return
	}

	// Register a signal handler to trigger a graceful shutdown.
	stop := make(chan os.Signal, 1)

	signal.Notify(stop, syscall.SIGTERM)

	go func() {
		<-stop

		// Cancel anything hanging off the root context.
		cancel()

		// Shutdown the server, Kubernetes gives us 30 seconds before a SIGKILL.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			logger.Error(err, "server shutdown error")
		}
	}()

	if err := metrics.Serve(server, listener); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return
		}

		logger.Error(err, "unexpected server error")

		return
	}
}

func newKubernetesClients(ctx context.Context, namespace string) (ctrlclient.Client, ctrlclient.Reader, error) {
	clientConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, nil, err
	}

	configureKubernetesClient(clientConfig)

	scheme, err := coreclient.NewScheme(unikornv1.AddToScheme)
	if err != nil {
		return nil, nil, err
	}

	kubernetesClient, err := ctrlclient.New(clientConfig, ctrlclient.Options{
		Scheme: scheme,
	})
	if err != nil {
		return nil, nil, err
	}

	options := readCacheOptions(scheme, namespace)

	readCache, err := cache.New(clientConfig, options)
	if err != nil {
		return nil, nil, err
	}

	for object := range options.ByObject {
		if _, err := readCache.GetInformer(ctx, object); err != nil {
			return nil, nil, err
		}
	}

	if err := startAndSyncCache(ctx, readCache); err != nil {
		return nil, nil, err
	}

	return kubernetesClient, readCache, nil
}

// readCacheOptions limits the cache to the kinds that the server reads from
// it. Organizations live in the identity namespace. Quotas, Allocations and
// Projects are listed in full for the organization list includes, so they
// are cached in all namespaces.
func readCacheOptions(scheme *runtime.Scheme, namespace string) cache.Options {
	return cache.Options{
		Scheme:                      scheme,
		ReaderFailOnMissingInformer: true,
		ByObject: map[ctrlclient.Object]cache.ByObject{
			&unikornv1.Organization{}: {
				Namespaces: map[string]cache.Config{
					namespace: {},
				},
			},
			&unikornv1.Quota{}:      {},
			&unikornv1.Allocation{}: {},
			&unikornv1.Project{}:    {},
		},
	}
}

func startAndSyncCache(ctx context.Context, resourceCache cacheRunner) error {
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
		syncResult <- resourceCache.WaitForCacheSync(cacheCtx)
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

		return errReadCacheSync
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
