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
	"net"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/readiness"
	"github.com/unikorn-cloud/identity/pkg/server"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"

	"sigs.k8s.io/controller-runtime/pkg/cache"
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

	require.NoError(t, startAndSyncCache(ctx, runner))

	select {
	case <-runner.stopped:
		t.Fatal("cache stopped after synchronization")
	default:
	}

	cancel()
	<-runner.stopped
}

// The server reads Organizations only from the identity namespace, and lists
// Quotas, Allocations and Projects across all namespaces. The cache must watch
// nothing else.
func TestReadCacheOptionsWatchOnlyTheKindsReadFromTheCache(t *testing.T) {
	t.Parallel()

	options := readCacheOptions(runtime.NewScheme(), "identity")

	require.True(t, options.ReaderFailOnMissingInformer)
	require.Empty(t, options.DefaultNamespaces)

	namespaces := map[string]map[string]cache.Config{}

	for object, byObject := range options.ByObject {
		namespaces[fmt.Sprintf("%T", object)] = byObject.Namespaces
	}

	require.Equal(t, map[string]map[string]cache.Config{
		fmt.Sprintf("%T", &unikornv1.Organization{}): {"identity": {}},
		fmt.Sprintf("%T", &unikornv1.Quota{}):        nil,
		fmt.Sprintf("%T", &unikornv1.Allocation{}):   nil,
		fmt.Sprintf("%T", &unikornv1.Project{}):      nil,
	}, namespaces)
}

// TestServeUntilStoppedStopsOnASPIFFEListenerError checks that a failure of the
// SPIFFE listener stops the API server, and that the error wraps
// server.ErrListenerStopped, so that the process exits with code 1.
func TestServeUntilStoppedStopsOnASPIFFEListenerError(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// The server has no TLS configuration, so ServeTLS on the SPIFFE address fails.
	apiServer := &http.Server{ReadHeaderTimeout: time.Second}
	serve := func() error { return apiServer.Serve(listener) }

	served := make(chan error, 1)

	go func() {
		served <- serveUntilStopped(logr.Discard(), apiServer, serve, "127.0.0.1:0", readiness.New(), func() {})
	}()

	select {
	case err := <-served:
		require.ErrorIs(t, err, server.ErrListenerStopped)
	case <-time.After(30 * time.Second):
		require.Fail(t, "a SPIFFE listener error did not stop the API server")
	}
}

// TestServeUntilStoppedReturnsNilAfterSIGTERM checks that the process exits with
// code 0 after SIGTERM, also when a request does not finish in the drain time.
// The shutdown delay and the drain time of server.Serve are fixed, so the test
// takes about 20 seconds.
//
//nolint:paralleltest // SIGTERM stops every server in the test process.
func TestServeUntilStoppedReturnsNilAfterSIGTERM(t *testing.T) {
	tests := []struct {
		name     string
		inFlight bool
	}{
		{
			name: "with no request in flight",
		},
		{
			name:     "with a request that is longer than the drain time",
			inFlight: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			require.NoError(t, err)

			entered := make(chan struct{})
			release := make(chan struct{})

			defer close(release)

			apiServer := &http.Server{
				Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					close(entered)
					<-release
				}),
				ReadHeaderTimeout: time.Second,
			}

			serving := make(chan struct{})

			serve := func() error {
				close(serving)

				return apiServer.Serve(listener)
			}

			served := make(chan error, 1)

			go func() {
				served <- serveUntilStopped(logr.Discard(), apiServer, serve, "", readiness.New(), func() {})
			}()

			select {
			case <-serving:
			case <-time.After(10 * time.Second):
				require.Fail(t, "the API server did not start to serve")
			}

			if test.inFlight {
				request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+listener.Addr().String(), nil)
				require.NoError(t, err)

				go func() {
					if response, err := http.DefaultClient.Do(request); err == nil {
						_ = response.Body.Close()
					}
				}()

				select {
				case <-entered:
				case <-time.After(10 * time.Second):
					require.Fail(t, "the request did not reach the handler")
				}
			}

			require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))

			select {
			case err := <-served:
				require.NoError(t, err)
			case <-time.After(30 * time.Second):
				require.Fail(t, "SIGTERM did not stop the API server")
			}
		})
	}
}
