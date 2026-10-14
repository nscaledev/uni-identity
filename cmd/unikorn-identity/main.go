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
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/pflag"
	"go.opentelemetry.io/otel"

	"github.com/unikorn-cloud/core/pkg/client"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/server"
	servermetrics "github.com/unikorn-cloud/identity/pkg/server/metrics"
	"github.com/unikorn-cloud/identity/pkg/telemetry"

	"k8s.io/client-go/rest"

	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

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

	client, directclient, err := newKubernetesClients(ctx)

	if err != nil {
		logger.Error(err, "failed to create Kubernetes clients")

		return
	}

	server, err := s.GetServer(client, directclient)
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

	metricsServer, err := newMetricsServer(ctx, logger)
	if err != nil {
		logger.Error(err, "failed to setup metrics server")

		return
	}

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

		shutdownServers(ctx, server, metricsServer, logger)
	}()

	if err := metrics.Serve(server, listener); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return
		}

		logger.Error(err, "unexpected server error")

		return
	}
}

func newMetricsServer(ctx context.Context, logger logr.Logger) (*http.Server, error) {
	if err := telemetry.Configure(ctx, ctrlmetrics.Registry); err != nil {
		return nil, fmt.Errorf("configure Prometheus metrics: %w", err)
	}

	//nolint:gosec // Prometheus and the Collector scrape the pod network.
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		return nil, fmt.Errorf("bind metrics listener: %w", err)
	}

	server := &http.Server{
		Handler:           promhttp.HandlerFor(ctrlmetrics.Registry, promhttp.HandlerOpts{}),
		ReadHeaderTimeout: time.Second,
	}
	go serveMetrics(server, listener, logger)

	return server, nil
}

func shutdownServers(ctx context.Context, server, metricsServer *http.Server, logger logr.Logger) {
	if err := server.Shutdown(ctx); err != nil {
		logger.Error(err, "server shutdown error")
	}

	if err := metricsServer.Shutdown(ctx); err != nil {
		logger.Error(err, "metrics server shutdown error")
	}
}

func newKubernetesClients(ctx context.Context) (ctrlclient.Client, ctrlclient.Client, error) {
	kubernetesClient, err := client.New(ctx, unikornv1.AddToScheme)
	if err != nil {
		return nil, nil, err
	}

	clientConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, nil, err
	}

	directClient, err := ctrlclient.New(clientConfig, ctrlclient.Options{
		Scheme: kubernetesClient.Scheme(),
	})
	if err != nil {
		return nil, nil, err
	}

	return kubernetesClient, directClient, nil
}

func closeServerMetrics(metrics *servermetrics.Reporter, logger logr.Logger) {
	if err := metrics.Close(); err != nil {
		logger.Error(err, "failed to close server metrics")
	}
}

func serveMetrics(server *http.Server, listener net.Listener, logger logr.Logger) {
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error(err, "metrics server error")
	}
}

func main() {
	start()
}
