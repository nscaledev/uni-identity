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
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/client"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/migration"
	"github.com/unikorn-cloud/identity/pkg/server"

	"k8s.io/client-go/rest"

	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
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

	client, err := client.New(ctx, unikornv1.AddToScheme)
	if err != nil {
		logger.Error(err, "failed to create client")

		return
	}

	clientconfig, err := rest.InClusterConfig()
	if err != nil {
		logger.Error(err, "failed to get client config")

		return
	}

	directclient, err := ctrlclient.New(clientconfig, ctrlclient.Options{
		Scheme: client.Scheme(),
	})
	if err != nil {
		logger.Error(err, "failed to create direct Kubernetes client")

		return
	}

	// Run one-time migration to convert groups from UserIDs to Subjects.
	// This must happen before the server starts to ensure the new authorization
	// code can find users by subject.
	logger.Info("running group migration")

	if err := migration.MigrateGroupsToSubjects(ctx, directclient, s.CoreOptions.Namespace, s.HandlerOptions.Issuer); err != nil {
		logger.Error(err, "group migration failed - server will not start")

		return
	}

	logger.Info("group migration completed successfully")

	server, err := s.GetServer(client, directclient)
	if err != nil {
		logger.Error(err, "failed to setup Handler")

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

	if err := server.ListenAndServe(); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return
		}

		logger.Error(err, "unexpected server error")

		return
	}
}

func main() {
	start()
}
