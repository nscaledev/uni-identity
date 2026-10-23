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

package server

import (
	"context"
	"time"

	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/identity/pkg/readiness"
)

// ShutdownOptions control how a replica leaves service.
type ShutdownOptions struct {
	// Delay is how long the server keeps serving after it reports not ready,
	// so endpoint removal reaches every node before connections are refused.
	Delay time.Duration

	// Drain bounds how long in-flight requests get to finish.
	Drain time.Duration
}

func (o *ShutdownOptions) AddFlags(f *pflag.FlagSet) {
	f.DurationVar(&o.Delay, "shutdown-delay", 5*time.Second, "How long to keep serving after reporting not ready, so endpoint removal propagates.")
	f.DurationVar(&o.Drain, "shutdown-drain", 10*time.Second, "How long in-flight requests get to finish on shutdown.")
}

// Shutdowner is the part of http.Server that drains and stops it.
type Shutdowner interface {
	Shutdown(ctx context.Context) error
}

// Stop takes the replica out of service, waits for endpoint removal to
// propagate, stops the background work, which releases the JOSE lease, then
// drains the listener. The pod's termination grace period must cover the delay
// and the drain.
func (o *ShutdownOptions) Stop(ready *readiness.Checker, stopBackground context.CancelFunc, server Shutdowner) error {
	ready.Stopping()

	time.Sleep(o.Delay)

	stopBackground()

	ctx, cancel := context.WithTimeout(context.Background(), o.Drain)
	defer cancel()

	return server.Shutdown(ctx)
}
