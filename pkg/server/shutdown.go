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

package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/unikorn-cloud/identity/pkg/readiness"
)

// HealthListenAddress serves the readiness probe. The Service does not expose
// it, so the ingress cannot route to it.
const HealthListenAddress = ":6081"

// lifecycle times how a replica leaves service. The chart's
// terminationGracePeriodSeconds must cover the delay, the drain and the
// final scrape.
type lifecycle struct {
	// delay is how long the server keeps serving after it reports not ready,
	// so endpoint removal reaches every node before connections are refused.
	delay time.Duration

	// drain bounds how long in-flight requests get to finish.
	drain time.Duration

	// scrape is how long metrics stay served after the drain, so a scrape
	// collects what the drain recorded. It exceeds the scrape interval.
	scrape time.Duration

	// sleep lets the shutdown sequence be observed without waiting in tests.
	sleep func(time.Duration)
}

const (
	shutdownDelay = 5 * time.Second
	shutdownDrain = 10 * time.Second
	// The platform PodMonitor uses the default 30s scrape interval.
	shutdownScrape = 35 * time.Second
)

// NewHealthServer serves the readiness probe on /readyz.
func NewHealthServer(ready *readiness.Checker) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("GET /readyz", ready)

	return &http.Server{
		Addr:              HealthListenAddress,
		Handler:           mux,
		ReadHeaderTimeout: time.Second,
	}
}

// Shutdowner is the part of http.Server that drains and stops it.
type Shutdowner interface {
	Shutdown(ctx context.Context) error
}

// Serve runs serve until stop closes, then takes the replica out of service
// with server's Shutdown. It returns once the drain has finished and metrics
// have been served for one more scrape, so the process does not exit while
// requests are in flight or before the drain's metrics are collected.
func Serve(serve func() error, server Shutdowner, ready *readiness.Checker, stopBackground, stopMetrics context.CancelFunc, stop <-chan struct{}) error {
	l := lifecycle{delay: shutdownDelay, drain: shutdownDrain, scrape: shutdownScrape}

	return l.serve(serve, server, ready, stopBackground, stopMetrics, stop)
}

func (l lifecycle) serve(serve func() error, server Shutdowner, ready *readiness.Checker, stopBackground, stopMetrics context.CancelFunc, stop <-chan struct{}) error {
	stopped := make(chan error, 1)
	served := make(chan struct{})

	defer close(served)

	go func() {
		select {
		case <-stop:
			stopped <- l.stop(ready, stopBackground, stopMetrics, server)
		case <-served:
		}
	}()

	// Serve returns ErrServerClosed as soon as Shutdown starts, before the
	// drain has finished.
	if err := serve(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return <-stopped
}

// stop takes the replica out of service, waits for endpoint removal to
// propagate, stops the background work, drains the server, then stops metrics
// after the final scrape.
func (l lifecycle) stop(ready *readiness.Checker, stopBackground, stopMetrics context.CancelFunc, server Shutdowner) error {
	ready.Stopping()

	l.wait(l.delay)

	stopBackground()

	ctx, cancel := context.WithTimeout(context.Background(), l.drain)
	defer cancel()

	err := server.Shutdown(ctx)

	l.wait(l.scrape)

	stopMetrics()

	return err
}

func (l lifecycle) wait(duration time.Duration) {
	if l.sleep != nil {
		l.sleep(duration)

		return
	}

	time.Sleep(duration)
}
