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
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/readiness"
)

// recordingServer notes what had already happened when Shutdown was called.
type recordingServer struct {
	t          *testing.T
	ready      *readiness.Checker
	background context.Context //nolint:containedctx // the test observes the context's state.
	drained    bool
}

func (s *recordingServer) Shutdown(ctx context.Context) error {
	require.ErrorIs(s.t, s.ready.Check(ctx), readiness.ErrStopping, "readiness fails before the drain")
	require.ErrorIs(s.t, s.background.Err(), context.Canceled, "background work stops before the drain")

	_, bounded := ctx.Deadline()
	require.True(s.t, bounded, "the drain is bounded")

	s.drained = true

	return nil
}

func TestStopFailsReadinessThenStopsBackgroundThenDrains(t *testing.T) {
	t.Parallel()

	ready := readiness.New()
	background, stopBackground := context.WithCancel(t.Context())
	server := &recordingServer{t: t, ready: ready, background: background}
	l := lifecycle{delay: time.Millisecond, drain: time.Second}

	require.NoError(t, l.stop(ready, stopBackground, server))
	require.True(t, server.drained)
}

// TestServeReturnsAfterTheDrain checks that Serve waits for an in-flight
// request, not just for the listener to close.
func TestServeReturnsAfterTheDrain(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{})
	release := make(chan struct{})

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			close(entered)
			<-release
			w.WriteHeader(http.StatusNoContent)
		}),
		ReadHeaderTimeout: time.Second,
	}

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	stop := make(chan struct{})
	l := lifecycle{delay: time.Millisecond, drain: 5 * time.Second}

	served := make(chan error, 1)

	go func() {
		served <- l.serve(func() error { return server.Serve(listener) }, server, readiness.New(), func() {}, stop)
	}()

	responded := make(chan int, 1)

	go func() {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+listener.Addr().String(), nil)
		if err != nil {
			responded <- 0

			return
		}

		response, err := http.DefaultClient.Do(request)
		if err != nil {
			responded <- 0

			return
		}

		response.Body.Close()
		responded <- response.StatusCode
	}()

	<-entered
	close(stop)

	select {
	case <-served:
		require.Fail(t, "Serve returned while a request was in flight")
	case <-time.After(200 * time.Millisecond):
	}

	close(release)

	require.Equal(t, http.StatusNoContent, <-responded)
	require.NoError(t, <-served)
}

// TestShutdownFitsTheGracePeriod guards the chart's
// terminationGracePeriodSeconds of 30, which hack/check_chart_render.sh checks.
func TestShutdownFitsTheGracePeriod(t *testing.T) {
	t.Parallel()

	require.Less(t, shutdownDelay+shutdownDrain, 30*time.Second)
}
