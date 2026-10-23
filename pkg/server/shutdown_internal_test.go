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
	options := &ShutdownOptions{Delay: time.Millisecond, Drain: time.Second}

	require.NoError(t, options.Stop(ready, stopBackground, server))
	require.True(t, server.drained)
}
