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
	"testing"

	"github.com/stretchr/testify/require"

	"k8s.io/client-go/rest"
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
