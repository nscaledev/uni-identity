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

package cerbos_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/authz/cerbos"
)

// TestNewEnforcesLoopbackEndpoint pins the loopback restriction: the PDP is
// an unauthenticated, plaintext, same-pod sidecar, so New must refuse to
// construct a client for any non-loopback host — otherwise a config typo
// would silently send authorization traffic across the network unprotected.
func TestNewEnforcesLoopbackEndpoint(t *testing.T) {
	t.Parallel()

	accepted := []string{
		"localhost:3593",
		"127.0.0.1:3593",
		// Anywhere in 127.0.0.0/8 is loopback.
		"127.0.0.2:3593",
		"[::1]:3593",
	}

	for _, endpoint := range accepted {
		client, err := cerbos.New(&cerbos.Options{Endpoint: endpoint, CheckTimeout: time.Second})
		require.NoError(t, err, "endpoint %q must be accepted", endpoint)
		require.NotNil(t, client)
	}

	rejected := []string{
		"cerbos.identity.svc.cluster.local:3593",
		"10.0.0.1:3593",
		"",
	}

	for _, endpoint := range rejected {
		client, err := cerbos.New(&cerbos.Options{Endpoint: endpoint, CheckTimeout: time.Second})
		require.ErrorIs(t, err, cerbos.ErrOptions, "endpoint %q must be rejected", endpoint)
		require.Nil(t, client)

		// Configuration errors are a static failure class, not the
		// runtime unavailable taxonomy the decision layer maps to deny.
		require.NotErrorIs(t, err, cerbos.ErrUnavailable)
	}
}

// TestNewRejectsNonPositiveCheckTimeout pins the timeout validation: a
// zero-value timeout would hand every call an already-expired context, so
// every check would be denied while the sidecar looks perfectly healthy.
func TestNewRejectsNonPositiveCheckTimeout(t *testing.T) {
	t.Parallel()

	for _, timeout := range []time.Duration{0, -time.Second} {
		client, err := cerbos.New(&cerbos.Options{Endpoint: "localhost:3593", CheckTimeout: timeout})
		require.ErrorIs(t, err, cerbos.ErrOptions, "timeout %v must be rejected", timeout)
		require.Nil(t, client)
		require.NotErrorIs(t, err, cerbos.ErrUnavailable)
	}
}
