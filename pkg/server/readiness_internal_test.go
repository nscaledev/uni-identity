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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// probe drives the readiness handler once and reports the status code.
func probe(t *testing.T, directory string) int {
	t.Helper()

	response := httptest.NewRecorder()
	policyProjectionReadiness(directory).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	return response.Code
}

// writeMarker projects a publication marker, as the policy controller would.
func writeMarker(t *testing.T, directory, body string) {
	t.Helper()

	require.NoError(t, os.WriteFile(filepath.Join(directory, storeVersionFile), []byte(body), 0o600))
}

// TestPolicyProjectionReadinessAdmitsAPublishedStore pins the reason this gate
// keys on the marker rather than on the presence of policy files. Cerbos is
// healthy with an empty policy directory and answers deny for everything, so a
// pod must stay out of the Service until the controller has published once.
func TestPolicyProjectionReadinessAdmitsAPublishedStore(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()

	require.Equal(t, http.StatusServiceUnavailable, probe(t, directory),
		"a projection with no marker has never been published to")

	writeMarker(t, directory, `{"schema":1,"state":"valid"}`+"\n")
	require.NoError(t, os.WriteFile(filepath.Join(directory, "resource.yaml"), []byte("policy"), 0o600))

	require.Equal(t, http.StatusOK, probe(t, directory), "a published store is ready")
}

// TestPolicyProjectionReadinessAdmitsAWithdrawnStore is the whole reason the
// marker exists. A withdrawal publishes no policy document, so a gate that
// counted policy files would hold every pod that STARTS during a withdrawal
// out of the Service for as long as it lasted: one malformed Role would then
// cost capacity on the next eviction, drain or rollout. Deny-all is a
// deliberate published state, and a pod serving it is serving correctly.
func TestPolicyProjectionReadinessAdmitsAWithdrawnStore(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	writeMarker(t, directory, `{"schema":1,"state":"withdrawn"}`+"\n")

	require.Equal(t, http.StatusOK, probe(t, directory),
		"a deliberately withdrawn store is ready: the pod serves deny-all, which is the published state")
}

// TestPolicyProjectionReadinessRejectsWhatItCannotTrust covers the states the
// pod must not act on. Each answers 503 rather than guessing, and the list is
// deliberately short: readiness is fleet-wide, so every field validated here
// is a field a publisher bug could use to take every replica out of service at
// once.
func TestPolicyProjectionReadinessRejectsWhatItCannotTrust(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"NotJSON":       "not json at all",
		"UnknownSchema": `{"schema":2,"state":"valid"}`,
		"MissingSchema": `{"state":"valid"}`,
		"UnknownState":  `{"schema":1,"state":"probably-fine"}`,
		"MissingState":  `{"schema":1}`,
		"EmptyMarker":   "",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			directory := t.TempDir()
			writeMarker(t, directory, body)

			require.Equal(t, http.StatusServiceUnavailable, probe(t, directory))
		})
	}
}

// TestPolicyProjectionReadinessRejectsUnconfiguredProjection keeps the flag
// itself fail-closed: a profile that should gate on a projection but was given
// no directory must not report ready.
func TestPolicyProjectionReadinessRejectsUnconfiguredProjection(t *testing.T) {
	t.Parallel()

	require.Equal(t, http.StatusServiceUnavailable, probe(t, ""))
}

// TestPolicyProjectionReadinessBoundsTheRead stops a wrong marker from costing
// the pod its memory. The file comes from a controller, not a user, but this
// runs on every kubelet probe.
func TestPolicyProjectionReadinessBoundsTheRead(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	writeMarker(t, directory, `{"schema":1,"state":"valid","pad":"`+string(make([]byte, maxStoreVersionBytes*2))+`"}`)

	require.Equal(t, http.StatusServiceUnavailable, probe(t, directory),
		"a marker larger than the bound is truncated, so it cannot parse, so it is not trusted")
}
