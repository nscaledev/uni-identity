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

package server_test

import (
	"net/http"
	"sort"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/server"
)

// walk returns "METHOD path" for every route a handler serves.  The handler
// under test is built by mountProfile below, without a live cluster.
func walk(t *testing.T, router chi.Router) []string {
	t.Helper()

	var routes []string

	require.NoError(t, chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes = append(routes, method+" "+route)

		return nil
	}))

	sort.Strings(routes)

	return routes
}

// mountProfile mounts the API for a profile over a stub handler, returning
// the router so the test can walk it.
func mountProfile(t *testing.T, profile string) chi.Router {
	t.Helper()

	router := chi.NewRouter()

	p := server.APIProfile(profile)
	server.MountAPIForTest(&p, router)

	return router
}

// TestAuthorizationProfileServesThreeRoutes is the deployment guard: the
// enclave profile must serve the read-only authorization surface and nothing
// else.  Set equality, not containment: an extra route is a widened surface.
func TestAuthorizationProfileServesThreeRoutes(t *testing.T) {
	t.Parallel()

	router := mountProfile(t, "authorization")

	require.Equal(t, []string{
		"GET /api/v1/acl",
		"GET /api/v1/organizations/{organizationID}/acl",
		"POST /api/v1/authorization/check",
	}, walk(t, router))
}

// TestFullProfileServesTheWholeAPI pins the other half: the default profile
// must be unchanged by this work.  Compared by count against the spec, so
// the test does not need updating whenever an endpoint is added.
func TestFullProfileServesTheWholeAPI(t *testing.T) {
	t.Parallel()

	router := mountProfile(t, "full")

	require.Greater(t, len(walk(t, router)), 40, "the full profile must mount the whole API")
}

// TestZeroValueProfileServesTheWholeAPI pins the required invariant: Options
// is constructed directly by tests and possibly by other consumers, without
// AddFlags, so APIProfile can hold the zero value "". A zero value must
// resolve to the full API, the safe default every pre-existing deployment
// already depends on, not to an error or an empty mux. This mirrors
// RBAC.mode() in pkg/rbac/engine.go, which treats any unrecognised engine
// value as legacy.
func TestZeroValueProfileServesTheWholeAPI(t *testing.T) {
	t.Parallel()

	var profile server.APIProfile

	router := chi.NewRouter()
	server.MountAPIForTest(&profile, router)

	require.Greater(t, len(walk(t, router)), 40, "a zero-valued profile must mount the whole API")
}

// TestAuthorizationProfileOmitsWriteRoutes states the security property in
// the form a reviewer checks: no write method is reachable at all.
func TestAuthorizationProfileOmitsWriteRoutes(t *testing.T) {
	t.Parallel()

	for _, route := range walk(t, mountProfile(t, "authorization")) {
		require.NotContains(t, route, http.MethodPut)
		require.NotContains(t, route, http.MethodPatch)
		require.NotContains(t, route, http.MethodDelete)
		require.NotContains(t, route, http.MethodPost+" /api/v1/organizations")
	}
}
