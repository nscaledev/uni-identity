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

//nolint:revive
package enclave_test

import (
	"net/http"
	"sort"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/openapi/enclave"
)

// enclaveTag is the spec tag that selects the authorization profile's
// surface.  It is a security-relevant switch, not documentation grouping:
// adding it to an operation widens what an enclave serves, which is why this
// test derives the expected route set from the spec instead of a literal.
const enclaveTag = "EnclaveAuthorization"

// stub satisfies the subset ServerInterface.  It never runs: the test only
// inspects the routes the generated code registers.
type stub struct{}

func (stub) PostApiV1AuthorizationCheck(http.ResponseWriter, *http.Request) {}
func (stub) GetApiV1Acl(http.ResponseWriter, *http.Request)                 {}
func (stub) GetApiV1OrganizationsOrganizationIDAcl(http.ResponseWriter, *http.Request, enclave.OrganizationIDParameter) {
}

// taggedRoutes reads the EMBEDDED spec and returns "METHOD path" for every
// operation carrying the enclave tag.  Reading the embedded spec is
// deliberate: it means a stale pkg/openapi/schema.go fails this test too.
func taggedRoutes(t *testing.T) []string {
	t.Helper()

	spec, err := openapi.GetSwagger()
	require.NoError(t, err)

	var routes []string

	for path, item := range spec.Paths.Map() {
		for method, operation := range item.Operations() {
			for _, tag := range operation.Tags {
				if tag == enclaveTag {
					routes = append(routes, method+" "+path)
				}
			}
		}
	}

	sort.Strings(routes)

	return routes
}

// mountedRoutes walks the generated subset router and returns the routes it
// actually serves, in the same "METHOD path" form.
func mountedRoutes(t *testing.T) []string {
	t.Helper()

	router := chi.NewRouter()
	enclave.HandlerFromMux(stub{}, router)

	var routes []string

	require.NoError(t, chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes = append(routes, method+" "+route)

		return nil
	}))

	sort.Strings(routes)

	return routes
}

// TestSubsetServesExactlyTheTaggedOperations is the profile's guard. The
// enclave deployment must serve the read-only authorization surface and
// NOTHING else, so this asserts set equality rather than containment: an
// extra route is a widened attack surface, and a missing one is an outage.
func TestSubsetServesExactlyTheTaggedOperations(t *testing.T) {
	t.Parallel()

	expected := taggedRoutes(t)
	require.Len(t, expected, 3, "the spec must tag exactly the three authorization routes")

	require.Equal(t, expected, mountedRoutes(t))
}

// TestSubsetServesNoWriteSurface pins the property a reviewer cares about in
// one assertion that does not depend on the tag set being right: no route the
// profile serves may use a write method.
func TestSubsetServesNoWriteSurface(t *testing.T) {
	t.Parallel()

	for _, route := range mountedRoutes(t) {
		require.NotContains(t, route, http.MethodPut)
		require.NotContains(t, route, http.MethodPatch)
		require.NotContains(t, route, http.MethodDelete)
	}
}
