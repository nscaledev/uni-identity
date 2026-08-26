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
	"os"
	"sort"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/openapi/enclave"

	"sigs.k8s.io/yaml"
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

// enclaveRoutes is the literal route list the design commits to serving:
// the decision endpoint and both ACL reads.  It exists alongside
// taggedRoutes because the two checks catch different failures.
// Moving the tag off an operation is NOT the failure this list catches: the
// generated ServerInterface would then require a method for whatever
// operation the tag landed on instead, the stub below would stop matching
// it, and the package would fail to BUILD before either test ran. What this
// literal list catches is a path renamed under an unchanged method and an
// unmoved tag — e.g. "GET /api/v1/acl" becomes "GET /api/v1/acls" with the
// tag and the operationId (so the Go method name) both left alone.
// taggedRoutes would silently track that rename, because it re-derives its
// expectation from the same tag the router filters on, so
// TestSubsetServesExactlyTheTaggedOperations would still pass. This literal
// list would not track it, so TestSubsetServesTheDesignedRoutes would catch
// it. Neither check alone is sufficient.
//
//nolint:gochecknoglobals // fixed test fixture, not mutable state.
var enclaveRoutes = []string{
	"GET /api/v1/acl",
	"GET /api/v1/organizations/{organizationID}/acl",
	"POST /api/v1/authorization/check",
}

// TestSubsetServesTheDesignedRoutes pins the mounted route set against the
// literal enclaveRoutes list instead of the tag. See the enclaveRoutes
// comment for why this check exists alongside the spec-derived one.
func TestSubsetServesTheDesignedRoutes(t *testing.T) {
	t.Parallel()

	require.Equal(t, enclaveRoutes, mountedRoutes(t))
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

// specOperation and specPathItem decode only the fields this test needs from
// server.spec.yaml on disk: which HTTP methods exist per path, and each
// operation's tags. sigs.k8s.io/yaml converts YAML to JSON and decodes with
// encoding/json, so unrecognised path-item keys ("description",
// "parameters", "summary") are ignored rather than erroring.
type specOperation struct {
	Tags []string `json:"tags"`
}

type specPathItem struct {
	Get     *specOperation `json:"get"`
	Put     *specOperation `json:"put"`
	Post    *specOperation `json:"post"`
	Delete  *specOperation `json:"delete"`
	Options *specOperation `json:"options"`
	Head    *specOperation `json:"head"`
	Patch   *specOperation `json:"patch"`
	Trace   *specOperation `json:"trace"`
}

type specDocument struct {
	Paths map[string]specPathItem `json:"paths"`
}

// taggedRoutesFromDisk re-derives taggedRoutes' expectation, but from
// server.spec.yaml read straight off disk rather than from the embedded,
// generated openapi.GetSwagger(). See TestSpecFileTagsMatchMountedRoutes for
// why that distinction matters.
func taggedRoutesFromDisk(t *testing.T) []string {
	t.Helper()

	raw, err := os.ReadFile("../server.spec.yaml")
	require.NoError(t, err)

	var doc specDocument

	require.NoError(t, yaml.Unmarshal(raw, &doc))

	var routes []string

	for path, item := range doc.Paths {
		methods := map[string]*specOperation{
			http.MethodGet:     item.Get,
			http.MethodPut:     item.Put,
			http.MethodPost:    item.Post,
			http.MethodDelete:  item.Delete,
			http.MethodOptions: item.Options,
			http.MethodHead:    item.Head,
			http.MethodPatch:   item.Patch,
			http.MethodTrace:   item.Trace,
		}

		for method, op := range methods {
			if op == nil {
				continue
			}

			for _, tag := range op.Tags {
				if tag == enclaveTag {
					routes = append(routes, method+" "+path)
				}
			}
		}
	}

	sort.Strings(routes)

	return routes
}

// TestSpecFileTagsMatchMountedRoutes is the staleness guard
// TestSubsetServesExactlyTheTaggedOperations cannot be. That test compares
// the generated router against the EMBEDDED spec (openapi.GetSwagger()), and
// `make generate` produces both the router and the embedded spec from
// server.spec.yaml in the same step. If that step ever stops running, the
// router and the embedded spec go stale TOGETHER: they stay mutually
// consistent with each other, and every existing test in this file keeps
// passing. This test parses server.spec.yaml directly off disk instead, so a
// regeneration gap between the spec file and either generated artifact
// fails it.
func TestSpecFileTagsMatchMountedRoutes(t *testing.T) {
	t.Parallel()

	require.Equal(t, taggedRoutesFromDisk(t), mountedRoutes(t))
}
