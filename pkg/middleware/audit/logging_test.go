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

package audit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/middleware/audit"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// These tests pin the F2 front-door audit fixes (logging.go): the decision
// accumulator seed-then-read, resource derivation from the authorization
// decision's authoritative ResourceKind plus the request's last path
// parameter (with the create-vs-action POST distinction that replaces the
// old URL-guessing heuristic), and the x-unikorn-audit sensitive-read marker
// — while proving the pre-existing skips (routine reads, no auth info) are
// untouched.

const (
	testOrganizationID = "11111111-1111-1111-1111-111111111111"
	testProjectID      = "test-project"
	testClusterID      = "test-cluster"

	// testGroupID, testServiceAccountID and testCreatedServiceAccountID
	// support the resource-derivation tests below: testServiceAccountID is
	// the path-addressed instance, testCreatedServiceAccountID a distinct id
	// that only ever appears in a response body, so the two can never be
	// mistaken for one another in an assertion.
	testGroupID                 = "test-group"
	testServiceAccountID        = "test-service-account"
	testCreatedServiceAccountID = "test-created-service-account"
)

// organizationUUID parses testOrganizationID for the typed
// AllowOrganizationScopeID calls the fixture handlers below use (the plain
// string AllowOrganizationScope is deprecated).
func organizationUUID(t *testing.T) ids.OrganizationID {
	t.Helper()

	id, err := ids.ParseOrganizationID(testOrganizationID)
	require.NoError(t, err)

	return id
}

// logCapture is a minimal logr.LogSink recording every record emitted
// through a logger backed by it, seeded into the context exactly where
// log.FromContext looks. A local analog of pkg/rbac's decision_log_test.go
// fixture of the same name (test types are not shared across packages).
type logCapture struct {
	mu      sync.Mutex
	records []logRecord
}

type logRecord struct {
	message string
	fields  []any
}

func (c *logCapture) Init(logr.RuntimeInfo) {}

func (c *logCapture) Enabled(int) bool {
	return true
}

func (c *logCapture) Info(_ int, message string, fields ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.records = append(c.records, logRecord{message: message, fields: fields})
}

func (c *logCapture) Error(_ error, message string, fields ...any) {
	c.Info(0, message, fields...)
}

func (c *logCapture) WithValues(...any) logr.LogSink {
	return c
}

func (c *logCapture) WithName(string) logr.LogSink {
	return c
}

func (c *logCapture) into(ctx context.Context) context.Context {
	return log.IntoContext(ctx, logr.New(c))
}

// auditRecords returns every captured record carrying the "audit" message —
// the only message this middleware ever emits.
func (c *logCapture) auditRecords() []logRecord {
	c.mu.Lock()
	defer c.mu.Unlock()

	var out []logRecord

	for _, record := range c.records {
		if record.message == "audit" {
			out = append(out, record)
		}
	}

	return out
}

// attrs flattens a record's flat key/value field list into a map, preserving
// each value's real type: unlike the PDP decision log, audit's fields are
// pointers/slices, not scalars.
func attrs(t *testing.T, record logRecord) map[string]any {
	t.Helper()

	require.Zero(t, len(record.fields)%2, "a record must carry complete key/value pairs")

	out := map[string]any{}

	for i := 0; i+1 < len(record.fields); i += 2 {
		key, ok := record.fields[i].(string)
		require.True(t, ok, "field keys must be strings")

		out[key] = record.fields[i+1]
	}

	return out
}

// testACL grants the fixture handlers below enough organization-scope
// permissions to record a real allow for each resource kind the tests below
// exercise: Update/Read on "compute:clusters", Delete on "identity:groups",
// Create/Update on "identity:serviceaccounts", and Update on
// "identity:quotas".
func testACL() *openapi.Acl {
	return &openapi.Acl{
		Organizations: &openapi.AclOrganizationList{
			{
				Id: testOrganizationID,
				Endpoints: &openapi.AclEndpoints{
					{Name: "compute:clusters", Operations: openapi.AclOperations{openapi.Update, openapi.Read}},
					{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Delete}},
					{Name: "identity:serviceaccounts", Operations: openapi.AclOperations{openapi.Create, openapi.Update}},
					{Name: "identity:quotas", Operations: openapi.AclOperations{openapi.Update}},
				},
			},
		},
	}
}

// newRequest builds a request whose context is pre-seeded exactly as
// production middleware seeds it before audit.Middleware runs: route info,
// authorization info and an ACL — everything audit reads from context, and
// everything a handler needs to call Allow*. audit.Middleware itself seeds
// the decision accumulator (that is Part 2's own job, not the test's).
func newRequest(t *testing.T, method string, route *routers.Route, params map[string]string, capture *logCapture) *http.Request {
	t.Helper()

	ctx := t.Context()
	ctx = context.WithValue(ctx, routeresolver.RouteInfoKey, &routeresolver.RouteInfo{Route: route, Parameters: params})
	ctx = authorization.NewContext(ctx, &authorization.Info{Userinfo: &openapi.Userinfo{Sub: "test-subject"}})
	ctx = rbac.NewContext(ctx, testACL())
	ctx = capture.into(ctx)

	return httptest.NewRequest(method, "/test", nil).WithContext(ctx)
}

func clusterParams() map[string]string {
	return map[string]string{
		"organizationID": testOrganizationID,
		"projectID":      testProjectID,
		"clusterID":      testClusterID,
	}
}

// TestMiddlewareResourceTypeIsAuthoritative proves the core F2 rescope: type
// comes from the authorization decision's ResourceKind — the kind the
// handler passed to Allow* — never from a URL segment (the old code would
// have reported the URL segment "groups", not "identity:groups"). id is the
// last {param} in the path template, resolved against the route's
// parameters.
func TestMiddlewareResourceTypeIsAuthoritative(t *testing.T) {
	t.Parallel()

	route := &routers.Route{
		Path:      "/api/v1/organizations/{organizationID}/groups/{groupid}",
		Method:    http.MethodDelete,
		Operation: &openapi3.Operation{},
	}
	params := map[string]string{
		"organizationID": testOrganizationID,
		"groupid":        testGroupID,
	}

	capture := &logCapture{}
	r := newRequest(t, http.MethodDelete, route, params, capture)
	orgID := organizationUUID(t)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, rbac.AllowOrganizationScopeID(r.Context(), "identity:groups", openapi.Delete, orgID))

		w.WriteHeader(http.StatusOK)
	})

	audit.New("test", "v1").Middleware(next).ServeHTTP(httptest.NewRecorder(), r)

	records := capture.auditRecords()
	require.Len(t, records, 1)

	resource, ok := attrs(t, records[0])["resource"].(*audit.Resource)
	require.True(t, ok, "resource field must be *audit.Resource")
	require.Equal(t, "identity:groups", resource.Type, "type must be the decision's ResourceKind, not the URL segment \"groups\"")
	require.Equal(t, testGroupID, resource.ID, "id must be the last path parameter")
}

// TestMiddlewareActionPostIsNotMisreadAsCreate is the regression the old
// code failed: a body-less action (x-no-body POST .../rotate,
// Operation.RequestBody nil) must not be misread as a create. The response
// carries a non-empty, canonical-shaped body (a freshly rotated access
// token) whose metadata.id differs from the path's serviceAccountID — the
// id must still come from the path, proving the body is never consulted for
// a body-less action.
func TestMiddlewareActionPostIsNotMisreadAsCreate(t *testing.T) {
	t.Parallel()

	route := &routers.Route{
		Path:      "/api/v1/organizations/{organizationID}/serviceaccounts/{serviceAccountID}/rotate",
		Method:    http.MethodPost,
		Operation: &openapi3.Operation{}, // x-no-body in the spec: no RequestBody.
	}
	params := map[string]string{
		"organizationID":   testOrganizationID,
		"serviceAccountID": testServiceAccountID,
	}

	capture := &logCapture{}
	r := newRequest(t, http.MethodPost, route, params, capture)
	orgID := organizationUUID(t)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, rbac.AllowOrganizationScopeID(r.Context(), "identity:serviceaccounts", openapi.Update, orgID))

		// The real rotate shape: 200 with a populated body (the new token),
		// carrying an id that is NOT the addressed service account's own id.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"metadata":{"id":"` + testCreatedServiceAccountID + `"}}`))
	})

	audit.New("test", "v1").Middleware(next).ServeHTTP(httptest.NewRecorder(), r)

	records := capture.auditRecords()
	require.Len(t, records, 1)

	resource, ok := attrs(t, records[0])["resource"].(*audit.Resource)
	require.True(t, ok)
	require.Equal(t, "identity:serviceaccounts", resource.Type)
	require.Equal(t, testServiceAccountID, resource.ID, "the path parameter must win; a body-less action's response body must not be consulted")
}

// TestMiddlewareCreateResourceIDFromResponseBody proves a real create — a
// POST carrying a request body to a collection (path ends in the literal
// "serviceaccounts", not an instance {parameter}) — resolves its id from
// the response body's canonical metadata. params also carries
// organizationID (the collection's own last path parameter): if the create
// branch fell through to the path instead of reading the body, it would
// wrongly report organizationID.
func TestMiddlewareCreateResourceIDFromResponseBody(t *testing.T) {
	t.Parallel()

	route := &routers.Route{
		Path:      "/api/v1/organizations/{organizationID}/serviceaccounts",
		Method:    http.MethodPost,
		Operation: &openapi3.Operation{RequestBody: &openapi3.RequestBodyRef{}},
	}
	params := map[string]string{
		"organizationID": testOrganizationID,
	}

	capture := &logCapture{}
	r := newRequest(t, http.MethodPost, route, params, capture)
	orgID := organizationUUID(t)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, rbac.AllowOrganizationScopeID(r.Context(), "identity:serviceaccounts", openapi.Create, orgID))

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"metadata":{"id":"` + testCreatedServiceAccountID + `"}}`))
	})

	audit.New("test", "v1").Middleware(next).ServeHTTP(httptest.NewRecorder(), r)

	records := capture.auditRecords()
	require.Len(t, records, 1)

	resource, ok := attrs(t, records[0])["resource"].(*audit.Resource)
	require.True(t, ok)
	require.Equal(t, "identity:serviceaccounts", resource.Type)
	require.Equal(t, testCreatedServiceAccountID, resource.ID, "a create must resolve its id from the response body, not organizationID (the last path parameter)")
}

// TestMiddlewareFailedCreateDoesNotStampParentID proves the F1 fix: a create
// whose response carries no canonical id — a denied or otherwise failed create
// — must resolve to an EMPTY id, never falling back to the last path parameter.
// For a create that parameter is the PARENT collection's id (organizationID
// here); the pre-fix code stamped it as the created resource's id,
// misattributing a failed create to the organization it was scoped under.
func TestMiddlewareFailedCreateDoesNotStampParentID(t *testing.T) {
	t.Parallel()

	route := &routers.Route{
		Path:      "/api/v1/organizations/{organizationID}/serviceaccounts",
		Method:    http.MethodPost,
		Operation: &openapi3.Operation{RequestBody: &openapi3.RequestBodyRef{}},
	}
	params := map[string]string{
		"organizationID": testOrganizationID,
	}

	capture := &logCapture{}
	r := newRequest(t, http.MethodPost, route, params, capture)
	orgID := organizationUUID(t)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The coarse check is recorded (so the audited kind is known), but the
		// create does not complete: the response carries no canonical metadata
		// id (here a 5xx error body — a denial or validation failure looks the
		// same to the id extraction).
		assert.NoError(t, rbac.AllowOrganizationScopeID(r.Context(), "identity:serviceaccounts", openapi.Create, orgID))

		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	})

	audit.New("test", "v1").Middleware(next).ServeHTTP(httptest.NewRecorder(), r)

	records := capture.auditRecords()
	require.Len(t, records, 1)

	resource, ok := attrs(t, records[0])["resource"].(*audit.Resource)
	require.True(t, ok)
	require.Equal(t, "identity:serviceaccounts", resource.Type)
	require.Empty(t, resource.ID, "a create with no canonical id in its response must not stamp the parent organizationID as the resource id")
}

// TestMiddlewareLiteralTerminatedPathResourceID proves a mutation whose path
// ends in a literal singleton segment (".../quotas", not an instance
// {parameter}) resolves its id from the last path parameter available —
// here organizationID — and its type from the decision, not the URL's
// trailing literal (the old code walked path.Dir past "quotas" and reported
// "organizations").
func TestMiddlewareLiteralTerminatedPathResourceID(t *testing.T) {
	t.Parallel()

	route := &routers.Route{
		Path:      "/api/v1/organizations/{organizationID}/quotas",
		Method:    http.MethodPut,
		Operation: &openapi3.Operation{RequestBody: &openapi3.RequestBodyRef{}},
	}
	params := map[string]string{
		"organizationID": testOrganizationID,
	}

	capture := &logCapture{}
	r := newRequest(t, http.MethodPut, route, params, capture)
	orgID := organizationUUID(t)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, rbac.AllowOrganizationScopeID(r.Context(), "identity:quotas", openapi.Update, orgID))

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"hard":{}}`))
	})

	audit.New("test", "v1").Middleware(next).ServeHTTP(httptest.NewRecorder(), r)

	records := capture.auditRecords()
	require.Len(t, records, 1)

	resource, ok := attrs(t, records[0])["resource"].(*audit.Resource)
	require.True(t, ok)
	require.Equal(t, "identity:quotas", resource.Type, "type must come from the decision, not the URL's trailing literal segment")
	require.Equal(t, testOrganizationID, resource.ID, "a PUT is never a create, so the response body (however shaped) must not be consulted")
}

// TestMiddlewareEmitsForMarkedSensitiveRead proves the x-unikorn-audit
// sensitive-read marker: a GET whose operation carries the extension is no
// longer blanket-skipped, and is logged like a mutation, with its resource
// type still the authoritative decision kind (not the URL segment
// "clusters") and its id the last path parameter.
func TestMiddlewareEmitsForMarkedSensitiveRead(t *testing.T) {
	t.Parallel()

	route := &routers.Route{
		Path:   "/api/v1/organizations/{organizationID}/projects/{projectID}/clusters/{clusterID}/kubeconfig",
		Method: http.MethodGet,
		Operation: &openapi3.Operation{
			Extensions: map[string]any{"x-unikorn-audit": "sensitive"},
		},
	}

	capture := &logCapture{}
	r := newRequest(t, http.MethodGet, route, clusterParams(), capture)
	orgID := organizationUUID(t)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, rbac.AllowOrganizationScopeID(r.Context(), "compute:clusters", openapi.Read, orgID))

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"kubeconfig":"redacted"}`))
	})

	audit.New("test", "v1").Middleware(next).ServeHTTP(httptest.NewRecorder(), r)

	records := capture.auditRecords()
	require.Len(t, records, 1, "a marked sensitive read must now be logged, not skipped")

	fields := attrs(t, records[0])

	resource, ok := fields["resource"].(*audit.Resource)
	require.True(t, ok)
	require.Equal(t, "compute:clusters", resource.Type)
	require.Equal(t, testClusterID, resource.ID)

	decisions, ok := fields["decisions"].([]audit.Decision)
	require.True(t, ok)
	require.Equal(t, []audit.Decision{
		{ResourceKind: "compute:clusters", Action: "read", Decision: "allow", Reason: "policy"},
	}, decisions)
}

// TestMiddlewareSkipsRoutineRead proves the existing selectivity is
// untouched: a GET whose operation carries no x-unikorn-audit extension is
// still skipped exactly as before.
func TestMiddlewareSkipsRoutineRead(t *testing.T) {
	t.Parallel()

	route := &routers.Route{
		Path:      "/api/v1/organizations/{organizationID}/projects/{projectID}/clusters/{clusterID}",
		Method:    http.MethodGet,
		Operation: &openapi3.Operation{},
	}

	capture := &logCapture{}
	r := newRequest(t, http.MethodGet, route, clusterParams(), capture)
	orgID := organizationUUID(t)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, rbac.AllowOrganizationScopeID(r.Context(), "compute:clusters", openapi.Read, orgID))

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"metadata":{"id":"` + testClusterID + `"}}`))
	})

	audit.New("test", "v1").Middleware(next).ServeHTTP(httptest.NewRecorder(), r)

	require.Empty(t, capture.auditRecords(), "an unmarked routine read must still be skipped")
}

// TestMiddlewareSkipsWithNoAuthInfo is a regression check on the existing
// "no accountability" skip: a request with no authorization.Info in context
// is still silently skipped, for a mutation and for a marked sensitive read
// alike. This is the one genuine skip the reordering in handle() (route
// resolution moved ahead of the GET check, to consult isSensitiveRead) could
// plausibly have disturbed.
func TestMiddlewareSkipsWithNoAuthInfo(t *testing.T) {
	t.Parallel()

	newRequestWithoutAuthInfo := func(t *testing.T, method string, route *routers.Route, params map[string]string, capture *logCapture) *http.Request {
		t.Helper()

		ctx := t.Context()
		ctx = context.WithValue(ctx, routeresolver.RouteInfoKey, &routeresolver.RouteInfo{Route: route, Parameters: params})
		ctx = rbac.NewContext(ctx, testACL())
		ctx = capture.into(ctx)

		return httptest.NewRequest(method, "/test", nil).WithContext(ctx)
	}

	t.Run("a mutation with no auth info is skipped", func(t *testing.T) {
		t.Parallel()

		route := &routers.Route{
			Path:      "/api/v1/organizations/{organizationID}/projects/{projectID}/clusters/{clusterID}",
			Method:    http.MethodPut,
			Operation: &openapi3.Operation{},
		}

		capture := &logCapture{}
		r := newRequestWithoutAuthInfo(t, http.MethodPut, route, clusterParams(), capture)

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"metadata":{"id":"` + testClusterID + `"}}`))
		})

		audit.New("test", "v1").Middleware(next).ServeHTTP(httptest.NewRecorder(), r)

		require.Empty(t, capture.auditRecords(), "a mutation with no auth info must still be skipped")
	})

	t.Run("a marked sensitive read with no auth info is skipped", func(t *testing.T) {
		t.Parallel()

		route := &routers.Route{
			Path:   "/api/v1/organizations/{organizationID}/projects/{projectID}/clusters/{clusterID}/kubeconfig",
			Method: http.MethodGet,
			Operation: &openapi3.Operation{
				Extensions: map[string]any{"x-unikorn-audit": "sensitive"},
			},
		}

		capture := &logCapture{}
		r := newRequestWithoutAuthInfo(t, http.MethodGet, route, clusterParams(), capture)

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"kubeconfig":"redacted"}`))
		})

		audit.New("test", "v1").Middleware(next).ServeHTTP(httptest.NewRecorder(), r)

		require.Empty(t, capture.auditRecords(), "a marked sensitive read with no auth info must still be skipped")
	})
}
