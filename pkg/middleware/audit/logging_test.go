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

// These tests pin the front-door audit record (logging.go): the decision
// accumulator seed-then-read that adds the decisions list, a resource field
// that keeps its existing type and id so current log consumers keep working,
// and the GET and no-auth-info skips.

const (
	testOrganizationID = "11111111-1111-1111-1111-111111111111"
	testProjectID      = "test-project"
	testClusterID      = "test-cluster"

	// testGroupID and testCreatedServiceAccountID support the resource tests
	// below: testCreatedServiceAccountID only ever appears in a response body.
	testGroupID                 = "test-group"
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
// exercise: Update/Read on "compute:clusters", Delete on "identity:groups"
// and Create on "identity:serviceaccounts".
func testACL() *openapi.Acl {
	return &openapi.Acl{
		Organizations: &openapi.AclOrganizationList{
			{
				Id: testOrganizationID,
				Endpoints: &openapi.AclEndpoints{
					{Name: "compute:clusters", Operations: openapi.AclOperations{openapi.Update, openapi.Read}},
					{Name: "identity:groups", Operations: openapi.AclOperations{openapi.Delete}},
					{Name: "identity:serviceaccounts", Operations: openapi.AclOperations{openapi.Create}},
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

// TestMiddlewareKeepsResourceTypeAndRecordsKind proves that the record adds
// the authorization decision without changing the resource field: existing
// log consumers parse resource.type as the URL segment ("groups"), so the
// kind the handler passed to Allow* ("identity:groups") goes only in the
// decisions list.
func TestMiddlewareKeepsResourceTypeAndRecordsKind(t *testing.T) {
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

	fields := attrs(t, records[0])

	resource, ok := fields["resource"].(*audit.Resource)
	require.True(t, ok, "resource field must be *audit.Resource")
	require.Equal(t, "groups", resource.Type, "type must keep the URL segment that existing log consumers parse")
	require.Equal(t, testGroupID, resource.ID)

	decisions, ok := fields["decisions"].([]audit.Decision)
	require.True(t, ok, "decisions field must be []audit.Decision")
	require.Len(t, decisions, 1)
	require.Equal(t, "identity:groups", decisions[0].ResourceKind, "the authorized kind belongs in the decisions list")
}

// TestMiddlewareCreateResourceIDFromResponseBody proves that a create keeps
// its existing record: the type is the collection's URL segment and the id
// comes from the response body's canonical metadata, because the server
// mints the id.
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
	require.Equal(t, "serviceaccounts", resource.Type)
	require.Equal(t, testCreatedServiceAccountID, resource.ID, "a create must resolve its id from the response body")
}

// TestMiddlewareNeverAuditsGet pins that a GET is never audit logged.
func TestMiddlewareNeverAuditsGet(t *testing.T) {
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
	})

	audit.New("test", "v1").Middleware(next).ServeHTTP(httptest.NewRecorder(), r)

	require.Empty(t, capture.auditRecords(), "a GET must never be audit logged")
}

// TestMiddlewareSkipsWithNoAuthInfo is a regression check on the existing
// "no accountability" skip: a mutation with no authorization.Info in context
// is still silently skipped.
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
}
