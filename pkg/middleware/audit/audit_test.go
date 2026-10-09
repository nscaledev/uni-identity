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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/authz"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/middleware/audit"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	testOrganizationID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	testProjectID      = "c9bf9e57-1685-4c89-bafb-ff5af830be8a"
	testObjectID       = "16fd2706-8baf-433b-82eb-8c7fada847da"
)

type entry struct {
	message string
	values  map[string]any
}

type recorder struct {
	mu      sync.Mutex
	entries []entry
}

func (r *recorder) Init(logr.RuntimeInfo)          {}
func (r *recorder) Enabled(int) bool               { return true }
func (r *recorder) Error(error, string, ...any)    {}
func (r *recorder) WithValues(...any) logr.LogSink { return r }
func (r *recorder) WithName(string) logr.LogSink   { return r }

func (r *recorder) Info(_ int, message string, keysAndValues ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()

	values := map[string]any{}

	for i := 0; i+1 < len(keysAndValues); i += 2 {
		if key, ok := keysAndValues[i].(string); ok {
			values[key] = keysAndValues[i+1]
		}
	}

	r.entries = append(r.entries, entry{message: message, values: values})
}

func (r *recorder) withMessage(message string) []entry {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := []entry{}

	for _, e := range r.entries {
		if e.message == message {
			out = append(out, e)
		}
	}

	return out
}

// exercise runs a request through the middleware, with a handler that makes the
// given authorization decisions, and returns what was logged.
func exercise(t *testing.T, method, path string, status int, body string, decisions ...authz.Decision) *recorder {
	t.Helper()

	rec := &recorder{}

	request := httptest.NewRequest(method, path, strings.NewReader("{}"))

	ctx := log.IntoContext(request.Context(), logr.New(rec))
	ctx = authorization.NewContext(ctx, &authorization.Info{
		Userinfo: &openapi.Userinfo{Sub: "someone@example.com"},
	})

	request = request.WithContext(ctx)

	handler := audit.New("identity", "v1.2.3").Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, decision := range decisions {
			authz.Record(r.Context(), decision)
		}

		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))

	handler.ServeHTTP(httptest.NewRecorder(), request)

	return rec
}

func primary(endpoint string, operation authz.Operation, object uuid.UUID) authz.Decision {
	return authz.Decision{
		Target: authz.Target{
			Endpoint:  endpoint,
			Operation: operation,
			Kind:      authz.Primary,
			ObjectID:  object,
		},
		Scope: authz.Scope{
			OrganizationID: ids.MustParseOrganizationID(testOrganizationID),
			ProjectID:      ids.MustParseProjectID(testProjectID),
		},
		Allowed: true,
	}
}

// Everything in the record comes from the decision, so nothing depends on the
// request's URL any more.
func TestRecordComesFromTheDecision(t *testing.T) {
	t.Parallel()

	rec := exercise(t, http.MethodDelete, "https://identity.example.com/anything", http.StatusNoContent, "",
		primary("identity:groups", authz.Delete, uuid.MustParse(testObjectID)))

	audits := rec.withMessage("audit")
	require.Len(t, audits, 1)

	values := audits[0].values
	require.Equal(t, &audit.Operation{Verb: "delete"}, values["operation"])
	require.Equal(t, &audit.Resource{Type: "groups", ID: testObjectID}, values["resource"])
	require.Equal(t, &audit.Scope{OrganizationID: testOrganizationID, ProjectID: testProjectID}, values["scope"])
	require.Equal(t, &audit.Result{Status: http.StatusNoContent}, values["result"])
	require.Equal(t, &audit.Actor{Subject: "someone@example.com"}, values["actor"])
}

// This is the case the URL could never describe: a path that does not end in an
// identifier produced no record at all.
func TestQuotaUpdateIsNowRecorded(t *testing.T) {
	t.Parallel()

	rec := exercise(t, http.MethodPut, "https://identity.example.com/api/v1/organizations/"+testOrganizationID+"/quotas",
		http.StatusOK, "", primary("identity:quotas", authz.Update, uuid.MustParse(testOrganizationID)))

	require.Len(t, rec.withMessage("audit"), 1)
}

// An action on a resource is a POST, like a create, so only the declared action
// distinguishes them.
func TestActionIsRecordedRatherThanTheMethod(t *testing.T) {
	t.Parallel()

	rec := exercise(t, http.MethodPost, "https://identity.example.com/anything", http.StatusOK, "",
		primary("identity:serviceaccounts", authz.Action(openapi.Update, "rotate"), uuid.MustParse(testObjectID)))

	values := rec.withMessage("audit")[0].values
	require.Equal(t, &audit.Operation{Verb: "rotate"}, values["operation"])

	resource, ok := values["resource"].(*audit.Resource)
	require.True(t, ok)
	require.Equal(t, "serviceaccounts", resource.Type)
}

// A create is authorized before the resource exists, so its identifier is only
// knowable from the response.
func TestCreateTakesItsIdentifierFromTheResponse(t *testing.T) {
	t.Parallel()

	rec := exercise(t, http.MethodPost, "https://identity.example.com/anything", http.StatusCreated,
		`{"metadata":{"id":"`+testObjectID+`"}}`,
		primary("identity:groups", authz.Create, uuid.Nil))

	values := rec.withMessage("audit")[0].values
	require.Equal(t, &audit.Resource{Type: "groups", ID: testObjectID}, values["resource"])
}

// One record per thing acted on, so a request touching several resources does
// not collapse into a single line that names one of them.
func TestOneRecordPerPrimaryDecision(t *testing.T) {
	t.Parallel()

	rec := exercise(t, http.MethodDelete, "https://identity.example.com/anything", http.StatusNoContent, "",
		primary("identity:groups", authz.Delete, uuid.MustParse(testObjectID)),
		primary("identity:groups", authz.Delete, uuid.MustParse(testProjectID)))

	require.Len(t, rec.withMessage("audit"), 2)
}

// Checks a request had to pass are not the request.  Granting a role while
// updating a group must not produce a second audit record.
func TestPreconditionsDoNotProduceRecords(t *testing.T) {
	t.Parallel()

	precondition := authz.Decision{
		Target:  authz.Target{Endpoint: "identity:roles", Operation: authz.Read},
		Allowed: true,
	}

	rec := exercise(t, http.MethodPut, "https://identity.example.com/anything", http.StatusOK, "",
		primary("identity:groups", authz.Update, uuid.MustParse(testObjectID)), precondition)

	require.Len(t, rec.withMessage("audit"), 1)
}

// A mutation that authorized something but never said what it was doing is a
// defect.  Silence is what we are trying to stop, so it is reported.
func TestMutationWithoutAPrimaryIsReported(t *testing.T) {
	t.Parallel()

	precondition := authz.Decision{
		Target:  authz.Target{Endpoint: "identity:groups", Operation: authz.Update},
		Allowed: true,
	}

	rec := exercise(t, http.MethodPut, "https://identity.example.com/anything", http.StatusOK, "", precondition)

	require.Empty(t, rec.withMessage("audit"))

	gaps := rec.withMessage("audit gap")
	require.Len(t, gaps, 1)

	// It must not guess the operation from the HTTP method.  A POST to an
	// action sub-resource reads as a creation, so a failed rotation would be
	// reported as a create, which is worse than saying nothing.
	require.NotContains(t, gaps[0].values, "operation")
	require.Equal(t, []string{"identity:groups"}, gaps[0].values["endpoints"])
}

func TestGetRequestsAreNotAudited(t *testing.T) {
	t.Parallel()

	rec := exercise(t, http.MethodGet, "https://identity.example.com/anything", http.StatusOK, "",
		primary("identity:groups", authz.Read, uuid.MustParse(testObjectID)))

	require.Empty(t, rec.withMessage("audit"))
	require.Empty(t, rec.withMessage("audit gap"), "a read is not a gap")
}

func TestUnauthenticatedRequestsAreNotAudited(t *testing.T) {
	t.Parallel()

	rec := &recorder{}

	request := httptest.NewRequest(http.MethodDelete, "https://identity.example.com/anything", nil)
	request = request.WithContext(log.IntoContext(request.Context(), logr.New(rec)))

	handler := audit.New("identity", "v1.2.3").Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz.Record(r.Context(), primary("identity:groups", authz.Delete, uuid.MustParse(testObjectID)))
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), request)

	require.Empty(t, rec.withMessage("audit"))
}
