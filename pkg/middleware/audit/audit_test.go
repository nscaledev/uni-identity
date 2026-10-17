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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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

// capturingSink records what it is handed.
type capturingSink struct {
	mu      sync.Mutex
	records []*audit.Record
}

func (s *capturingSink) Emit(_ context.Context, record *audit.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records = append(s.records, record)
}

func (s *capturingSink) all() []*audit.Record {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]*audit.Record{}, s.records...)
}

// panickingSink stands in for a sink that fails in the worst way available.
type panickingSink struct{}

func (panickingSink) Emit(context.Context, *audit.Record) {
	panic("sink exploded")
}

// exerciseWithSinks is exercise with sinks attached and an optional user agent.
func exerciseWithSinks(t *testing.T, sinks []audit.Sink, method, agent string, decisions ...authz.Decision) *recorder {
	t.Helper()

	rec := &recorder{}

	request := httptest.NewRequest(method, "https://identity.example.com/anything", strings.NewReader("{}"))
	if agent != "" {
		request.Header.Set("User-Agent", agent)
	}

	ctx := log.IntoContext(request.Context(), logr.New(rec))
	ctx = authorization.NewContext(ctx, &authorization.Info{
		Userinfo: &openapi.Userinfo{Sub: "someone@example.com"},
	})

	request = request.WithContext(ctx)

	handler := audit.New("identity", "v1.2.3", sinks...).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, decision := range decisions {
			authz.Record(r.Context(), decision)
		}

		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), request)

	return rec
}

func deleteGroup() authz.Decision {
	return primary("identity:groups", authz.Delete, uuid.MustParse(testObjectID))
}

// A configured sink receives the same record the log line was built from, so
// what ships to a collector cannot drift from what was logged.
func TestSinksReceiveTheSameRecordAsTheLog(t *testing.T) {
	t.Parallel()

	sink := &capturingSink{}

	rec := exerciseWithSinks(t, []audit.Sink{sink}, http.MethodDelete, "", deleteGroup())

	records := sink.all()
	require.Len(t, records, 1)
	require.Len(t, rec.withMessage("audit"), 1, "configuring a sink must not replace the log line")

	require.Equal(t, "delete", records[0].Operation.Verb)
	require.Equal(t, "groups", records[0].Resource.Type)
	require.Equal(t, testObjectID, records[0].Resource.ID)
	require.Equal(t, testOrganizationID, records[0].Scope.OrganizationID)
}

func TestSinksAreNotCalledWhenNothingIsAudited(t *testing.T) {
	t.Parallel()

	sink := &capturingSink{}

	exerciseWithSinks(t, []audit.Sink{sink}, http.MethodGet, "",
		primary("identity:groups", authz.Read, uuid.MustParse(testObjectID)))

	require.Empty(t, sink.all())
}

// Audit delivery MUST NOT affect the request.  A sink that panics is the
// harshest version of that.
func TestSinkPanicDoesNotBreakTheRequest(t *testing.T) {
	t.Parallel()

	good := &capturingSink{}

	require.NotPanics(t, func() {
		exerciseWithSinks(t, []audit.Sink{panickingSink{}, good}, http.MethodDelete, "", deleteGroup())
	})

	require.Len(t, good.all(), 1, "a failing sink must not stop the others")
}

// The client distinguishes a UI call from a CLI or direct API one.
func TestClientUserAgentIsRecorded(t *testing.T) {
	t.Parallel()

	sink := &capturingSink{}

	exerciseWithSinks(t, []audit.Sink{sink}, http.MethodDelete, "unikorn-cli/1.4.0", deleteGroup())

	records := sink.all()
	require.Len(t, records, 1)
	require.Equal(t, &audit.Client{UserAgent: "unikorn-cli/1.4.0"}, records[0].Client)
}

// A client may send no User-Agent.  That must not invent an empty one, nor
// appear as an empty object on the wire.
func TestAbsentUserAgentLeavesTheClientUnset(t *testing.T) {
	t.Parallel()

	sink := &capturingSink{}

	exerciseWithSinks(t, []audit.Sink{sink}, http.MethodDelete, "", deleteGroup())

	records := sink.all()
	require.Len(t, records, 1)
	require.Nil(t, records[0].Client)

	encoded, err := json.Marshal(records[0])
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "client")
}

// A record has to say when the thing happened.  The signature carries a
// creation time, but that moves on a retry, covers a batch rather than an
// event, and is gone once the record is stored.
func TestRecordCarriesItsOwnTimestamp(t *testing.T) {
	t.Parallel()

	sink := &capturingSink{}

	before := time.Now().UTC()

	exerciseWithSinks(t, []audit.Sink{sink}, http.MethodDelete, "", deleteGroup())

	after := time.Now().UTC()

	records := sink.all()
	require.Len(t, records, 1)
	require.False(t, records[0].Timestamp.Before(before))
	require.False(t, records[0].Timestamp.After(after))
}

// The checks a request had to pass are why it was allowed, which is what an
// auditor asks after what happened.  Granting roles while updating a group is
// the case that matters: the record should say which.
func TestGrantsRelayThePreconditions(t *testing.T) {
	t.Parallel()

	sink := &capturingSink{}

	grant := authz.Decision{
		Target: authz.Target{
			Endpoint:   "identity:roles",
			Operation:  authz.Action(openapi.Update, "grant"),
			ObjectID:   uuid.MustParse(testProjectID),
			ObjectName: "platform-admin",
		},
		Allowed: true,
	}

	exerciseWithSinks(t, []audit.Sink{sink}, http.MethodPut, "",
		primary("identity:groups", authz.Update, uuid.MustParse(testObjectID)), grant)

	records := sink.all()
	require.Len(t, records, 1, "a precondition is not its own event")
	require.Equal(t, []audit.Grant{{
		Endpoint:  "identity:roles",
		Operation: "grant",
		ID:        testProjectID,
		Name:      "platform-admin",
	}}, records[0].Grants, "the record must say which role, not merely that one was granted")
}

// With nothing but the operation itself there is nothing to relay, and an empty
// list should not appear on the wire.
func TestNoGrantsWhenThereAreNoPreconditions(t *testing.T) {
	t.Parallel()

	sink := &capturingSink{}

	exerciseWithSinks(t, []audit.Sink{sink}, http.MethodDelete, "", deleteGroup())

	records := sink.all()
	require.Len(t, records, 1)
	require.Nil(t, records[0].Grants)

	encoded, err := json.Marshal(records[0])
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "grants")
}

// A reader should not have to resolve an identifier to know what was touched,
// and after a deletion they cannot.
func TestResourceNameComesFromTheResponse(t *testing.T) {
	t.Parallel()

	rec := exercise(t, http.MethodPost, "https://identity.example.com/anything", http.StatusCreated,
		`{"metadata":{"id":"`+testObjectID+`","name":"platform-admins"}}`,
		primary("identity:groups", authz.Create, uuid.Nil))

	values := rec.withMessage("audit")[0].values

	resource, ok := values["resource"].(*audit.Resource)
	require.True(t, ok)
	require.Equal(t, testObjectID, resource.ID)
	require.Equal(t, "platform-admins", resource.Name)
}

// Behind a proxy the connection address is the proxy, so the forwarding header
// wins where it is present.
func TestSourceIPPrefersTheForwardedClient(t *testing.T) {
	t.Parallel()

	sink := &capturingSink{}

	rec := &recorder{}
	request := httptest.NewRequest(http.MethodDelete, "https://identity.example.com/anything", strings.NewReader("{}"))
	request.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")

	ctx := log.IntoContext(request.Context(), logr.New(rec))
	ctx = authorization.NewContext(ctx, &authorization.Info{
		Userinfo: &openapi.Userinfo{Sub: "someone@example.com"},
	})
	request = request.WithContext(ctx)

	handler := audit.New("identity", "v1.2.3", sink).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz.Record(r.Context(), deleteGroup())
		w.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), request)

	records := sink.all()
	require.Len(t, records, 1)
	require.Equal(t, &audit.Source{IP: "203.0.113.7"}, records[0].Source,
		"the first entry is the client, the rest are proxies it passed through")
}

// The log line and the posted body describe the same event, so they must carry
// the same fields.  A field reaching one and not the other is a discrepancy
// nobody notices until the two are compared during an investigation -- which is
// exactly when it matters.
//
// This compares them directly rather than listing expected keys, so a field
// added to the record and forgotten in the log sink fails here.
func TestLogLineCarriesEveryRecordField(t *testing.T) {
	t.Parallel()

	sink := &capturingSink{}

	grant := authz.Decision{
		Target:  authz.Target{Endpoint: "identity:roles", Operation: authz.Action(openapi.Update, "grant")},
		Allowed: true,
	}

	rec := exerciseWithSinks(t, []audit.Sink{sink}, http.MethodPut, "unikorn-cli/1.4.0",
		primary("identity:groups", authz.Update, uuid.MustParse(testObjectID)), grant)

	records := sink.all()
	require.Len(t, records, 1)

	encoded, err := json.Marshal(records[0])
	require.NoError(t, err)

	var body map[string]any

	require.NoError(t, json.Unmarshal(encoded, &body))

	audits := rec.withMessage("audit")
	require.Len(t, audits, 1)

	for field := range body {
		require.Contains(t, audits[0].values, field,
			"field %q is delivered to a collector but missing from the log line", field)
	}

	for field := range audits[0].values {
		require.Contains(t, body, field,
			"field %q is logged but never delivered to a collector", field)
	}
}

// metadata.name is required by the schema, so a resource with no meaningful
// name of its own carries a sentinel there.  A name the caller states is the
// real one and must win.
func TestStatedNameOverridesTheResponse(t *testing.T) {
	t.Parallel()

	stated := authz.Decision{
		Target: authz.Target{
			Endpoint:   "identity:users",
			Operation:  authz.Create,
			Kind:       authz.Primary,
			ObjectName: "simon.murray@nscale.com",
		},
		Scope:   authz.Scope{OrganizationID: ids.MustParseOrganizationID(testOrganizationID)},
		Allowed: true,
	}

	rec := exercise(t, http.MethodPost, "https://identity.example.com/anything", http.StatusCreated,
		`{"metadata":{"id":"`+testObjectID+`","name":"undefined"}}`, stated)

	resource, ok := rec.withMessage("audit")[0].values["resource"].(*audit.Resource)
	require.True(t, ok)
	require.Equal(t, "simon.murray@nscale.com", resource.Name)
	require.Equal(t, testObjectID, resource.ID, "the identifier still comes from the response")
}
