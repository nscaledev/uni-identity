/*
Copyright 2024-2025 the Unikorn Authors.
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

package audit

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/middleware"
	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	"github.com/unikorn-cloud/identity/pkg/authz"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

type Logger struct {
	// application is the application name.
	application string

	// version is the application version.
	version string

	// sinks consume every record.  The log sink is always first: the stdout
	// audit line is mandated by the platform specification, and it is what
	// remains if a remote sink cannot deliver.
	sinks []Sink
}

// New returns an initialized middleware.  Any sinks are additional to the
// structured log, never a replacement for it.
func New(application, version string, sinks ...Sink) *Logger {
	return &Logger{
		application: application,
		version:     version,
		sinks:       append([]Sink{logSink{}}, sinks...),
	}
}

// resourceType recovers the resource type from an RBAC endpoint, which is
// qualified by the service that owns it, for example "identity:groups".
func resourceType(endpoint string) string {
	if _, resource, found := strings.Cut(endpoint, ":"); found {
		return resource
	}

	return endpoint
}

// described recovers what the response says about the resource.
//
// The identifier is the one fact a decision cannot supply, because a create is
// authorized before the resource exists.  The name is not available to a
// decision either: handlers authorize on an identifier and the resource is only
// read later, inside the client.  Operations that return no body, notably
// deletes, yield neither.
func described(capture *middleware.Capture) (string, string) {
	if capture == nil || capture.Body() == nil {
		return "", ""
	}

	var body struct {
		Metadata openapi.ResourceReadMetadata `json:"metadata"`
	}

	if err := json.Unmarshal(capture.Body().Bytes(), &body); err != nil {
		return "", ""
	}

	return body.Metadata.Id, body.Metadata.Name
}

// resource describes what was acted on.
func resource(capture *middleware.Capture, decision authz.Decision) *Resource {
	out := &Resource{
		Type: resourceType(decision.Endpoint),
	}

	id, name := described(capture)

	// A name stated by the caller wins.  The response carries metadata.name,
	// which is a required field, so a resource with no meaningful name of its
	// own carries a sentinel there: a user's name is its subject, not the
	// placeholder the schema obliged somebody to supply.
	out.Name = name
	if decision.ObjectName != "" {
		out.Name = decision.ObjectName
	}

	if decision.ObjectID != uuid.Nil {
		out.ID = decision.ObjectID.String()

		return out
	}

	out.ID = id

	return out
}

// source is where the request came from.  Behind a proxy the connection address
// is the proxy, so the forwarding headers are preferred where present.
func source(r *http.Request) *Source {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// The first entry is the client; the rest are proxies it passed through.
		if client, _, found := strings.Cut(forwarded, ","); found {
			return &Source{IP: strings.TrimSpace(client)}
		}

		return &Source{IP: strings.TrimSpace(forwarded)}
	}

	if address := r.Header.Get("X-Real-Ip"); address != "" {
		return &Source{IP: address}
	}

	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return &Source{IP: host}
	}

	return nil
}

// grants are the checks the request had to pass before the operation itself.
// They are why it was allowed, which is the question asked after what happened.
func grants(decisions []authz.Decision) []Grant {
	out := make([]Grant, 0, len(decisions))

	for _, decision := range decisions {
		if decision.Kind == authz.Primary {
			continue
		}

		grant := Grant{
			Endpoint:  decision.Endpoint,
			Operation: decision.Operation.Action,
			Name:      decision.ObjectName,
		}

		if decision.ObjectID != uuid.Nil {
			grant.ID = decision.ObjectID.String()
		}

		out = append(out, grant)
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

// scope describes the tenancy affected, omitting what the decision did not name.
// scope is nil when nothing was checked, so an unknown scope is absent rather
// than empty.
func scope(decision authz.Decision) *Scope {
	if !decision.Scope.Organization() {
		return nil
	}

	out := &Scope{
		OrganizationID: decision.Scope.OrganizationID.String(),
	}

	if decision.Scope.Project() {
		out.ProjectID = decision.Scope.ProjectID.String()
	}

	return out
}

// getClient records what the actor called us with.  A client may legitimately
// send no User-Agent, which is reported as no client rather than an empty one.
func getClient(r *http.Request) *Client {
	agent := r.UserAgent()
	if agent == "" {
		return nil
	}

	return &Client{
		UserAgent: agent,
	}
}

// matched is what the server matched the request to: the method, the route
// template from its own schema, and the trace that joins the record to the
// response and the logs.  Never the raw path.
func matched(r *http.Request) *Request {
	out := &Request{
		Method: r.Method,
	}

	if info, err := routeresolver.FromContext(r.Context()); err == nil && info.Route != nil {
		out.Route = info.Route.Path
	}

	if span := trace.SpanContextFromContext(r.Context()); span.HasTraceID() {
		out.TraceID = span.TraceID().String()
	}

	return out
}

// caller is who made the request.  Outside authentication only the holder has
// it; inside, the context does, which is the order services used before audit
// could run outermost.
func caller(r *http.Request, holder *authorization.Holder) *authorization.Info {
	if info := holder.Info(); info != nil {
		return info
	}

	info, err := authorization.FromContext(r.Context())
	if err != nil {
		return nil
	}

	return info
}

// serve runs the handler and returns the status it answered with.  A panic is
// reported rather than allowed to skip the record, because a request that
// crashed is still one that was attempted; it counts as a 500.
func serve(w http.ResponseWriter, r *http.Request, next http.Handler) (*middleware.Capture, int, any) {
	var (
		capture   *middleware.Capture
		recovered any
	)

	func() {
		defer func() {
			recovered = recover()
		}()

		capture = middleware.CaptureResponse(w, r, next)
	}()

	if capture == nil {
		return nil, http.StatusInternalServerError, recovered
	}

	return capture, capture.StatusCode(), recovered
}

// handle audits one request.  See Middleware.
func (l *Logger) handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	// Users and auditors care about things coming, going and changing, who did
	// those things and when?  Certainly not periodic polling that is par for the
	// course.  Reads get no recorder at all, so a list filtering out what the
	// caller may not see costs nothing.
	if r.Method == http.MethodGet {
		next.ServeHTTP(w, r)

		return
	}

	// The recorder has to be in place before the handler runs, because the
	// decisions are made during it.  So does the holder, which is how the
	// caller reaches this middleware when it runs outside authentication.
	recorder := &authz.Recorder{}

	ctx, holder := authorization.NewHolderContext(authz.NewContext(r.Context(), recorder))

	// The recorder has to reach the handler, but r itself is left alone so that
	// everything read afterwards comes from the request as it arrived.
	capture, status, recovered := serve(w, r.WithContext(ctx), next)
	if recovered != nil {
		// The record is written before the panic carries on, so whatever
		// recovers it upstream answers the caller, and the audit log still
		// says what was attempted.
		defer panic(recovered)
	}

	// If there is not accountibility e.g. a global call, it's not worth logging.
	info := caller(r, holder)
	if info == nil {
		return
	}

	record := l.record(r, info, recorder, capture, status)

	// The response is already written by the time we get here, because the
	// capture writes through, so a sink costs the client nothing.  See the
	// README's delivery section.
	//
	// Delivery MUST NOT inherit the request's cancellation.  net/http cancels
	// that context when the client closes the connection, and since the
	// response has already been written, a caller that reads it and exits --
	// any CLI -- would cancel the POST in flight and lose the record everywhere
	// but stdout.  The per-delivery timeout still bounds it, and the context's
	// values are kept so logging stays correlated.
	ctx = context.WithoutCancel(r.Context())

	for _, sink := range l.sinks {
		emit(ctx, sink, record)
	}
}

// record builds the one record for a request, whatever the outcome: the status
// says whether it happened.  A request rejected before any handler described
// it, such as by schema validation, still gets one, with whatever is known and
// nothing invented: no verb from the HTTP method, as a POST to an action
// sub-resource is not a creation.  Grants are why it was allowed, so a request
// that did not succeed has none.  Handler mistakes found on the way are
// reported as defects.
func (l *Logger) record(r *http.Request, info *authorization.Info, recorder *authz.Recorder, capture *middleware.Capture, status int) *Record {
	logger := log.FromContext(r.Context())

	for _, defect := range recorder.Defects() {
		logger.Error(nil, "audit defect", "defect", defect)
	}

	request, state := recorder.Request()

	if state != authz.Checked && status < http.StatusBadRequest {
		logger.Error(nil, "audit defect", "defect", "request succeeded without its own authorization check",
			"endpoint", request.Endpoint, "status", status)
	}

	record := &Record{
		Timestamp: time.Now().UTC(),
		Component: &Component{
			Name:    l.application,
			Version: l.version,
		},
		Actor: &Actor{
			Subject: info.Userinfo.Sub,
		},
		Result: &Result{
			Status: status,
		},
		Client:  getClient(r),
		Source:  source(r),
		Request: matched(r),
	}

	if state != authz.NotDescribed {
		if request.Operation.Action != "" {
			record.Operation = &Operation{Verb: request.Operation.Action}
		}

		record.Scope = scope(request)
		record.Resource = resource(capture, request)
	}

	if status < http.StatusBadRequest {
		record.Grants = grants(recorder.Decisions())
	}

	return record
}

func (l *Logger) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.handle(w, r, next)
	})
}
