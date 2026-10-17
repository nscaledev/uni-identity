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
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/middleware"
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
	if capture.Body() == nil {
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
func scope(decision authz.Decision) *Scope {
	out := &Scope{}

	if decision.Scope.Organization() {
		out.OrganizationID = decision.Scope.OrganizationID.String()
	}

	if decision.Scope.Project() {
		out.ProjectID = decision.Scope.ProjectID.String()
	}

	return out
}

// checkedEndpoints names what the request did authorize against, which is the
// only thing known about an operation that never described itself.
func checkedEndpoints(decisions []authz.Decision) []string {
	out := make([]string, 0, len(decisions))

	for _, decision := range decisions {
		out = append(out, decision.Endpoint)
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

// ServeHTTP implements the http.Handler interface.
func (l *Logger) handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	// The recorder has to be in place before the handler runs, because the
	// decisions are made during it.
	recorder := &authz.Recorder{}

	// The recorder has to reach the handler, but r itself is left alone so that
	// everything read afterwards comes from the request as it arrived.
	capture := middleware.CaptureResponse(w, r.WithContext(authz.NewContext(r.Context(), recorder)), next)

	// Users and auditors care about things coming, going and changing, who did
	// those things and when?  Certainly not periodic polling that is par for the
	// course. Failures of reads may be indicative of someone trying to do
	// something they shouldn't via the API (or indeed a bug in a UI leeting them
	// attempt something they are forbidden to do).
	if r.Method == http.MethodGet {
		return
	}

	// If there is not accountibility e.g. a global call, it's not worth logging.
	info, err := authorization.FromContext(r.Context())
	if err != nil {
		return
	}

	decisions := recorder.Decisions()

	primaries := authz.Primaries(decisions)
	if len(primaries) == 0 {
		// A mutation that authorized something without saying what it was doing
		// cannot be described, and silence is the failure this exists to stop.
		// Report it as the defect it is rather than dropping the event.
		if len(decisions) > 0 {
			// Deliberately no operation.  The HTTP method is the obvious thing
			// to reach for here and it would be a lie: a POST to an action
			// sub-resource reads as a creation, so a failed rotation would be
			// reported as a create.  Naming the endpoints that were checked
			// says what is actually known, and no more.
			log.FromContext(r.Context()).Info("audit gap",
				"endpoints", checkedEndpoints(decisions),
				"result", &Result{Status: capture.StatusCode()},
				"reason", "no authorization decision described the request")
		}

		return
	}

	// One record per thing acted on, so a request touching several resources
	// does not collapse into one line naming only the first.
	for _, decision := range primaries {
		record := &Record{
			Timestamp: time.Now().UTC(),
			Component: &Component{
				Name:    l.application,
				Version: l.version,
			},
			Actor: &Actor{
				Subject: info.Userinfo.Sub,
			},
			Operation: &Operation{
				Verb: decision.Operation.Action,
			},
			Scope:    scope(decision),
			Resource: resource(capture, decision),
			Result: &Result{
				Status: capture.StatusCode(),
			},
			Client: getClient(r),
			Source: source(r),
			Grants: grants(decisions),
		}

		// The response is already written by the time we get here, because the
		// capture writes through, so a sink costs the client nothing.  See the
		// README's delivery section.
		for _, sink := range l.sinks {
			emit(r.Context(), sink, record)
		}
	}
}

func (l *Logger) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.handle(w, r, next)
	})
}
