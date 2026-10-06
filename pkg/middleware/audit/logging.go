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
	"net/http"
	"strings"

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
}

// New returns an initialized middleware.
func New(application, version string) *Logger {
	return &Logger{
		application: application,
		version:     version,
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

// createdID recovers an identifier from the response body.
//
// This is the one fact a decision cannot supply: a create is authorized before
// the resource exists, so nothing knows its identifier until the handler has
// written the response.
func createdID(capture *middleware.Capture) string {
	if capture.Body() == nil {
		return ""
	}

	var body struct {
		Metadata openapi.ResourceReadMetadata `json:"metadata"`
	}

	if err := json.Unmarshal(capture.Body().Bytes(), &body); err != nil {
		return ""
	}

	return body.Metadata.Id
}

// resource describes what was acted on.
func resource(capture *middleware.Capture, decision authz.Decision) *Resource {
	out := &Resource{
		Type: resourceType(decision.Endpoint),
	}

	if decision.ObjectID != uuid.Nil {
		out.ID = decision.ObjectID.String()

		return out
	}

	out.ID = createdID(capture)

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
// gapReason separates a request that was turned away from one the handler
// failed to describe.  They need different fixes: the first is the system
// working and is recorded so a denial leaves a trace, the second is a missing
// call site.
func gapReason(decisions []authz.Decision, status int) string {
	if len(decisions) == 0 {
		if status >= http.StatusBadRequest {
			return "the request was refused or failed before any authorization decision was recorded"
		}

		return "the handler made no authorization decision"
	}

	return "no authorization decision described the request"
}

func checkedEndpoints(decisions []authz.Decision) []string {
	out := make([]string, 0, len(decisions))

	for _, decision := range decisions {
		out = append(out, decision.Endpoint)
	}

	return out
}

// ServeHTTP implements the http.Handler interface.
func (l *Logger) handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	// The recorder has to be in place before the handler runs, because the
	// decisions are made during it.
	recorder := &authz.Recorder{}
	r = r.WithContext(authz.NewContext(r.Context(), recorder))

	capture := middleware.CaptureResponse(w, r, next)

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
		// An authenticated mutation reached a handler and nothing described it.
		// Silence is the failure this exists to stop, so it is reported whether
		// or not anything was checked.  A refusal records no decision at all --
		// gates record only on success -- so guarding this on having decisions
		// would discard every denied mutation, which is the event an auditor
		// most wants to see.
		//
		// Deliberately no operation.  The HTTP method is the obvious thing to
		// reach for and it would be a lie: a POST to an action sub-resource
		// reads as a creation, so a refused rotation would be reported as a
		// create.  Naming the endpoints actually checked says what is known,
		// and no more.
		log.FromContext(r.Context()).Info("audit gap",
			"actor", &Actor{
				Subject: info.Userinfo.Sub,
			},
			"endpoints", checkedEndpoints(decisions),
			"result", &Result{Status: capture.StatusCode()},
			"reason", gapReason(decisions, capture.StatusCode()))

		return
	}

	// One record per thing acted on, so a request touching several resources
	// does not collapse into one line naming only the first.
	for _, decision := range primaries {
		log.FromContext(r.Context()).Info("audit",
			"component", &Component{
				Name:    l.application,
				Version: l.version,
			},
			"actor", &Actor{
				Subject: info.Userinfo.Sub,
			},
			"operation", &Operation{
				Verb: decision.Operation.Action,
			},
			"scope", scope(decision),
			"resource", resource(capture, decision),
			"result", &Result{
				Status: capture.StatusCode(),
			},
		)
	}
}

func (l *Logger) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.handle(w, r, next)
	})
}
