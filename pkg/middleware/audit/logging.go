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

	"github.com/getkin/kin-openapi/routers"

	"github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/middleware"
	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/rbac"

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

// getResource identifies the resource an audited request acted on for the
// audit record: its kind — authoritative, the kind the handler passed to
// Allow*, read back from the decision accumulator — and its instance id,
// from the request. Returns nil only when neither can be determined
// (nothing worth logging).
func getResource(capture *middleware.Capture, r *http.Request, route *routers.Route, params map[string]string, decisions []rbac.Decision) *Resource {
	kind := primaryKind(decisions)
	id := resourceID(capture, r, route, params)

	if kind == "" && id == "" {
		return nil
	}

	return &Resource{Type: kind, ID: id}
}

// resourceID returns the id of the instance a request addressed. For a
// create — a POST carrying a request body (unlike a body-less x-no-body
// action such as rotate) to a collection (its path ends in a literal
// segment, not an instance {parameter}) — the new id is only in the
// response body, so it is read from there and is empty on a failed or
// non-canonical create. It deliberately does NOT fall back to the last path
// parameter for a create: that parameter is the PARENT collection's id (e.g.
// the organization id), and stamping it as the created resource's id would
// misattribute the record — a denied group create would be logged against the
// organization id. Every other audited op (read, update, delete, and
// body-less actions like rotate) addresses an existing instance by its last
// path parameter.
func resourceID(capture *middleware.Capture, r *http.Request, route *routers.Route, params map[string]string) string {
	if r.Method == http.MethodPost && route.Operation != nil && route.Operation.RequestBody != nil && !strings.HasSuffix(route.Path, "}") {
		return createdResourceID(capture)
	}

	return lastPathParamValue(route.Path, params)
}

// primaryKind returns the authoritative resource kind for the audited
// request — the kind the handler passed to Allow* (e.g.
// "identity:serviceaccounts"), read back from the decision accumulator. An
// audited request (a mutation or a sensitive read) makes a single scope
// check, so its sole decision names the resource; the loop takes the last
// non-empty kind defensively should a handler ever make more. "" when the
// handler made no Allow* call.
func primaryKind(decisions []rbac.Decision) string {
	kind := ""

	for _, d := range decisions {
		if d.ResourceKind != "" {
			kind = d.ResourceKind
		}
	}

	return kind
}

// lastPathParamValue returns the value of the last {param} in a path
// template — the most specific resource the URL addresses — by walking
// segments from the end and resolving the first placeholder against params.
// "" if the path has none (a collection or singleton).
func lastPathParamValue(routePath string, params map[string]string) string {
	segments := strings.Split(routePath, "/")

	for i := len(segments) - 1; i >= 0; i-- {
		segment := segments[i]
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			return params[strings.Trim(segment, "{}")]
		}
	}

	return ""
}

// createdResourceID reads a freshly-created resource's id from a create
// response's canonical metadata. "" if the body is not a canonical resource
// (empty, or a non-resource payload), so the caller can fall back to the URL.
func createdResourceID(capture *middleware.Capture) string {
	var body struct {
		Metadata openapi.ResourceReadMetadata `json:"metadata"`
	}

	if err := json.Unmarshal(capture.Body().Bytes(), &body); err != nil {
		return ""
	}

	return body.Metadata.Id
}

// sensitiveAuditExtension is the OpenAPI operation extension a spec uses to
// opt an otherwise-routine read into audit logging: x-unikorn-audit:
// sensitive. Declarative and central — each consumer marks its own
// sensitive reads (e.g. console URLs, credentials/kubeconfig, SSH keys) in
// its own spec; this middleware only needs to look for the one key.
const (
	sensitiveAuditExtension      = "x-unikorn-audit"
	sensitiveAuditExtensionValue = "sensitive"
)

// isSensitiveRead reports whether route is marked x-unikorn-audit:
// sensitive, opting an otherwise-skipped GET into the same logging a
// mutation gets below.
func isSensitiveRead(route *routers.Route) bool {
	if route == nil || route.Operation == nil {
		return false
	}

	value, ok := route.Operation.Extensions[sensitiveAuditExtension].(string)

	return ok && value == sensitiveAuditExtensionValue
}

// newDecisions converts the rbac accumulator's entries to this package's
// own DTO, mirroring Resource/Operation/etc.: the audit record's shape
// stays decoupled from pkg/rbac's internal type.
func newDecisions(accumulated []rbac.Decision) []Decision {
	decisions := make([]Decision, len(accumulated))

	for i, d := range accumulated {
		decisions[i] = Decision{
			ResourceKind: d.ResourceKind,
			ResourceID:   d.ResourceID,
			Action:       d.Action,
			Decision:     d.Decision,
			Reason:       d.Reason,
		}
	}

	return decisions
}

// isRoutineRead reports whether a request is a routine read — a GET that is not
// a marked sensitive read (x-unikorn-audit: sensitive), or a GET whose route
// did not resolve. Users and auditors care about things coming, going and
// changing (who did what, and when), not periodic polling that is par for the
// course; but a failed read may indicate someone probing the API, so a spec
// opts specific reads (console URLs, credentials/kubeconfig, SSH keys) into
// logging via the sensitive marker. A routine read is neither seeded a decision
// accumulator nor logged; every mutation and every sensitive read is. A GET
// whose route did not resolve is treated as routine here — the mutation case
// that must surface a resolution failure is handled separately (the
// errors.HandleError call in handle).
func isRoutineRead(method string, route *routeresolver.RouteInfo, routeErr error) bool {
	if method != http.MethodGet {
		return false
	}

	return routeErr != nil || !isSensitiveRead(route.Route)
}

// ServeHTTP implements the http.Handler interface.
func (l *Logger) handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	// The route is resolved pre-routing (server.go wires routeresolver ahead of
	// this middleware), so it is available here, BEFORE next.
	route, routeErr := routeresolver.FromContext(r.Context())

	routineRead := isRoutineRead(r.Method, route, routeErr)

	// F2: seed the request-scoped decision accumulator (pkg/rbac) BEFORE
	// calling next, so any Allow* dispatch the handler chain performs appends
	// to it (read back below). Skip it for a routine read — which is never
	// audited (the early return below), so seeding would only make the
	// handler's Allow* calls do mutex-guarded appends nothing ever reads.
	if !routineRead {
		r = r.WithContext(rbac.NewDecisionAccumulatorContext(r.Context()))
	}

	capture := middleware.CaptureResponse(w, r, next)

	if routineRead {
		return
	}

	// If there is not accountibility e.g. a global call, it's not worth logging.
	info, err := authorization.FromContext(r.Context())
	if err != nil {
		return
	}

	if routeErr != nil {
		errors.HandleError(w, r, routeErr)
		return
	}

	// If there's no scope, then discard also.
	if len(route.Parameters) == 0 {
		return
	}

	decisions := rbac.DecisionsFromContext(r.Context())

	// If you cannot derive the resource, then discard.
	resource := getResource(capture, r, route.Route, route.Parameters, decisions)
	if resource == nil {
		return
	}

	logParams := []any{
		"component", &Component{
			Name:    l.application,
			Version: l.version,
		},
		"actor", &Actor{
			Subject: info.Userinfo.Sub,
		},
		"operation", &Operation{
			Verb: r.Method,
		},
		"scope", route.Parameters,
		"resource", resource,
		"result", &Result{
			Status: capture.StatusCode(),
		},
		"decisions", newDecisions(decisions),
	}

	log.FromContext(r.Context()).Info("audit", logParams...)
}

func (l *Logger) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.handle(w, r, next)
	})
}
