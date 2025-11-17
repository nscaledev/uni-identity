/*
Copyright 2024-2025 the Unikorn Authors.

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
	"regexp"
	"strings"

	"github.com/getkin/kin-openapi/routers"

	"github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/middleware"
	"github.com/unikorn-cloud/core/pkg/server/v2/httputil"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

type Logger struct {
	// next defines the next HTTP handler in the chain.
	next http.Handler

	// openapi caches the Schema schema.
	openapi *openapi.Schema

	// application is the application name.
	application string

	// version is the application version.
	version string
}

// Ensure this implements the required interfaces.
var _ http.Handler = &Logger{}

// New returns an initialized middleware.
func New(next http.Handler, openapi *openapi.Schema, application, version string) *Logger {
	return &Logger{
		next:        next,
		openapi:     openapi,
		application: application,
		version:     version,
	}
}

// getResource will resolve to a resource type.
func getResource(w *middleware.Capture, r *http.Request, route *routers.Route, params map[string]string) *Resource {
	// Creates rely on the response containing the resource ID in the response metadata.
	if r.Method == http.MethodPost {
		// Nothing written, possibly a bug somewhere?
		if w.Body() == nil {
			return nil
		}

		var metadata struct {
			Metadata openapi.ResourceReadMetadata `json:"metadata"`
		}

		// Not a canonical API resource, possibly a bug somewhere?
		if err := json.Unmarshal(w.Body().Bytes(), &metadata); err != nil {
			return nil
		}

		segments := strings.Split(route.Path, "/")

		return &Resource{
			Type: segments[len(segments)-1],
			ID:   metadata.Metadata.Id,
		}
	}

	// Read, updates and deletes you can get the information from the route.
	matches := regexp.MustCompile(`/([^/]+)/{([^/}]+)}$`).FindStringSubmatch(route.Path)
	if matches == nil {
		return nil
	}

	return &Resource{
		Type: matches[1],
		ID:   params[matches[2]],
	}
}

// ServeHTTP implements the http.Handler interface.
func (l *Logger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, params, err := l.openapi.FindRoute(r)
	if err != nil {
		httputil.WriteErrorResponse(w, r, err)
		return
	}

	capture := middleware.CaptureResponse(w, r, l.next)

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

	// If there's no scope, then discard also.
	if len(params) == 0 {
		return
	}

	// If you cannot derive the resource, then discard.
	resource := getResource(capture, r, route, params)
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
		"scope", params,
		"resource", resource,
		"result", &Result{
			Status: capture.StatusCode(),
		},
	}

	log.FromContext(r.Context()).Info("audit", logParams...)
}

func Middleware(openapi *openapi.Schema, application, version string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return New(next, openapi, application, version)
	}
}
