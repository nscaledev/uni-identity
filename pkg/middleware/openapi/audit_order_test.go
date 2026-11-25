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

package openapi_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/go-chi/chi/v5"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/openapi/helpers"
	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	"github.com/unikorn-cloud/identity/pkg/middleware/audit"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

type auditSink struct {
	mu      sync.Mutex
	records []*audit.Record
}

func (s *auditSink) Emit(_ context.Context, record *audit.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records = append(s.records, record)
}

func (s *auditSink) all() []*audit.Record {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]*audit.Record(nil), s.records...)
}

var errACL = errors.New("acl lookup refused")

// refusingACLAuthorizer authenticates every caller, then fails the ACL lookup,
// so the validator refuses the request after it knows who made it.
type refusingACLAuthorizer struct{}

func (refusingACLAuthorizer) Authorize(*openapi3filter.AuthenticationInput) (*authorization.Info, error) {
	return authInfoFixture(identityapi.User), nil
}

func (refusingACLAuthorizer) GetACL(context.Context, string) (*identityapi.Acl, error) {
	return nil, errACL
}

// outermostAudit serves the real identity schema with audit outside the
// validator, the order where a request the validator rejects still reaches
// audit, and returns where its records land.
func outermostAudit(t *testing.T, authorizer openapi.Authorizer) (http.Handler, *auditSink) {
	t.Helper()

	schema, err := helpers.NewSchema(identityapi.GetSwagger)
	require.NoError(t, err)

	sink := &auditSink{}

	r := chi.NewRouter()
	r.Use(routeresolver.New(schema).Middleware)
	r.Use(audit.New("identity", "test", sink).Middleware)

	options := &openapi.Options{}

	flags := pflag.NewFlagSet("audit", pflag.ContinueOnError)
	options.AddFlags(flags)

	require.NoError(t, flags.Parse(nil))

	r.Use(openapi.NewValidator(options, authorizer).Middleware)
	r.Post("/api/v1/organizations/{organizationID}/groups", func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the handler must not run for a rejected request")
		w.WriteHeader(http.StatusInternalServerError)
	})

	return r, sink
}

const groupsPath = "/api/v1/organizations/" + membershipOrganizationID + "/groups"

const groupsRoute = "/api/v1/organizations/{organizationID}/groups"

// A request the validator rejects never reaches a handler, so nothing says
// what it attempted.  It is still recorded, with who made it, the route the
// server matched it to, and the outcome.
func TestValidatorRejectionIsAudited(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		authorizer openapi.Authorizer
		body       string
	}{
		{"invalid body", allowAllAuthorizer{}, `{"not":"a group"}`},
		{"acl lookup refused", refusingACLAuthorizer{}, `{"metadata":{"name":"group"},"spec":{}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			handler, sink := outermostAudit(t, test.authorizer)

			r := httptest.NewRequest(http.MethodPost, groupsPath, strings.NewReader(test.body))
			r.Header.Set("Content-Type", "application/json")
			addAuthorizationHeader(t, r)

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			require.GreaterOrEqual(t, w.Code, http.StatusBadRequest)

			records := sink.all()
			require.Len(t, records, 1)

			record := records[0]
			require.Equal(t, userActor, record.Actor.Subject)
			require.Equal(t, w.Code, record.Result.Status)
			require.Equal(t, http.MethodPost, record.Request.Method)
			require.Equal(t, groupsRoute, record.Request.Route)
			require.Nil(t, record.Operation, "nothing described the request, so no verb is invented")
		})
	}
}

// Without a caller there is nobody to hold to account, so an unauthenticated
// request is not recorded.
func TestUnauthenticatedRequestIsNotAudited(t *testing.T) {
	t.Parallel()

	handler, sink := outermostAudit(t, allowAllAuthorizer{})

	r := httptest.NewRequest(http.MethodPost, groupsPath, strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.GreaterOrEqual(t, w.Code, http.StatusBadRequest)
	require.Empty(t, sink.all())
}
