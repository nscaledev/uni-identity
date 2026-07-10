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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/local"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/mock"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// These tests pin the A6 decision-engine crossing: the middleware seeds the
// Cerbos-capable engine into the handler context when — and only when — its
// Authorizer optionally implements DecisionEngineProvider with a non-nil
// engine.  The assertion (instead of widening Authorizer) is the point: the
// generated mock and any external implementer keep compiling untouched, and
// their requests structurally take the legacy path.

// The local authorizer is the production provider today; remote gains the
// interface with A8.
var _ openapi.DecisionEngineProvider = (*local.Authorizer)(nil)

// providerAuthorizer wraps an Authorizer with a decision engine.
type providerAuthorizer struct {
	openapi.Authorizer

	engine *rbac.RBAC
}

func (p *providerAuthorizer) DecisionEngine() *rbac.RBAC {
	return p.engine
}

// engineRecordingHandler records the decision engine (or its absence) seen
// by the request context that reaches the handler.
type engineRecordingHandler struct {
	called bool
	engine *rbac.RBAC
}

func (h *engineRecordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
	h.engine = rbac.EngineFromContext(r.Context())

	w.WriteHeader(http.StatusOK)
}

// getEngineMux mirrors getMux for an arbitrary terminal handler.
func getEngineMux(t *testing.T, authorizer openapi.Authorizer, next http.Handler) http.Handler {
	t.Helper()

	options := &openapi.Options{
		ACLCacheSize:    1,
		ACLCacheTimeout: time.Minute,
	}

	resolver := routeresolver.New(getSchema(t))
	validator := openapi.NewValidator(options, authorizer)

	r := chi.NewRouter()
	r.Use(resolver.Middleware)
	r.Use(validator.Middleware)
	r.Get("/protected", next.ServeHTTP)

	return r
}

// engineActor deliberately differs from openapi_test.go's userActor so the
// shared authInfoFixture keeps a genuinely variable actor parameter.
const engineActor = "engine@acme.com"

// serveAuthenticated drives one authenticated bearer-token request through
// the middleware and returns what the handler observed.
func serveAuthenticated(t *testing.T, authorizer openapi.Authorizer) *engineRecordingHandler {
	t.Helper()

	h := &engineRecordingHandler{}
	m := getEngineMux(t, authorizer, h)

	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authenticatedURL, nil)
	require.NoError(t, err)

	addAuthorizationHeader(t, r)

	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Result().StatusCode)
	require.True(t, h.called)

	return h
}

func TestDecisionEngineSeededFromProvider(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().Authorize(gomock.Any()).Return(authInfoFixture(engineActor, identityapi.User), nil)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Return(&identityapi.Acl{}, nil)

	engine := rbac.New(nil, "", &rbac.Options{})

	h := serveAuthenticated(t, &providerAuthorizer{Authorizer: authorizer, engine: engine})

	require.Same(t, engine, h.engine, "the provider's engine must be seeded into the handler context")
}

func TestDecisionEngineNotSeededWithoutProvider(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	// The plain generated mock does not implement DecisionEngineProvider —
	// exactly like every pre-A6 downstream authorizer.
	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().Authorize(gomock.Any()).Return(authInfoFixture(engineActor, identityapi.User), nil)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Return(&identityapi.Acl{}, nil)

	h := serveAuthenticated(t, authorizer)

	require.Nil(t, h.engine, "without a provider the context must stay engine-free (legacy path)")
}

func TestDecisionEngineNotSeededWhenProviderReturnsNil(t *testing.T) {
	t.Parallel()

	c := gomock.NewController(t)
	defer c.Finish()

	authorizer := mock.NewMockAuthorizer(c)
	authorizer.EXPECT().Authorize(gomock.Any()).Return(authInfoFixture(engineActor, identityapi.User), nil)
	authorizer.EXPECT().GetACL(gomock.Any(), gomock.Any()).Return(&identityapi.Acl{}, nil)

	h := serveAuthenticated(t, &providerAuthorizer{Authorizer: authorizer})

	require.Nil(t, h.engine, "a nil engine must not be seeded")
}
