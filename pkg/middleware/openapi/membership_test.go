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
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/openapi/helpers"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

const (
	membershipOrganizationID   = "ab4a9d8d-4b93-5deb-9c4f-a41de1728257"
	membershipUserID           = "cfb20806-c9a4-4ef7-8197-cd6731cd1dca"
	membershipServiceAccountID = "e46f44b1-dc70-4a57-84e5-fc3902f320ca"
	unknownGroupID             = "00000000-0000-0000-0000-000000000000"
)

// unknownGroupHandler answers the way the membership check does when a
// request names a group that is not in the organization.
func unknownGroupHandler(w http.ResponseWriter, r *http.Request) {
	errors.HandleError(w, r, errors.OAuth2InvalidRequest("group "+unknownGroupID+" does not exist in this organization"))
}

// membershipMux serves the real identity schema, with response validation
// and its panic on, so any status missing from the schema panics.
func membershipMux(t *testing.T) http.Handler {
	t.Helper()

	options := &openapi.Options{}

	flags := pflag.NewFlagSet("membership", pflag.ContinueOnError)
	options.AddFlags(flags)

	require.NoError(t, flags.Parse([]string{"--runtime-schema-validation=true", "--runtime-schema-validation-panic=true"}))

	schema, err := helpers.NewSchema(identityapi.GetSwagger)
	require.NoError(t, err)

	r := chi.NewRouter()
	r.Use(routeresolver.New(schema).Middleware)
	r.Use(openapi.NewValidator(options, benchmarkAuthorizer{}).Middleware)
	r.Post("/api/v1/organizations/{organizationID}/users", unknownGroupHandler)
	r.Put("/api/v1/organizations/{organizationID}/users/{userID}", unknownGroupHandler)
	r.Post("/api/v1/organizations/{organizationID}/serviceaccounts", unknownGroupHandler)
	r.Put("/api/v1/organizations/{organizationID}/serviceaccounts/{serviceAccountID}", unknownGroupHandler)

	return r
}

// TestUnknownGroupReturnsBadRequest checks that every route that adds members
// to groups declares the 400 the membership check returns for an unknown
// group. Without it, response validation panics and the client gets a 502
// (ID-543).
func TestUnknownGroupReturnsBadRequest(t *testing.T) {
	t.Parallel()

	userBody := `{"spec":{"subject":"joe@acme.com","state":"active","groupIDs":["` + unknownGroupID + `"]}}`
	serviceAccountBody := `{"metadata":{"name":"my-service-account"},"spec":{"groupIDs":["` + unknownGroupID + `"]}}`

	organizationPath := "/api/v1/organizations/" + membershipOrganizationID

	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"user create", http.MethodPost, organizationPath + "/users", userBody},
		{"user update", http.MethodPut, organizationPath + "/users/" + membershipUserID, userBody},
		{"service account create", http.MethodPost, organizationPath + "/serviceaccounts", serviceAccountBody},
		{"service account update", http.MethodPut, organizationPath + "/serviceaccounts/" + membershipServiceAccountID, serviceAccountBody},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			m := membershipMux(t)

			r := httptest.NewRequestWithContext(t.Context(), test.method, test.path, strings.NewReader(test.body))
			r.Header.Set("Content-Type", "application/json")
			addAuthorizationHeader(t, r)

			w := httptest.NewRecorder()

			require.NotPanics(t, func() { m.ServeHTTP(w, r) })
			require.Equal(t, http.StatusBadRequest, w.Code)
			require.Contains(t, validationErrorDescription(t, w), "does not exist in this organization")
		})
	}
}
