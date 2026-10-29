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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	coreapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/ids"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"

	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestOrganizationReadAndUpdateDeclareNotFound checks that the organization
// read and update declare the 404 they return for an organization that does
// not exist.  A caller can name an unknown organization, or reach a new one
// before the cache holds it.  Without the declaration, response validation
// panics and the server aborts the connection, which an ingress reports as a
// 502.
func TestOrganizationReadAndUpdateDeclareNotFound(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	client := organizations.New(fake.NewClientBuilder().WithScheme(scheme).Build(), "unikorn-identity")

	organizationID, err := ids.ParseOrganizationID(membershipOrganizationID)
	require.NoError(t, err)

	getHandler := func(w http.ResponseWriter, r *http.Request) {
		_, err := client.Get(r.Context(), organizationID)
		errors.HandleError(w, r, err)
	}

	updateHandler := func(w http.ResponseWriter, r *http.Request) {
		request := &identityapi.OrganizationWrite{}

		if err := json.NewDecoder(r.Body).Decode(request); err != nil {
			errors.HandleError(w, r, err)
			return
		}

		errors.HandleError(w, r, client.Update(r.Context(), organizationID, request))
	}

	tests := []struct {
		name    string
		method  string
		body    string
		handler http.HandlerFunc
	}{
		{"read", http.MethodGet, "", getHandler},
		{"update", http.MethodPut, `{"metadata":{"name":"acme"},"spec":{"organizationType":"adhoc"}}`, updateHandler},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			m := membershipMux(t, test.method, "/api/v1/organizations/{organizationID}", test.handler)

			var body io.Reader
			if test.body != "" {
				body = strings.NewReader(test.body)
			}

			r := httptest.NewRequestWithContext(t.Context(), test.method, "/api/v1/organizations/"+membershipOrganizationID, body)
			r.Header.Set("Content-Type", "application/json")
			addAuthorizationHeader(t, r)

			w := httptest.NewRecorder()

			require.NotPanics(t, func() { m.ServeHTTP(w, r) })
			require.Equal(t, http.StatusNotFound, w.Code)

			oauthError := &coreapi.Error{}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), oauthError))
			require.Equal(t, coreapi.NotFound, oauthError.Error)
		})
	}
}
