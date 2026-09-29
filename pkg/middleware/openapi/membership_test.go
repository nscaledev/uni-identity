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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/go-chi/chi/v5"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/openapi/helpers"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/middleware/routeresolver"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/users"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

const (
	membershipOrganizationID   = "ab4a9d8d-4b93-5deb-9c4f-a41de1728257"
	membershipUserID           = "cfb20806-c9a4-4ef7-8197-cd6731cd1dca"
	membershipServiceAccountID = "e46f44b1-dc70-4a57-84e5-fc3902f320ca"
	unknownGroupID             = "00000000-0000-0000-0000-000000000000"
)

// allowAllAuthorizer accepts every request, so tests exercise response
// handling only.
type allowAllAuthorizer struct{}

func (allowAllAuthorizer) Authorize(*openapi3filter.AuthenticationInput) (*authorization.Info, error) {
	return authInfoFixture(identityapi.User), nil
}

func (allowAllAuthorizer) GetACL(context.Context, string) (*identityapi.Acl, error) {
	return &identityapi.Acl{}, nil
}

// unknownGroupHandler answers with the error the membership check returns
// when a request names a group that is not in the organization.
func unknownGroupHandler(w http.ResponseWriter, r *http.Request) {
	errors.HandleError(w, r, common.ValidateGroupsExist([]string{unknownGroupID}, &unikornv1.GroupList{}))
}

// invalidSubjectHandler answers with the error user create returns for a
// subject that is not an email address.  The check runs before create
// touches Kubernetes, so no client is needed.
func invalidSubjectHandler(w http.ResponseWriter, r *http.Request) {
	request := &identityapi.UserWrite{}

	if err := json.NewDecoder(r.Body).Decode(request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	organizationID, err := ids.ParseOrganizationID(membershipOrganizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	_, err = users.New(nil, "", common.IssuerValue{}).Create(r.Context(), organizationID, request)
	errors.HandleError(w, r, err)
}

// membershipMux serves one route of the real identity schema, with response
// validation and its panic on, so any status missing from the schema panics.
func membershipMux(t *testing.T, method, pattern string, handler http.HandlerFunc) http.Handler {
	t.Helper()

	options := &openapi.Options{}

	flags := pflag.NewFlagSet("membership", pflag.ContinueOnError)
	options.AddFlags(flags)

	require.NoError(t, flags.Parse([]string{"--runtime-schema-validation=true", "--runtime-schema-validation-panic=true"}))

	schema, err := helpers.NewSchema(identityapi.GetSwagger)
	require.NoError(t, err)

	r := chi.NewRouter()
	r.Use(routeresolver.New(schema).Middleware)
	r.Use(openapi.NewValidator(options, allowAllAuthorizer{}).Middleware)
	r.Method(method, pattern, handler)

	return r
}

// TestMembershipWritesDeclareBadRequest checks that every route that calls
// common.ValidateGroupsExist declares the 400 it returns, as does user create
// for an invalid subject.  Without the declaration, response validation
// panics and the server aborts the connection, which an ingress reports as a
// 502.
func TestMembershipWritesDeclareBadRequest(t *testing.T) {
	t.Parallel()

	userBody := `{"spec":{"subject":"joe@acme.com","state":"active","groupIDs":["` + unknownGroupID + `"]}}`
	invalidSubjectBody := `{"spec":{"subject":"not-an-address","state":"active","groupIDs":[]}}`
	serviceAccountBody := `{"metadata":{"name":"my-service-account"},"spec":{"groupIDs":["` + unknownGroupID + `"]}}`

	const (
		usersPattern           = "/api/v1/organizations/{organizationID}/users"
		userPattern            = "/api/v1/organizations/{organizationID}/users/{userID}"
		serviceAccountsPattern = "/api/v1/organizations/{organizationID}/serviceaccounts"
		serviceAccountPattern  = "/api/v1/organizations/{organizationID}/serviceaccounts/{serviceAccountID}"
	)

	organizationPath := "/api/v1/organizations/" + membershipOrganizationID

	tests := []struct {
		name        string
		method      string
		pattern     string
		path        string
		body        string
		handler     http.HandlerFunc
		description string
	}{
		{"user create, unknown group", http.MethodPost, usersPattern, organizationPath + "/users", userBody, unknownGroupHandler, "does not exist in this organization"},
		{"user create, invalid subject", http.MethodPost, usersPattern, organizationPath + "/users", invalidSubjectBody, invalidSubjectHandler, "subject address invalid"},
		{"user update, unknown group", http.MethodPut, userPattern, organizationPath + "/users/" + membershipUserID, userBody, unknownGroupHandler, "does not exist in this organization"},
		{"service account create, unknown group", http.MethodPost, serviceAccountsPattern, organizationPath + "/serviceaccounts", serviceAccountBody, unknownGroupHandler, "does not exist in this organization"},
		{"service account update, unknown group", http.MethodPut, serviceAccountPattern, organizationPath + "/serviceaccounts/" + membershipServiceAccountID, serviceAccountBody, unknownGroupHandler, "does not exist in this organization"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			m := membershipMux(t, test.method, test.pattern, test.handler)

			r := httptest.NewRequestWithContext(t.Context(), test.method, test.path, strings.NewReader(test.body))
			r.Header.Set("Content-Type", "application/json")
			addAuthorizationHeader(t, r)

			w := httptest.NewRecorder()

			require.NotPanics(t, func() { m.ServeHTTP(w, r) })
			require.Equal(t, http.StatusBadRequest, w.Code)
			require.Contains(t, validationErrorDescription(t, w), test.description)
		})
	}
}
