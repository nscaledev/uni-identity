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

package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/cachetest"
	"github.com/unikorn-cloud/identity/pkg/handler"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func newOrganizationsHandler(t *testing.T) *handler.Handler {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	store := cachetest.New(t, scheme, &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "identity",
			Name:      "id-1",
			Labels:    map[string]string{constants.NameLabel: "alpha"},
		},
	})

	h, err := handler.New(store.Client(), nil, "identity", nil, nil, nil, nil, &handler.Options{})
	require.NoError(t, err)

	return h
}

func TestGetApiV1OrganizationsDeprecationHeaders(t *testing.T) {
	t.Parallel()

	t.Run("success exposes the headers", func(t *testing.T) {
		t.Parallel()

		ctx := rbac.NewContext(t.Context(), &openapi.Acl{
			Global: &openapi.AclEndpoints{
				{Name: "identity:organizations", Operations: openapi.AclOperations{openapi.Read}},
			},
		})

		w := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/organizations", nil)

		newOrganizationsHandler(t).GetApiV1Organizations(w, r, openapi.GetApiV1OrganizationsParams{})

		require.Equal(t, http.StatusOK, w.Code)
		require.NotEmpty(t, w.Header().Get("Deprecation"))
		require.NotEmpty(t, w.Header().Get("Link"))
		require.Equal(t, "Deprecation, Link", w.Header().Get("Access-Control-Expose-Headers"))

		var result openapi.Organizations

		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		require.Len(t, result, 1)
		require.Equal(t, "id-1", result[0].Metadata.Id)
		require.Equal(t, "alpha", result[0].Metadata.Name)
	})

	t.Run("error sets none of the headers", func(t *testing.T) {
		t.Parallel()

		// An empty ACL and no principal, so the lister fails.
		ctx := rbac.NewContext(t.Context(), &openapi.Acl{})

		w := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/organizations", nil)

		newOrganizationsHandler(t).GetApiV1Organizations(w, r, openapi.GetApiV1OrganizationsParams{})

		require.Equal(t, http.StatusInternalServerError, w.Code)
		require.Empty(t, w.Header().Get("Deprecation"))
		require.Empty(t, w.Header().Get("Link"))
		require.Empty(t, w.Header().Get("Access-Control-Expose-Headers"))
	})
}
