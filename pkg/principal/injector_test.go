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

package principal //nolint:testpackage

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
)

func TestInjectorSetsPrincipalHeader(t *testing.T) {
	t.Parallel()

	ctx := NewContext(t.Context(), &Principal{
		OrganizationID: "org-1",
		ProjectID:      "proj-1",
		Actor:          "user@example.com",
	})

	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)

	err := Injector(nil, nil)(ctx, req)
	require.NoError(t, err)

	encoded := req.Header.Get(Header)
	require.NotEmpty(t, encoded)

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)

	decoded := &Principal{}
	require.NoError(t, json.Unmarshal(raw, decoded))

	assert.Equal(t, "org-1", decoded.OrganizationID)
	assert.Equal(t, "proj-1", decoded.ProjectID)
	assert.Equal(t, "user@example.com", decoded.Actor)
	assert.Empty(t, req.Header.Get("Authorization"))
}

func TestInjectorSetsPassportAuthorizationHeader(t *testing.T) {
	t.Parallel()

	ctx := NewContext(t.Context(), &Principal{Actor: "user@example.com"})
	ctx = authorization.NewContext(ctx, &authorization.Info{Passport: "passport-token"})

	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)

	err := Injector(nil, nil)(ctx, req)
	require.NoError(t, err)

	assert.Equal(t, "bearer passport-token", req.Header.Get("Authorization"))
}

func TestPrincipalOnlyInjectorDoesNotSetAuthorizationHeader(t *testing.T) {
	t.Parallel()

	ctx := NewContext(t.Context(), &Principal{Actor: "user@example.com"})
	ctx = authorization.NewContext(ctx, &authorization.Info{Passport: "passport-token"})

	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)

	err := PrincipalOnlyInjector(nil, nil)(ctx, req)
	require.NoError(t, err)

	assert.NotEmpty(t, req.Header.Get(Header))
	assert.Empty(t, req.Header.Get("Authorization"))
}
