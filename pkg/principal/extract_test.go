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

package principal_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/principal"
)

func encodePrincipal(t *testing.T, p *principal.Principal) string {
	t.Helper()

	data, err := json.Marshal(p)
	require.NoError(t, err)

	return base64.RawURLEncoding.EncodeToString(data)
}

func newRequest(t *testing.T, headers map[string]string) *http.Request {
	t.Helper()

	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example/v2/exchange", http.NoBody)
	require.NoError(t, err)

	for k, v := range headers {
		r.Header.Set(k, v)
	}

	return r
}

func TestExtractFromRequest_MissingHeaderReturnsErrHeader(t *testing.T) {
	t.Parallel()

	r := newRequest(t, nil)

	_, err := principal.ExtractFromRequest(t.Context(), r)

	require.Error(t, err)
	assert.ErrorIs(t, err, principal.ErrHeader, "expected ErrHeader, got %v", err)
}

func TestExtractFromRequest_ValidPrincipalWithoutImpersonate(t *testing.T) {
	t.Parallel()

	p := &principal.Principal{
		Actor:           "alice@example.com",
		OrganizationIDs: []string{"org-a", "org-b"},
		OrganizationID:  "org-a",
	}

	r := newRequest(t, map[string]string{
		principal.Header: encodePrincipal(t, p),
	})

	ctx, err := principal.ExtractFromRequest(t.Context(), r)
	require.NoError(t, err)

	got, err := principal.FromContext(ctx)
	require.NoError(t, err)
	assert.Equal(t, p.Actor, got.Actor)
	assert.Equal(t, p.OrganizationIDs, got.OrganizationIDs)
	assert.Equal(t, p.OrganizationID, got.OrganizationID)

	assert.False(t, principal.ImpersonateFromContext(ctx), "impersonation must not be set without header")
}

func TestExtractFromRequest_ImpersonateHeaderTrueSetsFlag(t *testing.T) {
	t.Parallel()

	p := &principal.Principal{Actor: "alice@example.com"}

	r := newRequest(t, map[string]string{
		principal.Header:            encodePrincipal(t, p),
		principal.ImpersonateHeader: "true",
	})

	ctx, err := principal.ExtractFromRequest(t.Context(), r)
	require.NoError(t, err)

	assert.True(t, principal.ImpersonateFromContext(ctx))
}

func TestExtractFromRequest_ImpersonateHeaderOtherValuesDoNotSetFlag(t *testing.T) {
	t.Parallel()

	p := &principal.Principal{Actor: "alice@example.com"}

	cases := []string{"false", "1", "TRUE", "", "yes"}

	for _, value := range cases {
		t.Run("value="+value, func(t *testing.T) {
			t.Parallel()

			r := newRequest(t, map[string]string{
				principal.Header:            encodePrincipal(t, p),
				principal.ImpersonateHeader: value,
			})

			ctx, err := principal.ExtractFromRequest(t.Context(), r)
			require.NoError(t, err)

			assert.False(t, principal.ImpersonateFromContext(ctx),
				"only literal 'true' should enable impersonation, got %q", value)
		})
	}
}

func TestExtractFromRequest_MalformedJSONInDecodedPrincipalReturnsError(t *testing.T) {
	t.Parallel()

	// Valid base64 but the decoded bytes aren't valid JSON.
	r := newRequest(t, map[string]string{
		principal.Header: base64.RawURLEncoding.EncodeToString([]byte("not-json")),
	})

	_, err := principal.ExtractFromRequest(t.Context(), r)

	require.Error(t, err)
	// Surface the JSON decode failure — caller treats any error from this
	// helper as a fail-closed signal.
	assert.NotErrorIs(t, err, principal.ErrHeader,
		"JSON decode error must not be reported as missing-header")
}

func TestExtractFromRequest_InvalidBase64WithoutClientCertFailsClosed(t *testing.T) {
	t.Parallel()

	// Non-base64 header falls through to the cert-verified fallback path.
	// Without a client cert header it must fail — critically, it must not
	// silently succeed or return an empty principal.
	r := newRequest(t, map[string]string{
		principal.Header: "!!not-base64!!",
	})

	_, err := principal.ExtractFromRequest(t.Context(), r)

	require.Error(t, err)
}
