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

package oauth2

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRedirectorRaiseLogs checks that every error redirect writes one log line,
// with the error, its description and the client ID, and nothing secret.
func TestRedirectorRaiseLogs(t *testing.T) {
	t.Parallel()

	var lines []map[string]any

	logger := funcr.NewJSON(func(obj string) {
		var line map[string]any

		if err := json.Unmarshal([]byte(obj), &line); err == nil {
			lines = append(lines, line)
		}
	}, funcr.Options{})

	r := httptest.NewRequest(http.MethodGet, "/oauth2/v2/oidc/callback?code=secret-code&state=secret-state", nil)
	r = r.WithContext(logr.NewContext(r.Context(), logger))
	w := httptest.NewRecorder()

	newRedirector(w, r, "https://client.example.com/callback", "client-state", "my-client").raise(ErrorAccessDenied, "user not found")

	require.Equal(t, http.StatusFound, w.Code)

	location, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, string(ErrorAccessDenied), location.Query().Get("error"))
	assert.Equal(t, "user not found", location.Query().Get("error_description"))
	assert.Equal(t, "client-state", location.Query().Get("state"))

	require.Len(t, lines, 1)

	line := lines[0]

	assert.Equal(t, "oauth2: redirecting with error", line["msg"])
	assert.Equal(t, string(ErrorAccessDenied), line["error"])
	assert.Equal(t, "user not found", line["error_description"])
	assert.Equal(t, "my-client", line["client_id"])

	for _, v := range line {
		s, ok := v.(string)
		if !ok {
			continue
		}

		assert.NotContains(t, s, "secret-code")
		assert.NotContains(t, s, "secret-state")
		assert.NotContains(t, s, "client-state")
	}
}
