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

package passport //nolint:testpackage

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExchangeClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		status    int
		body      string
		options   *exchangeOptions
		expectErr error
		contains  string
	}{
		{
			name:   "returns exchanged passport on success",
			status: http.StatusOK,
			body:   `{"access_token":"passport-token"}`,
			options: &exchangeOptions{
				organizationID: "org-1",
				projectID:      "proj-1",
			},
		},
		{
			name:      "returns unauthorized sentinel on 401",
			status:    http.StatusUnauthorized,
			body:      `{"error":"access_denied"}`,
			expectErr: ErrExchangeUnauthorized,
		},
		{
			name:      "returns unavailable sentinel on 503",
			status:    http.StatusServiceUnavailable,
			body:      `{"error":"server_error"}`,
			expectErr: ErrExchangeUnavailable,
		},
		{
			name:     "returns error on malformed success body",
			status:   http.StatusOK,
			body:     `{"access_token":`,
			contains: "token exchange invalid response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !assert.NoError(t, r.ParseForm()) {
					w.WriteHeader(http.StatusBadRequest)

					return
				}

				assert.Equal(t, tokenExchangeGrantType, r.Form.Get("grant_type"))
				assert.Equal(t, tokenExchangeSubjectToken, r.Form.Get("subject_token_type"))
				assert.Equal(t, tokenExchangeRequestedPassport, r.Form.Get("requested_token_type"))
				assert.Equal(t, "raw-token", r.Form.Get("subject_token"))

				if tt.options != nil {
					assert.Equal(t, tt.options.organizationID, r.Form.Get("organizationId"))
					assert.Equal(t, tt.options.projectID, r.Form.Get("projectId"))
				}

				w.WriteHeader(tt.status)
				_, err := fmt.Fprint(w, tt.body)
				assert.NoError(t, err)
			}))
			defer server.Close()

			client := newExchangeClient(server.Client(), server.URL)
			passport, err := client.Exchange(t.Context(), "raw-token", tt.options)

			if tt.expectErr != nil || tt.contains != "" {
				require.Error(t, err)

				if tt.expectErr != nil {
					require.ErrorIs(t, err, tt.expectErr)
				}

				if tt.contains != "" {
					assert.Contains(t, err.Error(), tt.contains)
				}

				return
			}

			require.NoError(t, err)
			assert.Equal(t, "passport-token", passport)
		})
	}
}

func TestExchangeClientTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, err := fmt.Fprint(w, `{"access_token":"passport-token"}`)
		assert.NoError(t, err)
	}))
	defer server.Close()

	httpClient := server.Client()
	httpClient.Timeout = 10 * time.Millisecond

	client := newExchangeClient(httpClient, server.URL)
	_, err := client.Exchange(t.Context(), "raw-token", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrExchangeUnavailable)
}
