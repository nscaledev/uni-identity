/*
Copyright 2022-2024 EscherCloud.
Copyright 2024-2025 the Unikorn Authors.
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

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/readiness"

	"k8s.io/utils/ptr"
)

func TestGetReadyz(t *testing.T) {
	t.Parallel()

	checker := readiness.New()
	h := &Handler{readiness: checker}

	w := httptest.NewRecorder()
	h.GetReadyz(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))

	var ready openapi.Readiness

	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &ready))
	require.Equal(t, openapi.Readiness{Ready: true}, ready)

	checker.Stopping()

	w = httptest.NewRecorder()
	h.GetReadyz(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusServiceUnavailable, w.Code)

	var notReady openapi.Readiness

	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &notReady))
	require.Equal(t, openapi.Readiness{Ready: false, Reason: ptr.To(readiness.ErrStopping.Error())}, notReady)
}
