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

package api_test

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/test/api"
)

// A run without a subject suffix would create users with new subjects, and identity never
// deletes a global user, so a deployed environment would grow by one record per created user.
func TestLoadTestConfigRequiresSubjectSuffix(t *testing.T) {
	// LoadTestConfig reads ../../.env; two empty levels keep any stray file out of reach.
	dir := filepath.Join(t.TempDir(), "a", "b")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	t.Chdir(dir)
	t.Setenv("IDENTITY_BASE_URL", "https://identity.example.com")
	t.Setenv("TEST_ORG_ID", "org")
	t.Setenv("TEST_PROJECT_ID", "project")
	t.Setenv("TEST_SUBJECT_SUFFIX", "")

	_, err := api.LoadTestConfig()
	require.ErrorContains(t, err, "TEST_SUBJECT_SUFFIX")
}

// Identity reuses the global user for a subject it has seen, so the same key and suffix must
// give the same subject, in the lower case identity stores, which is what the sweep matches.
func TestUserSubjectIsTheStoredForm(t *testing.T) {
	t.Parallel()

	config := &api.TestConfig{SubjectSuffix: "Nightly"}

	require.Equal(t, "users-create-nightly@example.com", api.UserSubject(config, "users-create"))
}

// A negative spec sends a create the API must refuse; only an accepted POST leaves an object
// behind, and only then is there an ID to delete.
func TestAcceptedCreateIDOnlyForAnAcceptedPost(t *testing.T) {
	t.Parallel()

	body := []byte(`{"metadata":{"id":"0b1c"}}`)

	require.Equal(t, "0b1c", api.AcceptedCreateID(http.MethodPost, &http.Response{StatusCode: http.StatusCreated}, body))
	require.Empty(t, api.AcceptedCreateID(http.MethodPost, &http.Response{StatusCode: http.StatusForbidden}, body))
	require.Empty(t, api.AcceptedCreateID(http.MethodPut, &http.Response{StatusCode: http.StatusOK}, body))
}
