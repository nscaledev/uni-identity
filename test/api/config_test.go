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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/test/api"
)

// A run without a subject suffix would create users with new subjects, and identity never
// deletes a global user, so a deployed environment would grow by one record per created user.
func TestLoadTestConfigRequiresSubjectSuffix(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("IDENTITY_BASE_URL", "https://identity.example.com")
	t.Setenv("TEST_ORG_ID", "org")
	t.Setenv("TEST_PROJECT_ID", "project")
	t.Setenv("TEST_SUBJECT_SUFFIX", "")

	_, err := api.LoadTestConfig()
	require.ErrorContains(t, err, "TEST_SUBJECT_SUFFIX")
}
