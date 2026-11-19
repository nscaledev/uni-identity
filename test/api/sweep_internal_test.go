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

package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The sweep must recognise every name a spec gives a test object, including after an update
// spec renames it, and must never match a standing fixture.
func TestIsTestObjectNameMatchesUniqueNamesOnly(t *testing.T) {
	t.Parallel()

	name := uniqueName("test-group")

	require.True(t, isTestObjectName(name))
	require.True(t, isTestObjectName(name+"-updated"))
	require.False(t, isTestObjectName("identity-api-tests-admin"))
}

// A cancelled run leaves its users behind, and identity returns an existing membership
// unchanged on create, so the sweep must remove them; the standing fixture user stays.
func TestIsTestUserSubjectMatchesTheRunSuffixOnly(t *testing.T) {
	t.Parallel()

	config := &TestConfig{SubjectSuffix: "nightly"}

	require.True(t, isTestUserSubject(config, UserSubject(config, "users-create")))
	require.False(t, isTestUserSubject(config, "identity-api-tests-user@nscale.test"))
}

// The rename spec appends "-updated" to whatever name it reads, so every killed run adds one.
func TestOriginalOrganizationNameStripsEveryRename(t *testing.T) {
	t.Parallel()

	require.Equal(t, "QA2UAT", originalOrganizationName("QA2UAT-updated-updated"))
}
