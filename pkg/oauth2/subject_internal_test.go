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

package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/unikorn-cloud/identity/pkg/oauth2/oidc"
)

// TestNormalizeIDTokenSubjectFoldsTheClaimInPlace pins the ingress fold for the
// interactive path.  Callback resolves the user by this claim and stores the
// same token in the authorization code, so TokenAuthorizationCode and
// oidcIDToken read whatever this leaves behind.  Before the fold existed, a
// mixed-case claim missed a folded record and Callback answered access_denied.
func TestNormalizeIDTokenSubjectFoldsTheClaimInPlace(t *testing.T) {
	t.Parallel()

	idToken := &oidc.IDToken{}
	idToken.Email.Email = "  JW@Aion.xyz "

	normalizeIDTokenSubject(idToken)

	assert.Equal(t, "jw@aion.xyz", idToken.Email.Email)
}

// TestNormalizeIDTokenSubjectToleratesNoIDToken pins the guard the silent
// authorization path needs.  That path decodes a session cookie into a Code and
// folds the id_token it finds, and a decoded Code can carry none.
func TestNormalizeIDTokenSubjectToleratesNoIDToken(t *testing.T) {
	t.Parallel()

	assert.NotPanics(t, func() { normalizeIDTokenSubject(nil) })
}
