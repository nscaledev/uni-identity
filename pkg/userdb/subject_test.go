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

package userdb_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/userdb"
)

// TestNormalizeSubjectFoldsEmailCase pins the fix for the case mismatch that
// made a mixed-case record invisible to the bearer path: the trusted-issuer
// path folds the email claim (pkg/oauth2/auth0.validateEmail), so every writer
// and every claim-side lookup has to agree on the same folded form.
func TestNormalizeSubjectFoldsEmailCase(t *testing.T) {
	t.Parallel()

	require.Equal(t, "jw@aion.xyz", userdb.NormalizeSubject("JW@aion.xyz"))
	require.Equal(t, "haweso@wellingtoncollege.org.uk",
		userdb.NormalizeSubject("HAWESO@wellingtoncollege.org.uk"))
}

// TestNormalizeSubjectKeepsNonEmailCase pins the limit on the fold. Service
// users are created with kubectl-unikorn and their subjects are not email
// addresses, so they can be case sensitive. Folding one would change the
// identity that --system-account-roles-ids matches.
func TestNormalizeSubjectKeepsNonEmailCase(t *testing.T) {
	t.Parallel()

	require.Equal(t, "org-service", userdb.NormalizeSubject("org-service"))
	require.Equal(t, "CAPNS-Sys1-ICE2", userdb.NormalizeSubject("CAPNS-Sys1-ICE2"))
}

// TestNormalizeSubjectIsIdempotent pins that the fold can run on a value that
// is already folded. Every write path calls it, including updates to a record
// that an earlier run already normalized.
func TestNormalizeSubjectIsIdempotent(t *testing.T) {
	t.Parallel()

	once := userdb.NormalizeSubject("Mixed@Example.com")
	require.Equal(t, "mixed@example.com", once, "a no-op implementation must not satisfy this test")
	require.Equal(t, once, userdb.NormalizeSubject(once))
}

// TestNormalizeSubjectTrimsWhitespace pins that surrounding whitespace never
// reaches storage or a lookup key. The trusted-issuer path already trims the
// claim, so a writer that did not trim would store a subject that path can
// never match.
func TestNormalizeSubjectTrimsWhitespace(t *testing.T) {
	t.Parallel()

	require.Equal(t, "jw@aion.xyz", userdb.NormalizeSubject("  JW@aion.xyz\t"))
}

// TestNormalizeSubjectLeavesDisplayNameFormAlone pins the limit of the email
// test.  net/mail.ParseAddress accepts an RFC mailbox with a display name, so
// folding whatever it accepts would rewrite the name as well as the address and
// still not produce the bare address a claim carries.  Such a subject is left
// untouched rather than corrupted.
func TestNormalizeSubjectLeavesDisplayNameFormAlone(t *testing.T) {
	t.Parallel()

	require.Equal(t, `"Alice Smith" <Alice@Example.com>`,
		userdb.NormalizeSubject(`"Alice Smith" <Alice@Example.com>`))
	require.Equal(t, "<Bob@Example.com>", userdb.NormalizeSubject("<Bob@Example.com>"))
}
