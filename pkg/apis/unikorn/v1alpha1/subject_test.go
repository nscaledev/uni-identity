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

package v1alpha1_test

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
)

// TestNormalizeSubjectFoldsEmailCase pins the canonical form. The trusted-issuer
// path folds the email claim before it resolves a user, so every comparison
// against a stored subject must agree on this one form.
func TestNormalizeSubjectFoldsEmailCase(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "jw@aion.xyz", unikornv1.NormalizeSubject("JW@aion.xyz"))
	assert.Equal(t, "haweso@wellingtoncollege.org.uk",
		unikornv1.NormalizeSubject("HAWESO@wellingtoncollege.org.uk"))
}

// TestNormalizeSubjectKeepsNonEmailCase pins the limit of the fold. Service users
// are created with kubectl-unikorn and are not email addresses, so they can be
// case sensitive. Folding one can join two service identities that differ only
// in case.
func TestNormalizeSubjectKeepsNonEmailCase(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "org-service", unikornv1.NormalizeSubject("org-service"))
	assert.Equal(t, "CAPNS-Sys1-ICE2", unikornv1.NormalizeSubject("CAPNS-Sys1-ICE2"))
}

// TestNormalizeSubjectIsIdempotent pins that folding a folded value changes
// nothing, and asserts the canonical value so that a no-op cannot pass.
func TestNormalizeSubjectIsIdempotent(t *testing.T) {
	t.Parallel()

	once := unikornv1.NormalizeSubject("Mixed@Example.com")
	assert.Equal(t, "mixed@example.com", once)
	assert.Equal(t, once, unikornv1.NormalizeSubject(once))
}

// TestNormalizeSubjectTrimsWhitespace pins that surrounding whitespace never
// reaches a comparison. The trusted-issuer path trims the claim as well.
func TestNormalizeSubjectTrimsWhitespace(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "jw@aion.xyz", unikornv1.NormalizeSubject("  JW@aion.xyz\t"))
}

// TestNormalizeSubjectLeavesDisplayNameFormAlone pins that only a bare address
// folds. net/mail.ParseAddress accepts a mailbox with a display name or angle
// brackets. Folding one rewrites the display name and still does not give the
// bare address that a claim carries, so the value keeps its case after the trim.
func TestNormalizeSubjectLeavesDisplayNameFormAlone(t *testing.T) {
	t.Parallel()

	assert.Equal(t, `"Alice Smith" <Alice@Example.com>`,
		unikornv1.NormalizeSubject(`"Alice Smith" <Alice@Example.com>`))
	assert.Equal(t, "<Bob@Example.com>", unikornv1.NormalizeSubject(" <Bob@Example.com> "))
}

// TestNormalizeSubjectFoldsASCIILettersOnly pins that Unicode case mapping takes
// no part. strings.ToLower maps KELVIN SIGN (U+212A) to k and U+0130 to i, so a
// Unicode fold joins a lookalike mailbox to a different user's record.
func TestNormalizeSubjectFoldsASCIILettersOnly(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "\u212aim@x.com", unikornv1.NormalizeSubject("\u212aim@X.com"))
	assert.Equal(t, "\u0130nfo@x.com", unikornv1.NormalizeSubject("\u0130nfo@X.com"))
}

func users(subjects ...string) []unikornv1.User {
	out := make([]unikornv1.User, len(subjects))
	for i, subject := range subjects {
		out[i].Spec.Subject = subject
	}

	return out
}

// TestMatchSubjectPrefersAnExactMatch pins the property that makes a tolerant
// lookup safe to deploy: any lookup that matched before still resolves to the same
// record. With two records that differ only in case, each case finds its own.
func TestMatchSubjectPrefersAnExactMatch(t *testing.T) {
	t.Parallel()

	list := users("JW@aion.xyz", "jw@aion.xyz")

	index, ambiguous := unikornv1.MatchSubject(list, "JW@aion.xyz")
	require.False(t, ambiguous)
	assert.Equal(t, 0, index)

	index, ambiguous = unikornv1.MatchSubject(list, "jw@aion.xyz")
	require.False(t, ambiguous)
	assert.Equal(t, 1, index)
}

// TestMatchSubjectAcceptsEitherStoredForm pins the migration window. A stored
// record and a claim can each be in either case until the data migration
// completes, so every combination must resolve the one record.
func TestMatchSubjectAcceptsEitherStoredForm(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name, stored, query string
	}{
		{name: "unmigrated record, folded claim", stored: "JW@aion.xyz", query: "jw@aion.xyz"},
		{name: "migrated record, raw claim", stored: "jw@aion.xyz", query: "JW@aion.xyz"},
		{name: "migrated record, folded claim", stored: "jw@aion.xyz", query: "jw@aion.xyz"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			index, ambiguous := unikornv1.MatchSubject(users("someone@example.com", tt.stored), tt.query)
			require.False(t, ambiguous)
			assert.Equal(t, 1, index)
		})
	}
}

// TestMatchSubjectRefusesAnAmbiguousFold pins the ambiguity rule. The lookup is
// first-match over an unordered list. When no record matches exactly and two fold
// to the same form, a pick depends on list order, so the caller must refuse.
func TestMatchSubjectRefusesAnAmbiguousFold(t *testing.T) {
	t.Parallel()

	index, ambiguous := unikornv1.MatchSubject(users("JW@aion.xyz", "Jw@aion.xyz"), "jw@aion.xyz")
	assert.True(t, ambiguous)
	assert.Equal(t, -1, index)
}

// TestMatchSubjectReportsNotFound pins the plain miss, which callers keep mapping
// to their existing not-found errors.
func TestMatchSubjectReportsNotFound(t *testing.T) {
	t.Parallel()

	index, ambiguous := unikornv1.MatchSubject(users("someone@example.com"), "nobody@example.com")
	assert.False(t, ambiguous)
	assert.Equal(t, -1, index)
}

// TestMatchSubjectKeepsServiceSubjectsExact pins that a subject which is not an
// email address never matches another case, because it is never folded.
func TestMatchSubjectKeepsServiceSubjectsExact(t *testing.T) {
	t.Parallel()

	index, ambiguous := unikornv1.MatchSubject(users("org-service"), "ORG-SERVICE")
	assert.False(t, ambiguous)
	assert.Equal(t, -1, index)
}

// TestMatchSubjectDoesNotJoinALookalike pins the ASCII-only fold at the lookup.
// The query uses KELVIN SIGN in place of K. It names a different mailbox, so it
// must not resolve kim's record.
func TestMatchSubjectDoesNotJoinALookalike(t *testing.T) {
	t.Parallel()

	index, ambiguous := unikornv1.MatchSubject(users("kim@x.com"), "\u212aim@x.com")
	assert.Equal(t, -1, index)
	assert.False(t, ambiguous)
}

// TestMatchSubjectMatchesNothingForAnEmptySubject pins the guard that
// HasMemberByID also has. An empty claim folds to the same canonical form as a
// whitespace-only record, and must not resolve it.
func TestMatchSubjectMatchesNothingForAnEmptySubject(t *testing.T) {
	t.Parallel()

	index, ambiguous := unikornv1.MatchSubject(users("  "), "")
	assert.Equal(t, -1, index)
	assert.False(t, ambiguous)
}

// TestMatchSubjectMissDoesNotParseEveryRecord pins the cost of a miss. A token
// exchange for an identity with no record misses on every call, and each miss
// scans every user. Parsing every stored subject as an address costs several
// times the cached list that comes before the scan.
//
//nolint:paralleltest // AllocsPerRun counts allocations for the whole process, and panics in a parallel test.
func TestMatchSubjectMissDoesNotParseEveryRecord(t *testing.T) {
	subjects := make([]string, 1000)
	for i := range subjects {
		subjects[i] = "user" + strconv.Itoa(i) + "@example.com"
	}

	list := users(subjects...)

	allocs := testing.AllocsPerRun(10, func() {
		unikornv1.MatchSubject(list, "Nobody@Example.com")
	})

	assert.Less(t, allocs, float64(50), "a miss must not parse every stored subject")
}

// TestHasMemberByIDMatchesEitherStoredForm pins the grant gates through the
// migration. A group entry can be stored in either case, and a membership that
// already confers the roles must not read as an addition and be refused.
func TestHasMemberByIDMatchesEitherStoredForm(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name, stored, query string
	}{
		{name: "unmigrated entry, folded subject", stored: "JW@aion.xyz", query: "jw@aion.xyz"},
		{name: "migrated entry, raw subject", stored: "jw@aion.xyz", query: "JW@aion.xyz"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			spec := unikornv1.GroupSpec{Subjects: []unikornv1.GroupSubject{{ID: tt.stored}}}
			assert.True(t, spec.HasMemberByID("", tt.query))
		})
	}
}

// TestHasMemberByIDStillMatchesNothingForAnEmptySubject pins the existing
// contract: a junk empty entry must not stand in for a principal.
func TestHasMemberByIDStillMatchesNothingForAnEmptySubject(t *testing.T) {
	t.Parallel()

	spec := unikornv1.GroupSpec{Subjects: []unikornv1.GroupSubject{{ID: ""}}}
	assert.False(t, spec.HasMemberByID("", ""))
}
