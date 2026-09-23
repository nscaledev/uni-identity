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

package v1alpha1

import (
	"net/mail"
	"slices"
	"strings"
)

// NormalizeSubject returns the canonical form of a subject.
//
// An email subject folds to lower case and loses surrounding whitespace. The
// trusted-issuer path folds the email claim before it resolves a user (see
// pkg/oauth2/auth0), so every comparison against a stored subject must agree
// on this one form.
//
// Only the ASCII letters A to Z fold. Unicode case mapping joins distinct
// addresses: strings.ToLower maps KELVIN SIGN (U+212A) to k, so a lookalike
// mailbox resolves another user's record. The chart check on binding subjects
// and the data migration also treat A to Z as the only letters that fold.
//
// A subject that net/mail does not parse as a bare address keeps its case, and
// loses only surrounding whitespace. Service users are created with
// kubectl-unikorn and their subjects are not addresses, so folding one can join
// two service identities that differ only in case. A mailbox with a display
// name or angle brackets is not a bare address either, so it keeps its case too.
//
// The function lives here, not in pkg/userdb, because GroupSpec.HasMemberByID
// needs it and pkg/userdb imports this package.
func NormalizeSubject(subject string) string {
	trimmed := strings.TrimSpace(subject)

	address, err := mail.ParseAddress(trimmed)
	if err != nil {
		return trimmed
	}

	// ParseAddress also accepts a mailbox with a display name or angle
	// brackets.  Folding one of those also rewrites the display name, and still
	// does not give the bare address that a claim carries, so only a bare
	// address folds.
	if address.Name != "" || address.Address != trimmed {
		return trimmed
	}

	return foldASCII(trimmed)
}

// foldASCII lower-cases the ASCII letters of s and leaves every other rune as
// it is.
func foldASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + ('a' - 'A')
		}

		return r
	}, s)
}

// equalFoldASCII reports whether a and b are equal when the ASCII letters of
// both fold.  It compares bytes, which is safe for UTF-8 because an ASCII byte
// never occurs inside a multi-byte rune.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range len(a) {
		x, y := a[i], b[i]

		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}

		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}

		if x != y {
			return false
		}
	}

	return true
}

// MatchSubject returns the index of the user that subject names, or -1, and
// whether the subject is ambiguous.
//
// An exact match wins. As a result, a lookup that matched before the canonical
// form existed still resolves to the same record, which is what makes a
// tolerant lookup safe to deploy ahead of the data migration.
//
// Failing an exact match, a single user whose subject has the same canonical form
// matches. That covers both halves of the migration window: a record not yet
// folded, looked up with a folded claim, and a folded record looked up with the
// raw claim.
//
// When there is no exact match and two or more users share the canonical form,
// a pick depends on list order. MatchSubject then reports ambiguous, and the
// caller must refuse rather than pick one. A subject that is empty after the
// trim matches nothing unless a stored subject is equal to it exactly.
func MatchSubject(users []User, subject string) (int, bool) {
	if index := slices.IndexFunc(users, func(user User) bool { return user.Spec.Subject == subject }); index >= 0 {
		return index, false
	}

	// An empty subject names nobody.  Without this, it folds to the same form
	// as a whitespace-only record and resolves it.
	canonical := NormalizeSubject(subject)
	if canonical == "" {
		return -1, false
	}

	trimmed := strings.TrimSpace(subject)
	index := -1

	for i := range users {
		stored := users[i].Spec.Subject

		// Two subjects with the same canonical form are also equal after the
		// trim with ASCII case ignored.  That test costs no allocation, so only
		// a candidate pays for the address parse in NormalizeSubject.
		if !equalFoldASCII(strings.TrimSpace(stored), trimmed) || NormalizeSubject(stored) != canonical {
			continue
		}

		if index >= 0 {
			return -1, true
		}

		index = i
	}

	return index, false
}
