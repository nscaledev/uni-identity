/*
Copyright 2025 the Unikorn Authors.
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

package userdb

import (
	"net/mail"
	"strings"
)

// NormalizeSubject returns the canonical storage and lookup form of a subject.
//
// An email subject folds to lower case. The trusted-issuer path folds the email
// claim before it resolves a user (see pkg/oauth2/auth0.validateEmail), so a
// record stored in any other case is invisible to that path: the holder is
// admitted as never onboarded and the inactive-user rejection cannot reach
// them.
//
// A subject that is not an email address keeps its case. Service users are
// created with kubectl-unikorn and their subjects are not addresses, so folding
// one would change the identity that --system-account-roles-ids matches.
//
// This is a writer-side and claim-side helper. Do not fold inside
// UserDatabase.GetUser: that lookup is first-match over an unordered list, so
// folding there would resolve non-deterministically while any case-variant
// records still exist.
func NormalizeSubject(subject string) string {
	trimmed := strings.TrimSpace(subject)

	address, err := mail.ParseAddress(trimmed)
	if err != nil {
		return trimmed
	}

	// ParseAddress also accepts a mailbox with a display name or angle
	// brackets.  Folding one of those would rewrite the display name too, and
	// would still not produce the bare address that a claim carries, so only a
	// bare address folds.
	if address.Name != "" || address.Address != trimmed {
		return trimmed
	}

	return strings.ToLower(trimmed)
}
