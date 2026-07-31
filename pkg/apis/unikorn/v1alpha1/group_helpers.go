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
	"slices"
)

// IdentityKey returns a comparable key for the principal a subject names.  A
// principal is identified by the issuer that authenticated it and its ID at
// that issuer.  Email is display data only — the handlers that write subjects
// populate it from different sources and it can differ between two records
// for the same principal — so it takes no part in identity.
func (s *GroupSubject) IdentityKey() string {
	return s.Issuer + "\x00" + s.ID
}

// Matches reports whether two subjects name the same principal.
func (s *GroupSubject) Matches(other GroupSubject) bool {
	return s.IdentityKey() == other.IdentityKey()
}

// HasSubject reports whether the group already lists a subject for the same
// principal.
func (s *GroupSpec) HasSubject(subject GroupSubject) bool {
	return slices.ContainsFunc(s.Subjects, subject.Matches)
}

// HasMember reports whether the group already confers its roles on the
// principal.  Either membership representation counts: RBAC resolves a
// principal's groups through the subject list and through the deprecated
// organization user ID list alike, so presence in one is enough for the
// principal to hold the roles already, and writing the other half confers
// nothing.
//
// An empty organization user ID matches nothing.  Membership lists are not
// validated against real records, so a junk empty entry must not stand in for
// a principal that has no organization user record yet.
func (s *GroupSpec) HasMember(organizationUserID string, subject GroupSubject) bool {
	if organizationUserID != "" && slices.Contains(s.UserIDs, organizationUserID) {
		return true
	}

	return s.HasSubject(subject)
}
