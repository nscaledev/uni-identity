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

// IdentityKey returns a comparable key for deduplicating stored subject
// records: two records are the same stored fact only if they share the issuer
// that authenticated the principal and its ID at that issuer.  Email is display
// data only — writers populate it from different sources and it can differ
// between two records for the same principal — so it takes no part.  This is
// issuer-qualified on purpose; whether the group already confers its roles on a
// principal is a different question, answered ID-only by HasMemberByID to
// mirror how RBAC resolves membership.
func (s *GroupSubject) IdentityKey() string {
	return s.Issuer + "\x00" + s.ID
}

// HasMemberByID reports whether the group already confers its roles on the
// principal, matching subjects by ID alone.  This mirrors how RBAC actually
// resolves membership: its subject matching deliberately ignores the recorded
// issuer (see groupSubjectFilter in pkg/rbac), because subject records written
// before issuers were recorded carry an empty one and must still resolve.  A
// grant gate has to match the same way — a membership stored as a legacy
// record already confers the roles, so a write that re-states it confers
// nothing and must not read as an addition and be refused.  If RBAC matching
// ever becomes issuer-qualified, this must move with it.
//
// An empty organization user ID, and an empty subject ID, match nothing:
// membership lists are not validated against real records, so a junk empty
// entry must not stand in for a principal that has no record yet.
func (s *GroupSpec) HasMemberByID(organizationUserID, subjectID string) bool {
	if organizationUserID != "" && slices.Contains(s.UserIDs, organizationUserID) {
		return true
	}

	if subjectID == "" {
		return false
	}

	return slices.ContainsFunc(s.Subjects, func(subject GroupSubject) bool {
		return subject.ID == subjectID
	})
}
