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

package server

import (
	"reflect"
	"testing"

	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/rbac"
)

// TestExpandBareAdminSubjects covers the legacy-compatibility mirroring of
// bare (UNI-sentinel) platform-admin entries onto the deprecated
// auth0-exchange issuer. The runtime match compares issuers exactly, so the
// mirror copies the flag issuer verbatim.
func TestExpandBareAdminSubjects(t *testing.T) {
	t.Parallel()

	const legacyIssuer = "https://legacy.auth0.com/"

	bare := rbac.PlatformAdministratorSubject{Issuer: constants.UNISentinel, Subject: "admin@nscale.com"}
	mirrored := rbac.PlatformAdministratorSubject{Issuer: legacyIssuer, Subject: "admin@nscale.com"}
	qualified := rbac.PlatformAdministratorSubject{Issuer: "https://staff.auth0.com/", Subject: "staff@nscale.com"}

	cases := []struct {
		name         string
		subjects     []rbac.PlatformAdministratorSubject
		legacyIssuer string
		want         []rbac.PlatformAdministratorSubject
	}{
		{
			// The bare entry is retained (UNI-login admins keep matching the
			// sentinel) and mirrored onto the legacy issuer (Auth0-exchange
			// admins keep matching), reproducing main's issuer-blind match.
			name:         "bare entry mirrored and sentinel retained",
			subjects:     []rbac.PlatformAdministratorSubject{bare},
			legacyIssuer: legacyIssuer,
			want:         []rbac.PlatformAdministratorSubject{bare, mirrored},
		},
		{
			name:         "issuer-qualified entries are not duplicated",
			subjects:     []rbac.PlatformAdministratorSubject{qualified},
			legacyIssuer: legacyIssuer,
			want:         []rbac.PlatformAdministratorSubject{qualified},
		},
		{
			// The dominant real deployment: no auth0-exchange flags at all.
			// Expansion no-ops and the admin is preserved via the sentinel
			// entry — behaviour identical to main.
			name:         "no auth0-exchange flags set",
			subjects:     []rbac.PlatformAdministratorSubject{bare},
			legacyIssuer: "",
			want:         []rbac.PlatformAdministratorSubject{bare},
		},
		{
			name:         "sentinel-valued legacy issuer is a no-op",
			subjects:     []rbac.PlatformAdministratorSubject{bare},
			legacyIssuer: constants.UNISentinel,
			want:         []rbac.PlatformAdministratorSubject{bare},
		},
		{
			// An operator who already supplied both forms gets a duplicate
			// mirrored entry. That is deliberate: duplicates are harmless
			// (the runtime match short-circuits on first hit) and the
			// expansion does not dedupe.
			name:         "pre-existing qualified duplicate is not deduped",
			subjects:     []rbac.PlatformAdministratorSubject{bare, mirrored},
			legacyIssuer: legacyIssuer,
			want:         []rbac.PlatformAdministratorSubject{bare, mirrored, mirrored},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := expandBareAdminSubjects(tc.subjects, tc.legacyIssuer); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("expandBareAdminSubjects(%v, %q) = %v, want %v", tc.subjects, tc.legacyIssuer, got, tc.want)
			}
		})
	}
}
