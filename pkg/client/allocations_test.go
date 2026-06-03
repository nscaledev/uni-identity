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

package client_test

import (
	"testing"

	"github.com/unikorn-cloud/identity/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/principal"
)

const (
	validOrgUUID  = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	validProjUUID = "550e8400-e29b-41d4-a716-446655440000"
)

func TestParsePrincipalIDs(t *testing.T) {
	t.Parallel()

	t.Run("valid org and project IDs", func(t *testing.T) {
		t.Parallel()

		p := &principal.Principal{OrganizationID: validOrgUUID, ProjectID: validProjUUID}

		orgID, projID, err := client.ParsePrincipalIDs(p)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if orgID.String() != validOrgUUID {
			t.Fatalf("orgID.String() = %q, want %q", orgID.String(), validOrgUUID)
		}

		if projID.String() != validProjUUID {
			t.Fatalf("projID.String() = %q, want %q", projID.String(), validProjUUID)
		}
	})

	t.Run("invalid organization ID", func(t *testing.T) {
		t.Parallel()

		p := &principal.Principal{OrganizationID: "not-a-uuid", ProjectID: validProjUUID}

		_, _, err := client.ParsePrincipalIDs(p)
		if err == nil {
			t.Fatal("expected error for invalid organization ID, got nil")
		}
	})

	t.Run("invalid project ID", func(t *testing.T) {
		t.Parallel()

		p := &principal.Principal{OrganizationID: validOrgUUID, ProjectID: "not-a-uuid"}

		_, _, err := client.ParsePrincipalIDs(p)
		if err == nil {
			t.Fatal("expected error for invalid project ID, got nil")
		}
	})

	t.Run("both IDs invalid", func(t *testing.T) {
		t.Parallel()

		p := &principal.Principal{OrganizationID: "bad-org", ProjectID: "bad-proj"}

		_, _, err := client.ParsePrincipalIDs(p)
		if err == nil {
			t.Fatal("expected error for invalid IDs, got nil")
		}
	})
}
