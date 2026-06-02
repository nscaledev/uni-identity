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

package ids_test

import (
	"fmt"
	"testing"

	"github.com/unikorn-cloud/identity/pkg/ids"
)

const (
	validUUID   = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	invalidUUID = "not-a-uuid"
)

func TestParseOrganizationID(t *testing.T) {
	t.Parallel()

	id, err := ids.ParseOrganizationID(validUUID)
	if err != nil {
		t.Fatalf("unexpected error parsing valid UUID: %v", err)
	}

	if id.String() != validUUID {
		t.Fatalf("String() round-trip failed: got %q, want %q", id.String(), validUUID)
	}
}

func TestParseOrganizationIDRejectsInvalid(t *testing.T) {
	t.Parallel()

	if _, err := ids.ParseOrganizationID(invalidUUID); err == nil {
		t.Fatal("expected error parsing invalid UUID, got nil")
	}
}

func TestParseProjectID(t *testing.T) {
	t.Parallel()

	id, err := ids.ParseProjectID(validUUID)
	if err != nil {
		t.Fatalf("unexpected error parsing valid UUID: %v", err)
	}

	if id.String() != validUUID {
		t.Fatalf("String() round-trip failed: got %q, want %q", id.String(), validUUID)
	}
}

func TestParseProjectIDRejectsInvalid(t *testing.T) {
	t.Parallel()

	if _, err := ids.ParseProjectID(invalidUUID); err == nil {
		t.Fatal("expected error parsing invalid UUID, got nil")
	}
}

func TestOrganizationIDStringFormats(t *testing.T) {
	t.Parallel()

	id := ids.MustParseOrganizationID(validUUID)

	// Verify value receiver String() works correctly with fmt verbs.
	if got := fmt.Sprintf("%s", id); got != validUUID { //nolint:staticcheck
		t.Fatalf("fmt.Sprintf(%%s) = %q, want %q", got, validUUID)
	}

	if got := fmt.Sprintf("%v", id); got != validUUID {
		t.Fatalf("fmt.Sprintf(%%v) = %q, want %q", got, validUUID)
	}
}

func TestProjectIDStringFormats(t *testing.T) {
	t.Parallel()

	id := ids.MustParseProjectID(validUUID)

	if got := fmt.Sprintf("%s", id); got != validUUID { //nolint:staticcheck
		t.Fatalf("fmt.Sprintf(%%s) = %q, want %q", got, validUUID)
	}
}

func TestMarshalText(t *testing.T) {
	t.Parallel()

	org := ids.MustParseOrganizationID(validUUID)

	b, err := org.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText returned unexpected error: %v", err)
	}

	if string(b) != validUUID {
		t.Fatalf("MarshalText = %q, want %q", string(b), validUUID)
	}

	proj := ids.MustParseProjectID(validUUID)

	b, err = proj.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText returned unexpected error: %v", err)
	}

	if string(b) != validUUID {
		t.Fatalf("MarshalText = %q, want %q", string(b), validUUID)
	}
}

func TestUnmarshalTextRejectsInvalid(t *testing.T) {
	t.Parallel()

	var org ids.OrganizationID
	if err := org.UnmarshalText([]byte(invalidUUID)); err == nil {
		t.Fatal("UnmarshalText should reject non-UUID input")
	}

	var proj ids.ProjectID
	if err := proj.UnmarshalText([]byte(invalidUUID)); err == nil {
		t.Fatal("UnmarshalText should reject non-UUID input")
	}
}

func TestMustParseOrganizationIDPanics(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("MustParseOrganizationID should panic on invalid UUID")
		}
	}()

	ids.MustParseOrganizationID(invalidUUID)
}

func TestMustParseProjectIDPanics(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("MustParseProjectID should panic on invalid UUID")
		}
	}()

	ids.MustParseProjectID(invalidUUID)
}
