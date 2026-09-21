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

func TestStringFormats(t *testing.T) {
	t.Parallel()

	// Verify value receiver String() works correctly with fmt verbs for all types.
	// This guards against a regression where pointer-receiver-only String() causes
	// fmt to fall back to raw byte-array formatting.
	cases := []struct {
		name string
		s    string
		v    string
	}{
		{
			"OrganizationID",
			fmt.Sprintf("%s", ids.MustParseOrganizationID(validUUID)), //nolint:staticcheck
			fmt.Sprintf("%v", ids.MustParseOrganizationID(validUUID)),
		},
		{
			"ProjectID",
			fmt.Sprintf("%s", ids.MustParseProjectID(validUUID)), //nolint:staticcheck
			fmt.Sprintf("%v", ids.MustParseProjectID(validUUID)),
		},
		{
			"ServiceAccountID",
			fmt.Sprintf("%s", ids.MustParseServiceAccountID(validUUID)), //nolint:staticcheck
			fmt.Sprintf("%v", ids.MustParseServiceAccountID(validUUID)),
		},
		{
			"UserID",
			fmt.Sprintf("%s", ids.MustParseUserID(validUUID)), //nolint:staticcheck
			fmt.Sprintf("%v", ids.MustParseUserID(validUUID)),
		},
		{
			"GroupID",
			fmt.Sprintf("%s", ids.MustParseGroupID(validUUID)), //nolint:staticcheck
			fmt.Sprintf("%v", ids.MustParseGroupID(validUUID)),
		},
		{
			"OAuth2ProviderID",
			fmt.Sprintf("%s", ids.MustParseOAuth2ProviderID(validUUID)), //nolint:staticcheck
			fmt.Sprintf("%v", ids.MustParseOAuth2ProviderID(validUUID)),
		},
		{
			"AllocationID",
			fmt.Sprintf("%s", ids.MustParseAllocationID(validUUID)), //nolint:staticcheck
			fmt.Sprintf("%v", ids.MustParseAllocationID(validUUID)),
		},
	}

	for _, tc := range cases {
		if tc.s != validUUID {
			t.Errorf("%s: fmt.Sprintf(%%s) = %q, want %q", tc.name, tc.s, validUUID)
		}

		if tc.v != validUUID {
			t.Errorf("%s: fmt.Sprintf(%%v) = %q, want %q", tc.name, tc.v, validUUID)
		}
	}
}

func TestMarshalText(t *testing.T) {
	t.Parallel()

	type marshaler interface {
		MarshalText() ([]byte, error)
	}

	cases := []struct {
		name  string
		value marshaler
	}{
		{"OrganizationID", ids.MustParseOrganizationID(validUUID)},
		{"ProjectID", ids.MustParseProjectID(validUUID)},
		{"ServiceAccountID", ids.MustParseServiceAccountID(validUUID)},
		{"UserID", ids.MustParseUserID(validUUID)},
		{"GroupID", ids.MustParseGroupID(validUUID)},
		{"OAuth2ProviderID", ids.MustParseOAuth2ProviderID(validUUID)},
		{"AllocationID", ids.MustParseAllocationID(validUUID)},
	}

	for _, tc := range cases {
		b, err := tc.value.MarshalText()
		if err != nil {
			t.Errorf("%s: MarshalText returned unexpected error: %v", tc.name, err)
			continue
		}

		if string(b) != validUUID {
			t.Errorf("%s: MarshalText = %q, want %q", tc.name, string(b), validUUID)
		}
	}
}

func TestUnmarshalTextAcceptsValid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		target interface {
			UnmarshalText(text []byte) error
			String() string
		}
	}{
		{"OrganizationID", new(ids.OrganizationID)},
		{"ProjectID", new(ids.ProjectID)},
		{"ServiceAccountID", new(ids.ServiceAccountID)},
		{"UserID", new(ids.UserID)},
		{"GroupID", new(ids.GroupID)},
		{"OAuth2ProviderID", new(ids.OAuth2ProviderID)},
		{"AllocationID", new(ids.AllocationID)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := tc.target.UnmarshalText([]byte(validUUID)); err != nil {
				t.Fatalf("%s.UnmarshalText returned unexpected error: %v", tc.name, err)
			}

			if got := tc.target.String(); got != validUUID {
				t.Fatalf("%s: round-trip mismatch: got %q, want %q", tc.name, got, validUUID)
			}
		})
	}
}

func TestUnmarshalTextRejectsInvalid(t *testing.T) {
	t.Parallel()

	type unmarshalTarget interface {
		UnmarshalText(text []byte) error
	}

	cases := []struct {
		name   string
		target unmarshalTarget
	}{
		{"OrganizationID", new(ids.OrganizationID)},
		{"ProjectID", new(ids.ProjectID)},
		{"ServiceAccountID", new(ids.ServiceAccountID)},
		{"UserID", new(ids.UserID)},
		{"GroupID", new(ids.GroupID)},
		{"OAuth2ProviderID", new(ids.OAuth2ProviderID)},
		{"AllocationID", new(ids.AllocationID)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := tc.target.UnmarshalText([]byte(invalidUUID)); err == nil {
				t.Fatalf("%s.UnmarshalText should reject non-UUID input", tc.name)
			}
		})
	}
}

func TestMustParsePanics(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		fn   func(string)
	}{
		{"MustParseOrganizationID", func(s string) { ids.MustParseOrganizationID(s) }},
		{"MustParseProjectID", func(s string) { ids.MustParseProjectID(s) }},
		{"MustParseServiceAccountID", func(s string) { ids.MustParseServiceAccountID(s) }},
		{"MustParseUserID", func(s string) { ids.MustParseUserID(s) }},
		{"MustParseGroupID", func(s string) { ids.MustParseGroupID(s) }},
		{"MustParseOAuth2ProviderID", func(s string) { ids.MustParseOAuth2ProviderID(s) }},
		{"MustParseAllocationID", func(s string) { ids.MustParseAllocationID(s) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if r := recover(); r == nil {
					t.Fatalf("%s should panic on invalid UUID", tc.name)
				}
			}()

			tc.fn(invalidUUID)
		})
	}
}

func TestParseRoundTrips(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		fn   func(string) (string, error)
	}{
		{"ParseOrganizationID", func(s string) (string, error) {
			v, err := ids.ParseOrganizationID(s)
			return v.String(), err
		}},
		{"ParseProjectID", func(s string) (string, error) {
			v, err := ids.ParseProjectID(s)
			return v.String(), err
		}},
		{"ParseServiceAccountID", func(s string) (string, error) {
			v, err := ids.ParseServiceAccountID(s)
			return v.String(), err
		}},
		{"ParseUserID", func(s string) (string, error) {
			v, err := ids.ParseUserID(s)
			return v.String(), err
		}},
		{"ParseGroupID", func(s string) (string, error) {
			v, err := ids.ParseGroupID(s)
			return v.String(), err
		}},
		{"ParseOAuth2ProviderID", func(s string) (string, error) {
			v, err := ids.ParseOAuth2ProviderID(s)
			return v.String(), err
		}},
		{"ParseAllocationID", func(s string) (string, error) {
			v, err := ids.ParseAllocationID(s)
			return v.String(), err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name+"/valid", func(t *testing.T) {
			t.Parallel()

			got, err := tc.fn(validUUID)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != validUUID {
				t.Fatalf("String() = %q, want %q", got, validUUID)
			}
		})

		t.Run(tc.name+"/invalid", func(t *testing.T) {
			t.Parallel()

			if _, err := tc.fn(invalidUUID); err == nil {
				t.Fatal("expected error for invalid UUID, got nil")
			}
		})
	}
}
