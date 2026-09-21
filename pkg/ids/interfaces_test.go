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
	"errors"
	"testing"

	"github.com/unikorn-cloud/identity/pkg/ids"
)

var errScope = errors.New("scope unavailable")

// scopeStub implements both scope-reader interfaces, standing in for a CRD that
// recovers its owning organization and project from labels.
type scopeStub struct {
	orgID  ids.OrganizationID
	projID ids.ProjectID
	err    error
}

func (s scopeStub) OrganizationID() (ids.OrganizationID, error) {
	return s.orgID, s.err
}

func (s scopeStub) OrganizationAndProjectID() (ids.OrganizationID, ids.ProjectID, error) {
	return s.orgID, s.projID, s.err
}

// Compile-time assertions that the interfaces are satisfiable, and that a
// ProjectScopeReader is usable wherever an OrganizationScopeReader is required
// (the embedding contract).
var (
	_ ids.OrganizationScopeReader = scopeStub{}
	_ ids.ProjectScopeReader      = scopeStub{}
	_ ids.OrganizationScopeReader = ids.ProjectScopeReader(scopeStub{})
)

func TestSameProject(t *testing.T) {
	t.Parallel()

	org1 := ids.MustParseOrganizationID("f47ac10b-58cc-4372-a567-0e02b2c3d479")
	org2 := ids.MustParseOrganizationID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	proj1 := ids.MustParseProjectID("550e8400-e29b-41d4-a716-446655440000")
	proj2 := ids.MustParseProjectID("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name    string
		a       scopeStub
		b       scopeStub
		want    bool
		wantErr bool
	}{
		{
			name: "same organization and project",
			a:    scopeStub{orgID: org1, projID: proj1},
			b:    scopeStub{orgID: org1, projID: proj1},
			want: true,
		},
		{
			name: "same organization, different project",
			a:    scopeStub{orgID: org1, projID: proj1},
			b:    scopeStub{orgID: org1, projID: proj2},
			want: false,
		},
		{
			name: "different organization, same project ID",
			a:    scopeStub{orgID: org1, projID: proj1},
			b:    scopeStub{orgID: org2, projID: proj1},
			want: false,
		},
		{
			name:    "first resource scope error",
			a:       scopeStub{err: errScope},
			b:       scopeStub{orgID: org1, projID: proj1},
			wantErr: true,
		},
		{
			name:    "second resource scope error",
			a:       scopeStub{orgID: org1, projID: proj1},
			b:       scopeStub{err: errScope},
			wantErr: true,
		},
	}

	for i := range tests {
		test := &tests[i]

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := ids.SameProject(test.a, test.b)

			if test.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != test.want {
				t.Fatalf("SameProject = %v, want %v", got, test.want)
			}
		})
	}
}

func TestOwnedByProject(t *testing.T) {
	t.Parallel()

	org1 := ids.MustParseOrganizationID("f47ac10b-58cc-4372-a567-0e02b2c3d479")
	org2 := ids.MustParseOrganizationID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	proj1 := ids.MustParseProjectID("550e8400-e29b-41d4-a716-446655440000")
	proj2 := ids.MustParseProjectID("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name    string
		scope   scopeStub
		orgID   ids.OrganizationID
		projID  ids.ProjectID
		want    bool
		wantErr bool
	}{
		{
			name:   "owned by the expected organization and project",
			scope:  scopeStub{orgID: org1, projID: proj1},
			orgID:  org1,
			projID: proj1,
			want:   true,
		},
		{
			name:   "wrong project",
			scope:  scopeStub{orgID: org1, projID: proj1},
			orgID:  org1,
			projID: proj2,
			want:   false,
		},
		{
			name:   "wrong organization",
			scope:  scopeStub{orgID: org1, projID: proj1},
			orgID:  org2,
			projID: proj1,
			want:   false,
		},
		{
			name:    "scope error",
			scope:   scopeStub{err: errScope},
			orgID:   org1,
			projID:  proj1,
			wantErr: true,
		},
	}

	for i := range tests {
		test := &tests[i]

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := ids.OwnedByProject(test.scope, test.orgID, test.projID)

			if test.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != test.want {
				t.Fatalf("OwnedByProject = %v, want %v", got, test.want)
			}
		})
	}
}

func TestOwnedByOrganization(t *testing.T) {
	t.Parallel()

	org1 := ids.MustParseOrganizationID("f47ac10b-58cc-4372-a567-0e02b2c3d479")
	org2 := ids.MustParseOrganizationID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

	tests := []struct {
		name    string
		scope   scopeStub
		orgID   ids.OrganizationID
		want    bool
		wantErr bool
	}{
		{
			name:  "owned by the expected organization",
			scope: scopeStub{orgID: org1},
			orgID: org1,
			want:  true,
		},
		{
			name:  "wrong organization",
			scope: scopeStub{orgID: org1},
			orgID: org2,
			want:  false,
		},
		{
			name:    "scope error",
			scope:   scopeStub{err: errScope},
			orgID:   org1,
			wantErr: true,
		},
	}

	for i := range tests {
		test := &tests[i]

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := ids.OwnedByOrganization(test.scope, test.orgID)

			if test.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != test.want {
				t.Fatalf("OwnedByOrganization = %v, want %v", got, test.want)
			}
		})
	}
}
