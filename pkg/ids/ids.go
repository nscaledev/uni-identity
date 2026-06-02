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

package ids

import (
	"github.com/google/uuid"
)

// OrganizationID is a UUID-backed identifier for organizations. It is a distinct
// named type so the compiler prevents accidental interchange with ProjectID.
// UnmarshalText delegates to uuid.UUID, so the oapi-codegen runtime rejects
// non-UUID path parameter values before any handler is reached.
//
//nolint:recvcheck // UnmarshalText must be a pointer receiver; String/MarshalText are value receivers for fmt.Stringer compatibility.
type OrganizationID uuid.UUID

func (o OrganizationID) String() string {
	return uuid.UUID(o).String()
}

func (o OrganizationID) MarshalText() ([]byte, error) {
	return uuid.UUID(o).MarshalText()
}

func (o *OrganizationID) UnmarshalText(text []byte) error {
	var id uuid.UUID

	if err := id.UnmarshalText(text); err != nil {
		return err
	}

	*o = OrganizationID(id)

	return nil
}

// ProjectID is a UUID-backed identifier for projects. It is a distinct
// named type so the compiler prevents accidental interchange with OrganizationID.
//
//nolint:recvcheck // UnmarshalText must be a pointer receiver; String/MarshalText are value receivers for fmt.Stringer compatibility.
type ProjectID uuid.UUID

func (p ProjectID) String() string {
	return uuid.UUID(p).String()
}

func (p ProjectID) MarshalText() ([]byte, error) {
	return uuid.UUID(p).MarshalText()
}

func (p *ProjectID) UnmarshalText(text []byte) error {
	var id uuid.UUID

	if err := id.UnmarshalText(text); err != nil {
		return err
	}

	*p = ProjectID(id)

	return nil
}

// ParseOrganizationID parses s as a UUID into an OrganizationID, returning
// an error if s is not a valid UUID.
func ParseOrganizationID(s string) (OrganizationID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return OrganizationID{}, err
	}

	return OrganizationID(id), nil
}

// ParseProjectID parses s as a UUID into a ProjectID, returning an error
// if s is not a valid UUID.
func ParseProjectID(s string) (ProjectID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return ProjectID{}, err
	}

	return ProjectID(id), nil
}

// MustParseOrganizationID parses s as a UUID into an OrganizationID.
// Panics if s is not a valid UUID; use only where s is guaranteed valid
// (e.g. previously validated API path parameters).
func MustParseOrganizationID(s string) OrganizationID {
	return OrganizationID(uuid.MustParse(s))
}

// MustParseProjectID parses s as a UUID into a ProjectID.
// Panics if s is not a valid UUID; use only where s is guaranteed valid
// (e.g. previously validated API path parameters).
func MustParseProjectID(s string) ProjectID {
	return ProjectID(uuid.MustParse(s))
}
