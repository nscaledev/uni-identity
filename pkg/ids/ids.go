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
// named type so the compiler prevents accidental interchange with any other ID type.
// UnmarshalText delegates to uuid.UUID, so the oapi-codegen runtime rejects
// non-UUID path parameter values before any handler is reached.
//
//nolint:recvcheck // UnmarshalText must be a pointer receiver; String/MarshalText are value receivers for fmt.Stringer compatibility.
type OrganizationID uuid.UUID

func (v OrganizationID) String() string                { return uuid.UUID(v).String() }
func (v OrganizationID) MarshalText() ([]byte, error)  { return uuid.UUID(v).MarshalText() }
func (v *OrganizationID) UnmarshalText(b []byte) error { return unmarshalUUID((*uuid.UUID)(v), b) }

// ProjectID is a UUID-backed identifier for projects. It is a distinct
// named type so the compiler prevents accidental interchange with any other ID type.
// UnmarshalText delegates to uuid.UUID, so the oapi-codegen runtime rejects
// non-UUID path parameter values before any handler is reached.
//
//nolint:recvcheck // UnmarshalText must be a pointer receiver; String/MarshalText are value receivers for fmt.Stringer compatibility.
type ProjectID uuid.UUID

func (v ProjectID) String() string                { return uuid.UUID(v).String() }
func (v ProjectID) MarshalText() ([]byte, error)  { return uuid.UUID(v).MarshalText() }
func (v *ProjectID) UnmarshalText(b []byte) error { return unmarshalUUID((*uuid.UUID)(v), b) }

// ServiceAccountID is a UUID-backed identifier for service accounts. It is a distinct
// named type so the compiler prevents accidental interchange with any other ID type.
// UnmarshalText delegates to uuid.UUID, so the oapi-codegen runtime rejects
// non-UUID path parameter values before any handler is reached.
//
//nolint:recvcheck // UnmarshalText must be a pointer receiver; String/MarshalText are value receivers for fmt.Stringer compatibility.
type ServiceAccountID uuid.UUID

func (v ServiceAccountID) String() string                { return uuid.UUID(v).String() }
func (v ServiceAccountID) MarshalText() ([]byte, error)  { return uuid.UUID(v).MarshalText() }
func (v *ServiceAccountID) UnmarshalText(b []byte) error { return unmarshalUUID((*uuid.UUID)(v), b) }

// UserID is a UUID-backed identifier for users. It is a distinct
// named type so the compiler prevents accidental interchange with any other ID type.
// UnmarshalText delegates to uuid.UUID, so the oapi-codegen runtime rejects
// non-UUID path parameter values before any handler is reached.
//
//nolint:recvcheck // UnmarshalText must be a pointer receiver; String/MarshalText are value receivers for fmt.Stringer compatibility.
type UserID uuid.UUID

func (v UserID) String() string                { return uuid.UUID(v).String() }
func (v UserID) MarshalText() ([]byte, error)  { return uuid.UUID(v).MarshalText() }
func (v *UserID) UnmarshalText(b []byte) error { return unmarshalUUID((*uuid.UUID)(v), b) }

// GroupID is a UUID-backed identifier for groups. It is a distinct
// named type so the compiler prevents accidental interchange with any other ID type.
// UnmarshalText delegates to uuid.UUID, so the oapi-codegen runtime rejects
// non-UUID path parameter values before any handler is reached.
//
//nolint:recvcheck // UnmarshalText must be a pointer receiver; String/MarshalText are value receivers for fmt.Stringer compatibility.
type GroupID uuid.UUID

func (v GroupID) String() string                { return uuid.UUID(v).String() }
func (v GroupID) MarshalText() ([]byte, error)  { return uuid.UUID(v).MarshalText() }
func (v *GroupID) UnmarshalText(b []byte) error { return unmarshalUUID((*uuid.UUID)(v), b) }

// OAuth2ProviderID is a UUID-backed identifier for OAuth2 providers. It is a distinct
// named type so the compiler prevents accidental interchange with any other ID type.
// UnmarshalText delegates to uuid.UUID, so the oapi-codegen runtime rejects
// non-UUID path parameter values before any handler is reached.
//
//nolint:recvcheck // UnmarshalText must be a pointer receiver; String/MarshalText are value receivers for fmt.Stringer compatibility.
type OAuth2ProviderID uuid.UUID

func (v OAuth2ProviderID) String() string                { return uuid.UUID(v).String() }
func (v OAuth2ProviderID) MarshalText() ([]byte, error)  { return uuid.UUID(v).MarshalText() }
func (v *OAuth2ProviderID) UnmarshalText(b []byte) error { return unmarshalUUID((*uuid.UUID)(v), b) }

// AllocationID is a UUID-backed identifier for resource allocations. It is a distinct
// named type so the compiler prevents accidental interchange with any other ID type.
// UnmarshalText delegates to uuid.UUID, so the oapi-codegen runtime rejects
// non-UUID path parameter values before any handler is reached.
//
//nolint:recvcheck // UnmarshalText must be a pointer receiver; String/MarshalText are value receivers for fmt.Stringer compatibility.
type AllocationID uuid.UUID

func (v AllocationID) String() string                { return uuid.UUID(v).String() }
func (v AllocationID) MarshalText() ([]byte, error)  { return uuid.UUID(v).MarshalText() }
func (v *AllocationID) UnmarshalText(b []byte) error { return unmarshalUUID((*uuid.UUID)(v), b) }

// unmarshalUUID is the shared implementation for all UnmarshalText methods.
func unmarshalUUID(dst *uuid.UUID, text []byte) error {
	var id uuid.UUID

	if err := id.UnmarshalText(text); err != nil {
		return err
	}

	*dst = id

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

// ParseProjectID parses s as a UUID into a ProjectID, returning
// an error if s is not a valid UUID.
func ParseProjectID(s string) (ProjectID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return ProjectID{}, err
	}

	return ProjectID(id), nil
}

// ParseServiceAccountID parses s as a UUID into a ServiceAccountID, returning
// an error if s is not a valid UUID.
func ParseServiceAccountID(s string) (ServiceAccountID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return ServiceAccountID{}, err
	}

	return ServiceAccountID(id), nil
}

// ParseUserID parses s as a UUID into a UserID, returning
// an error if s is not a valid UUID.
func ParseUserID(s string) (UserID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return UserID{}, err
	}

	return UserID(id), nil
}

// ParseGroupID parses s as a UUID into a GroupID, returning
// an error if s is not a valid UUID.
func ParseGroupID(s string) (GroupID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return GroupID{}, err
	}

	return GroupID(id), nil
}

// ParseOAuth2ProviderID parses s as a UUID into an OAuth2ProviderID, returning
// an error if s is not a valid UUID.
func ParseOAuth2ProviderID(s string) (OAuth2ProviderID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return OAuth2ProviderID{}, err
	}

	return OAuth2ProviderID(id), nil
}

// ParseAllocationID parses s as a UUID into an AllocationID, returning
// an error if s is not a valid UUID.
func ParseAllocationID(s string) (AllocationID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return AllocationID{}, err
	}

	return AllocationID(id), nil
}

// MustParseOrganizationID parses s as a UUID into an OrganizationID.
// Panics if s is not a valid UUID; use only where s is guaranteed valid
// (e.g. previously validated API path parameters).
func MustParseOrganizationID(s string) OrganizationID { return OrganizationID(uuid.MustParse(s)) }

// MustParseProjectID parses s as a UUID into a ProjectID.
// Panics if s is not a valid UUID; use only where s is guaranteed valid
// (e.g. previously validated API path parameters).
func MustParseProjectID(s string) ProjectID { return ProjectID(uuid.MustParse(s)) }

// MustParseServiceAccountID parses s as a UUID into a ServiceAccountID.
// Panics if s is not a valid UUID; use only where s is guaranteed valid
// (e.g. previously validated API path parameters).
func MustParseServiceAccountID(s string) ServiceAccountID { return ServiceAccountID(uuid.MustParse(s)) }

// MustParseUserID parses s as a UUID into a UserID.
// Panics if s is not a valid UUID; use only where s is guaranteed valid
// (e.g. previously validated API path parameters).
func MustParseUserID(s string) UserID { return UserID(uuid.MustParse(s)) }

// MustParseGroupID parses s as a UUID into a GroupID.
// Panics if s is not a valid UUID; use only where s is guaranteed valid
// (e.g. previously validated API path parameters).
func MustParseGroupID(s string) GroupID { return GroupID(uuid.MustParse(s)) }

// MustParseOAuth2ProviderID parses s as a UUID into an OAuth2ProviderID.
// Panics if s is not a valid UUID; use only where s is guaranteed valid
// (e.g. previously validated API path parameters).
func MustParseOAuth2ProviderID(s string) OAuth2ProviderID { return OAuth2ProviderID(uuid.MustParse(s)) }

// MustParseAllocationID parses s as a UUID into an AllocationID.
// Panics if s is not a valid UUID; use only where s is guaranteed valid
// (e.g. previously validated API path parameters).
func MustParseAllocationID(s string) AllocationID { return AllocationID(uuid.MustParse(s)) }
