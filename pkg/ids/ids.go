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
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// ID provides nominal typing over UUID resource identifiers.
type ID[T any] uuid.UUID

func Parse[T any](value string) (ID[T], error) {
	id, err := uuid.Parse(value)
	if err != nil {
		return ID[T]{}, err
	}

	return ID[T](id), nil
}

func MustParse[T any](value string) ID[T] {
	return ID[T](uuid.MustParse(value))
}

func FromUUID[T any](value uuid.UUID) ID[T] {
	return ID[T](value)
}

func (i ID[T]) UUID() uuid.UUID {
	return uuid.UUID(i)
}

func (i ID[T]) IsZero() bool {
	return i.UUID() == uuid.Nil
}

func (i ID[T]) String() string {
	return i.UUID().String()
}

func (i ID[T]) MarshalText() ([]byte, error) {
	return i.UUID().MarshalText()
}

func (i *ID[T]) UnmarshalText(text []byte) error {
	var id uuid.UUID

	if err := id.UnmarshalText(text); err != nil {
		return err
	}

	*i = ID[T](id)

	return nil
}

func (i ID[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.String())
}

func (i *ID[T]) UnmarshalJSON(data []byte) error {
	var value string

	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}

	id, err := Parse[T](value)
	if err != nil {
		return fmt.Errorf("invalid UUID %q: %w", value, err)
	}

	*i = id

	return nil
}

type OrganizationKind struct{}
type ProjectKind struct{}
type ServiceAccountKind struct{}
type UserKind struct{}
type GroupKind struct{}
type RoleKind struct{}
type OAuth2ProviderKind struct{}
type AllocationKind struct{}

type OrganizationID struct {
	ID[OrganizationKind]
}

type ProjectID struct {
	ID[ProjectKind]
}

type ServiceAccountID struct {
	ID[ServiceAccountKind]
}

type UserID struct {
	ID[UserKind]
}

type GroupID struct {
	ID[GroupKind]
}

type RoleID struct {
	ID[RoleKind]
}

type OAuth2ProviderID struct {
	ID[OAuth2ProviderKind]
}

type AllocationID struct {
	ID[AllocationKind]
}

func ParseOrganizationID(value string) (OrganizationID, error) {
	id, err := Parse[OrganizationKind](value)
	if err != nil {
		return OrganizationID{}, err
	}

	return OrganizationID{ID: id}, nil
}

func MustParseOrganizationID(value string) OrganizationID {
	return OrganizationID{ID: MustParse[OrganizationKind](value)}
}

func OrganizationIDFromUUID(value uuid.UUID) OrganizationID {
	return OrganizationID{ID: FromUUID[OrganizationKind](value)}
}

func ParseProjectID(value string) (ProjectID, error) {
	id, err := Parse[ProjectKind](value)
	if err != nil {
		return ProjectID{}, err
	}

	return ProjectID{ID: id}, nil
}

func MustParseProjectID(value string) ProjectID {
	return ProjectID{ID: MustParse[ProjectKind](value)}
}

func ProjectIDFromUUID(value uuid.UUID) ProjectID {
	return ProjectID{ID: FromUUID[ProjectKind](value)}
}

func ParseServiceAccountID(value string) (ServiceAccountID, error) {
	id, err := Parse[ServiceAccountKind](value)
	if err != nil {
		return ServiceAccountID{}, err
	}

	return ServiceAccountID{ID: id}, nil
}

func MustParseServiceAccountID(value string) ServiceAccountID {
	return ServiceAccountID{ID: MustParse[ServiceAccountKind](value)}
}

func ServiceAccountIDFromUUID(value uuid.UUID) ServiceAccountID {
	return ServiceAccountID{ID: FromUUID[ServiceAccountKind](value)}
}

func ParseUserID(value string) (UserID, error) {
	id, err := Parse[UserKind](value)
	if err != nil {
		return UserID{}, err
	}

	return UserID{ID: id}, nil
}

func MustParseUserID(value string) UserID {
	return UserID{ID: MustParse[UserKind](value)}
}

func UserIDFromUUID(value uuid.UUID) UserID {
	return UserID{ID: FromUUID[UserKind](value)}
}

func ParseGroupID(value string) (GroupID, error) {
	id, err := Parse[GroupKind](value)
	if err != nil {
		return GroupID{}, err
	}

	return GroupID{ID: id}, nil
}

func MustParseGroupID(value string) GroupID {
	return GroupID{ID: MustParse[GroupKind](value)}
}

func GroupIDFromUUID(value uuid.UUID) GroupID {
	return GroupID{ID: FromUUID[GroupKind](value)}
}

func ParseRoleID(value string) (RoleID, error) {
	id, err := Parse[RoleKind](value)
	if err != nil {
		return RoleID{}, err
	}

	return RoleID{ID: id}, nil
}

func MustParseRoleID(value string) RoleID {
	return RoleID{ID: MustParse[RoleKind](value)}
}

func RoleIDFromUUID(value uuid.UUID) RoleID {
	return RoleID{ID: FromUUID[RoleKind](value)}
}

func ParseOAuth2ProviderID(value string) (OAuth2ProviderID, error) {
	id, err := Parse[OAuth2ProviderKind](value)
	if err != nil {
		return OAuth2ProviderID{}, err
	}

	return OAuth2ProviderID{ID: id}, nil
}

func MustParseOAuth2ProviderID(value string) OAuth2ProviderID {
	return OAuth2ProviderID{ID: MustParse[OAuth2ProviderKind](value)}
}

func OAuth2ProviderIDFromUUID(value uuid.UUID) OAuth2ProviderID {
	return OAuth2ProviderID{ID: FromUUID[OAuth2ProviderKind](value)}
}

func ParseAllocationID(value string) (AllocationID, error) {
	id, err := Parse[AllocationKind](value)
	if err != nil {
		return AllocationID{}, err
	}

	return AllocationID{ID: id}, nil
}

func MustParseAllocationID(value string) AllocationID {
	return AllocationID{ID: MustParse[AllocationKind](value)}
}

func AllocationIDFromUUID(value uuid.UUID) AllocationID {
	return AllocationID{ID: FromUUID[AllocationKind](value)}
}
