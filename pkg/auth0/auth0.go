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

package auth0

import (
	"errors"

	mgmtcore "github.com/auth0/go-auth0/v2/management/core"
)

const (
	MetadataKeyManagedBy = "managed_by"

	MetadataKeyUniAuth0OrganizationNamespace = "uni_auth0_organization_namespace"
	MetadataKeyUniAuth0OrganizationName      = "uni_auth0_organization_name"
	MetadataKeyUniOrganizationID             = "uni_organization_id"

	MetadataKeyUniAuth0UserNamespace = "uni_auth0_user_namespace"
	MetadataKeyUniAuth0UserName      = "uni_auth0_user_name"
	MetadataKeyUniAccountType        = "uni_account_type"
	MetadataKeyUniAccountID          = "uni_account_id"

	MetadataValueManagedByMigrationController = "migration_controller"

	MetadataKeyUniAccountTypeUser = "user"
)

//nolint:nlreturn,wsl
func IsStatusCodeError(err error, statusCode int) bool {
	if e := (*mgmtcore.APIError)(nil); errors.As(err, &e) && e.StatusCode == statusCode {
		return true
	}
	return false
}
