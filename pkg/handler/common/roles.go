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

package common

import (
	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
)

// RoleDisplayName returns the name a caller knows a role by, for use in
// errors that have to say which role blocked a write.  Roles are stored under
// a generated ID, so the human name lives in a label; fall back to the ID when
// the label is absent.
func RoleDisplayName(role *unikornv1.Role) string {
	if name, ok := role.Labels[constants.NameLabel]; ok {
		return name
	}

	return role.Name
}
