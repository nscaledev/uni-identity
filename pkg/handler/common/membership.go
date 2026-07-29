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
	"context"
	"fmt"

	"github.com/unikorn-cloud/core/pkg/constants"
	servererrors "github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	kerrors "k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// RoleDisplayName returns the role's human name for error messages, falling
// back to the ID.
func RoleDisplayName(role *unikornv1.Role) string {
	if name, ok := role.Labels[constants.NameLabel]; ok {
		return name
	}

	return role.Name
}

// AllowGroupMembershipAddition returns nil if the calling principal may add
// a member to the given group.  Adding a member confers the group's roles,
// so the caller must be able to grant every role the group carries.  Roles
// that no longer resolve confer nothing and are skipped.
//
// Only additions go through here.  Removing a member, and deleting a
// principal (which strips its memberships as cleanup), take authority away
// rather than handing it out, so neither is gated.
func AllowGroupMembershipAddition(ctx context.Context, cli client.Client, namespace string, organizationID ids.OrganizationID, group *unikornv1.Group) error {
	for _, roleID := range group.Spec.RoleIDs {
		var resource unikornv1.Role

		if err := cli.Get(ctx, client.ObjectKey{Namespace: namespace, Name: roleID}, &resource); err != nil {
			if kerrors.IsNotFound(err) {
				continue
			}

			return fmt.Errorf("%w: failed to validate group membership addition", err)
		}

		if err := rbac.AllowRole(ctx, &resource, organizationID); err != nil {
			return servererrors.HTTPForbidden(fmt.Sprintf("members cannot be added to the group: role %q (%s) is not grantable by the caller", RoleDisplayName(&resource), roleID)).WithError(err)
		}
	}

	return nil
}
