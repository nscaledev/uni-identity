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
	"slices"

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

// ValidateGroupsExist returns an error naming the first requested group that
// is not in the organization's group list.
//
// Membership reconciliation walks the groups that exist and asks of each
// whether the request names it, so a requested ID matching nothing matches no
// branch: without this the principal is neither joined to it nor told, and the
// response reports only the memberships that did apply.  Note the list is read
// through an informer cache, so a group created moments earlier may not be in
// it yet; refusing is still the better answer, because the alternative is a
// success whose body silently contradicts the request.
func ValidateGroupsExist(groupIDs []string, groups *unikornv1.GroupList) error {
	for _, groupID := range groupIDs {
		if !slices.ContainsFunc(groups.Items, func(group unikornv1.Group) bool {
			return group.Name == groupID
		}) {
			return servererrors.OAuth2InvalidRequest(fmt.Sprintf("group %s does not exist in this organization", groupID))
		}
	}

	return nil
}

// AllowGroupMembershipAddition returns nil if the calling principal may add
// a member to the given group.  Adding a member confers the group's roles,
// so the caller must be able to grant every role the group carries.
//
// A role reference that does not resolve refuses the addition rather than
// being skipped.  Role IDs are derived from the role name, so a role that is
// deleted and later re-applied comes back with the same ID and immediately
// re-binds to every group still referencing it; a member added during the gap
// would then hold a role nobody was ever asked to grant, and for a service
// account that authority rides a long-lived token.  Refusing also keeps this
// consistent with ACL construction, which treats the same dangling reference
// as a consistency failure rather than an empty permission set.
//
// Only additions go through here.  Removing a member, and deleting a
// principal (which strips its memberships as cleanup), take authority away
// rather than handing it out, so neither is gated.  Dropping a dangling role
// from a group is likewise allowed — see validateRoleRemovals in
// pkg/handler/groups.  The asymmetry is deliberate: skipping an unresolvable
// role errs towards less authority on a removal and towards more on an
// addition, so only the removal side is safe to skip.
func AllowGroupMembershipAddition(ctx context.Context, cli client.Client, namespace string, organizationID ids.OrganizationID, group *unikornv1.Group) error {
	for _, roleID := range group.Spec.RoleIDs {
		var resource unikornv1.Role

		if err := cli.Get(ctx, client.ObjectKey{Namespace: namespace, Name: roleID}, &resource); err != nil {
			if kerrors.IsNotFound(err) {
				return servererrors.HTTPForbidden(fmt.Sprintf("members cannot be added to the group: role %s does not resolve, so the authority it confers cannot be checked", roleID)).WithError(err)
			}

			return fmt.Errorf("%w: failed to validate group membership addition", err)
		}

		if err := rbac.AllowRole(ctx, &resource, organizationID); err != nil {
			return servererrors.HTTPForbidden(fmt.Sprintf("members cannot be added to the group: role %q (%s) is not grantable by the caller", RoleDisplayName(&resource), roleID)).WithError(err)
		}
	}

	return nil
}
