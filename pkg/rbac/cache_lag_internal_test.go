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

package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func lagContext(organizationIDs ...string) context.Context {
	info := &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: estateSubject,
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.User,
				OrgIds:  organizationIDs,
			},
		},
	}

	return authorization.NewContext(context.Background(), info)
}

// lagObjects is the estate with organization 0 removed (membership present,
// organization not cached yet) and organization 1 intact. Organization 1's
// group also names a role the cache does not hold.
func lagObjects() []client.Object {
	all := estateObjects(2, 1)
	objects := make([]client.Object, 0, len(all))

	for _, object := range all {
		if org, ok := object.(*unikornv1.Organization); ok && org.Name == estateOrganizationID(0) {
			continue
		}

		if group, ok := object.(*unikornv1.Group); ok && group.Namespace == estateOrganizationNamespace(1) {
			group.Spec.RoleIDs = append([]string{"missing"}, group.Spec.RoleIDs...)
		}

		objects = append(objects, object)
	}

	return objects
}

// TestACLBuildSkipsWhatTheCacheDoesNotHoldYet checks that an organization or
// role the cache has not seen yet is left out of the ACL, not a failure.
func TestACLBuildSkipsWhatTheCacheDoesNotHoldYet(t *testing.T) {
	t.Parallel()

	r := New(newEstateClient(t, lagObjects(), interceptor.Funcs{}), estateNamespace, &Options{})
	ctx := lagContext(estateOrganizationID(0), estateOrganizationID(1))

	acl, err := r.GetACL(ctx, "")
	require.NoError(t, err)
	require.NotNil(t, acl.Organizations)
	require.Len(t, *acl.Organizations, 1)

	organization := (*acl.Organizations)[0]
	require.Equal(t, estateOrganizationID(1), organization.Id)
	require.NotNil(t, organization.Endpoints, "the organization role after the missing one survives")
	require.NotNil(t, organization.Projects, "the known role still grants its permissions")
	require.Len(t, *organization.Projects, 1)

	scoped, err := r.GetACL(ctx, estateOrganizationID(1))
	require.NoError(t, err)
	require.NotNil(t, scoped.Organization)
	require.NotNil(t, scoped.Organization.Endpoints)
	require.NotNil(t, scoped.Projects)
	require.Len(t, *scoped.Projects, 1)
}

// TestScopedACLStillFailsForAMissingOrganization checks that the organization a
// request is explicitly scoped to is not skipped.
func TestScopedACLStillFailsForAMissingOrganization(t *testing.T) {
	t.Parallel()

	r := New(newEstateClient(t, lagObjects(), interceptor.Funcs{}), estateNamespace, &Options{})

	_, err := r.GetACL(lagContext(estateOrganizationID(0), estateOrganizationID(1)), estateOrganizationID(0))
	require.Error(t, err)
}
