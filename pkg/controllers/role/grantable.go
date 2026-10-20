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

package role

import (
	"context"
	"fmt"
	"strings"

	"github.com/unikorn-cloud/identity/pkg/aggregation"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	corev1 "k8s.io/api/core/v1"
)

// Placeholder IDs used to build a holder ACL for the grantable check.  The
// check only compares scopes, so any valid IDs will do.
const (
	grantCheckOrganizationID = "00000000-0000-0000-0000-000000000001"
	grantCheckProjectID      = "00000000-0000-0000-0000-000000000002"
)

// grantable checks the role can grant every non-protected role labelled for
// it, using the same AllowRole check the API runs when an org admin grants a
// role.  A labelled role that is in use is held, so it passes unless it is in
// a cycle, where it holds what its cycle's outside sources give.  The useful
// failure is a labelled role that was skipped for having global scopes, which
// no org admin can ever grant.  The check runs over the real roles in each environment, so it sees roles from every chart
// and per-environment config, which a chart unit test cannot.
//
// The holder ACL puts project scopes in one linked project, as a group member
// with a linked project gets them.  A holder of a non-flattening role whose
// group has no linked project can grant less than this says.
func grantable(ctx context.Context, result *aggregation.Result) aggregation.Condition {
	ctx = rbac.NewContext(ctx, holderACL(result.EffectiveScopes))
	organizationID := ids.MustParseOrganizationID(grantCheckOrganizationID)

	var refused []string

	for _, labelled := range result.Labelled {
		target := &unikornv1.Role{Spec: unikornv1.RoleSpec{Scopes: labelled.Scopes}}

		if err := rbac.AllowRole(ctx, target, organizationID); err != nil {
			refused = append(refused, labelled.Name)
		}
	}

	if len(refused) > 0 {
		return aggregation.Condition{
			Status:  corev1.ConditionFalse,
			Reason:  unikornv1.RoleReasonNotGrantable,
			Message: "cannot grant: " + strings.Join(refused, ", "),
		}
	}

	return aggregation.Condition{
		Status:  corev1.ConditionTrue,
		Reason:  unikornv1.RoleReasonGrantable,
		Message: fmt.Sprintf("can grant all %d labelled roles", len(result.Labelled)),
	}
}

// holderACL builds the ACL a principal holding exactly these scopes gets in
// one organization: the organization block at organization scope and the
// project block in one project, as pkg/rbac builds it for group members.
func holderACL(scopes unikornv1.RoleScopes) *openapi.Acl {
	organization := openapi.AclOrganization{Id: grantCheckOrganizationID}

	if endpoints := toACLEndpoints(scopes.Organization); len(endpoints) > 0 {
		organization.Endpoints = &endpoints
	}

	if endpoints := toACLEndpoints(scopes.Project); len(endpoints) > 0 {
		projects := openapi.AclProjectList{
			{Id: grantCheckProjectID, Endpoints: endpoints},
		}

		organization.Projects = &projects
	}

	organizations := openapi.AclOrganizationList{organization}

	return &openapi.Acl{Organizations: &organizations}
}

func toACLEndpoints(scopes []unikornv1.RoleScope) openapi.AclEndpoints {
	endpoints := make(openapi.AclEndpoints, 0, len(scopes))

	for _, scope := range scopes {
		operations := make(openapi.AclOperations, len(scope.Operations))

		for i, operation := range scope.Operations {
			operations[i] = openapi.AclOperation(operation)
		}

		endpoints = append(endpoints, openapi.AclEndpoint{Name: scope.Name, Operations: operations})
	}

	return endpoints
}
