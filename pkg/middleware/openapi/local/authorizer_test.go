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

package local_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/middleware/openapi/local"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestGetACL_ServiceAccount_NonMemberOrganization_Returns403 verifies that the
// local authorizer translates the rbac sentinel ErrNotInOrganization into an
// HTTP 403 error when a service account requests an organization-scoped ACL for
// an organization that is not its home org. This is the boundary contract that
// closes the bug where the endpoint silently returned 200 with the home-org ACL.
func TestGetACL_ServiceAccount_NonMemberOrganization_Returns403(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	authorizer := local.NewAuthorizer(nil, rbac.New(c, "test-namespace", &rbac.Options{}))

	info := &authorization.Info{
		Userinfo: &openapi.Userinfo{
			Sub: "service-account-subject",
			HttpsunikornCloudOrgauthz: &openapi.AuthClaims{
				Acctype: openapi.Service,
				OrgIds:  []string{"home-org-id"},
			},
		},
	}

	ctx := authorization.NewContext(t.Context(), info)

	_, err := authorizer.GetACL(ctx, "different-org-id")
	require.Error(t, err)

	assert.True(t, errors.IsForbidden(err),
		"local authorizer must report 403 for cross-org service-account ACL requests, got %v", err)
	assert.ErrorIs(t, err, rbac.ErrNotInOrganization,
		"wrapped error should preserve the rbac sentinel for diagnostics")
}
