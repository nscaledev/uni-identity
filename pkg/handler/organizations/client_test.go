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

package organizations_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common/fixtures"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestFleetTenantIDRoundTrip covers the org-to-tenant link DX-2012 depends on:
// an adhoc organization must carry it, since the provider fields beside it in
// the spec are only plumbed for domain organizations.
func TestFleetTenantIDRoundTrip(t *testing.T) {
	t.Parallel()

	const namespace = "base"

	tenantID := uuid.MustParse("0198f3a1-4c2e-7a11-9f3b-6d1e2c4a8b90")

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	cli := fake.NewClientBuilder().WithScheme(scheme).Build()
	ctx := fixtures.HandlerContextFixture(t.Context(), 0)

	created, err := organizations.New(cli, namespace).Create(ctx, &openapi.OrganizationWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{Name: "acme"},
		Spec: openapi.OrganizationSpec{
			OrganizationType: openapi.Adhoc,
			FleetTenantId:    &tenantID,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, created.Spec.FleetTenantId)
	require.Equal(t, tenantID, *created.Spec.FleetTenantId)

	read, err := organizations.New(cli, namespace).Get(ctx, ids.MustParseOrganizationID(created.Metadata.Id))
	require.NoError(t, err)
	require.NotNil(t, read.Spec.FleetTenantId)
	require.Equal(t, tenantID, *read.Spec.FleetTenantId)
}
