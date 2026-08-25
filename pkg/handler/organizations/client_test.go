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
	"github.com/unikorn-cloud/identity/pkg/rbac"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

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

// TestFleetTenantIDIsPlatformAdministratorOnly covers the write side of the link.  The
// shipped administrator role holds identity:organizations update at organization scope,
// so were the field writable there an organization administrator could point themselves
// at another customer's tenant: it would resolve cleanly, pass every check we write, and
// render that customer's hardware.  That is the misdirection the link exists to rule out,
// so only a global-scope holder may retarget it.
func TestFleetTenantIDIsPlatformAdministratorOnly(t *testing.T) {
	t.Parallel()

	const namespace = "base"

	tenantID := uuid.MustParse("0198f3a1-4c2e-7a11-9f3b-6d1e2c4a8b90")
	otherTenantID := uuid.MustParse("0198f3a1-4c2e-7a11-9f3b-6d1e2c4a8b91")

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	cli := fake.NewClientBuilder().WithScheme(scheme).Build()
	ctx := fixtures.HandlerContextFixture(t.Context(), 0)
	client := organizations.New(cli, namespace)

	write := func(tenant *uuid.UUID) *openapi.OrganizationWrite {
		return &openapi.OrganizationWrite{
			Metadata: coreopenapi.ResourceWriteMetadata{Name: "acme"},
			Spec: openapi.OrganizationSpec{
				OrganizationType: openapi.Adhoc,
				FleetTenantId:    tenant,
			},
		}
	}

	created, err := client.Create(ctx, write(&tenantID))
	require.NoError(t, err)

	organizationID := ids.MustParseOrganizationID(created.Metadata.Id)

	endpoints := openapi.AclEndpoints{{
		Name:       "identity:organizations",
		Operations: openapi.AclOperations{openapi.Read, openapi.Update},
	}}
	scoped := openapi.AclOrganizationList{{Id: organizationID.String(), Endpoints: &endpoints}}

	organizationAdmin := rbac.NewContext(ctx, &openapi.Acl{Organizations: &scoped})
	platformAdmin := rbac.NewContext(ctx, &openapi.Acl{Global: &endpoints})

	fleetTenantID := func() *uuid.UUID {
		t.Helper()

		read, err := client.Get(ctx, organizationID)
		require.NoError(t, err)

		return read.Spec.FleetTenantId
	}

	require.NoError(t, client.Update(organizationAdmin, organizationID, write(&otherTenantID)))
	require.Equal(t, tenantID, *fleetTenantID(), "organization administrator retargeted the tenant link")

	require.NoError(t, client.Update(organizationAdmin, organizationID, write(nil)))
	require.Equal(t, tenantID, *fleetTenantID(), "a write body without the field cleared the tenant link")

	require.NoError(t, client.Update(platformAdmin, organizationID, write(&otherTenantID)))
	require.Equal(t, otherTenantID, *fleetTenantID(), "platform administrator could not retarget the tenant link")

	require.NoError(t, client.Update(platformAdmin, organizationID, write(nil)))
	require.Nil(t, fleetTenantID(), "platform administrator could not clear the tenant link")
}

// TestFleetTenantIDUnparseableReadsAsAbsent covers the fail-closed read.  Both the
// generated type and the CRD's uuid format keep a bad value out, so this is reachable
// only by hand-editing the resource -- at which point resolving to nothing beats
// resolving to a guess.
func TestFleetTenantIDUnparseableReadsAsAbsent(t *testing.T) {
	t.Parallel()

	const namespace = "base"

	organizationID := uuid.MustParse("0198f3a1-4c2e-7a11-9f3b-6d1e2c4a8b92")

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	organization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      organizationID.String(),
			Namespace: namespace,
		},
		Spec: unikornv1.OrganizationSpec{
			FleetTenantID: ptr.To("not-a-uuid"),
		},
	}

	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(organization).Build()

	read, err := organizations.New(cli, namespace).Get(t.Context(), ids.MustParseOrganizationID(organizationID.String()))
	require.NoError(t, err)
	require.Nil(t, read.Spec.FleetTenantId)
}
