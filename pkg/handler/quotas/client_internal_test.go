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

package quotas

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	servererrors "github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common/fixtures"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func qty(s string) *resource.Quantity {
	v := resource.MustParse(s)

	return &v
}

func metaObj(name, def string) unikornv1.QuotaMetadata {
	return unikornv1.QuotaMetadata{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "identity"},
		Spec:       unikornv1.QuotaMetadataSpec{DisplayName: "Display " + name, Description: "Desc " + name, Default: qty(def), Format: unikornv1.Decimal},
	}
}

func allocationObj(kind, committed, reserved string) unikornv1.Allocation {
	return unikornv1.Allocation{
		Spec: unikornv1.AllocationSpec{Allocations: []unikornv1.ResourceAllocation{{Kind: kind, Committed: qty(committed), Reserved: qty(reserved)}}},
	}
}

func TestUpdateRendersRequestListAndGetNormalises(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	organizationID := ids.MustParseOrganizationID("a1111111-1111-4111-8111-111111111111")

	organization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{Namespace: "identity", Name: organizationID.String()},
		Status:     unikornv1.OrganizationStatus{Namespace: "org-a"},
	}

	gpus := metaObj("gpus", "1")
	cpus := metaObj("cpus", "1")

	c := New(fake.NewClientBuilder().WithScheme(scheme).WithObjects(organization, &gpus, &cpus).Build(), "identity")

	// generate() sets identity metadata from the principal in the context.
	ctx := fixtures.HandlerContextFixture(t.Context(), 0)

	written, err := c.Update(ctx, organizationID, &openapi.QuotasWrite{Quotas: openapi.QuotaWriteList{{Kind: "gpus", Quantity: 4}}})
	require.NoError(t, err)
	require.Len(t, written.Quotas, 1)
	require.Equal(t, "gpus", written.Quotas[0].Kind)
	require.Equal(t, 4, written.Quotas[0].Quantity)

	read, err := c.Get(ctx, organizationID)
	require.NoError(t, err)
	require.Len(t, read.Quotas, 2)
	require.Equal(t, "cpus", read.Quotas[0].Kind)
	require.Equal(t, 1, read.Quotas[0].Quantity)
	require.Equal(t, "gpus", read.Quotas[1].Kind)
	require.Equal(t, 4, read.Quotas[1].Quantity)

	// The second write uses the patch path with the optimistic lock. That path
	// needs GetQuota to keep the stored ObjectMeta.
	patched, err := c.Update(ctx, organizationID, &openapi.QuotasWrite{Quotas: openapi.QuotaWriteList{{Kind: "gpus", Quantity: 6}}})
	require.NoError(t, err)
	require.Len(t, patched.Quotas, 1)
	require.Equal(t, 6, patched.Quotas[0].Quantity)

	// Check that the patch is stored, not only that the Update response shows
	// it.
	readAfterPatch, err := c.Get(ctx, organizationID)
	require.NoError(t, err)
	require.Len(t, readAfterPatch.Quotas, 2)
	require.Equal(t, "cpus", readAfterPatch.Quotas[0].Kind)
	require.Equal(t, 1, readAfterPatch.Quotas[0].Quantity)
	require.Equal(t, "gpus", readAfterPatch.Quotas[1].Kind)
	require.Equal(t, 6, readAfterPatch.Quotas[1].Quantity)
}

// TestGetRendersStoredAndVirtualQuotas pins the kinds, usage and metadata
// fields that the per-organization read returns.
func TestGetRendersStoredAndVirtualQuotas(t *testing.T) {
	t.Parallel()

	const orgA = "a1111111-1111-4111-8111-111111111111"

	labels := map[string]string{constants.OrganizationLabel: orgA}
	gpus := metaObj("gpus", "4")
	servers := metaObj("servers", "10")
	stored := &unikornv1.Quota{
		ObjectMeta: metav1.ObjectMeta{Name: "quota", Namespace: "org-a", Labels: labels},
		Spec:       unikornv1.QuotaSpec{Quotas: []unikornv1.ResourceQuota{{Kind: "gpus", Quantity: qty("8")}}},
	}
	used := allocationObj("gpus", "3", "1")
	used.ObjectMeta = metav1.ObjectMeta{Name: "alloc", Namespace: "org-a", Labels: labels}

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	organizationID, err := ids.ParseOrganizationID(orgA)
	require.NoError(t, err)

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&gpus, &servers, stored, &used).Build()

	out, err := New(c, "identity").Get(t.Context(), organizationID)
	require.NoError(t, err)
	require.Len(t, out.Quotas, 2)
	require.Equal(t, "gpus", out.Quotas[0].Kind)
	require.Equal(t, 8, out.Quotas[0].Quantity)
	require.Equal(t, 4, out.Quotas[0].Used)
	require.Equal(t, 4, out.Quotas[0].Free)
	require.Equal(t, "servers", out.Quotas[1].Kind)
	require.Equal(t, 10, out.Quotas[1].Quantity)
	require.Equal(t, 0, out.Quotas[1].Used)

	virtual, err := New(fake.NewClientBuilder().WithScheme(scheme).WithObjects(&gpus).Build(), "identity").Get(t.Context(), organizationID)
	require.NoError(t, err)
	require.Len(t, virtual.Quotas, 1)
	require.Equal(t, 4, virtual.Quotas[0].Quantity)
	require.Equal(t, 4, virtual.Quotas[0].Default)
}

func TestUpdateRejectsUnknownKindBeforeWriting(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, unikornv1.AddToScheme(scheme))

	organizationID := ids.MustParseOrganizationID("a1111111-1111-4111-8111-111111111111")

	organization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{Namespace: "identity", Name: organizationID.String()},
		Status:     unikornv1.OrganizationStatus{Namespace: "org-a"},
	}

	gpus := metaObj("gpus", "1")

	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(organization, &gpus).Build()

	ctx := fixtures.HandlerContextFixture(t.Context(), 0)

	_, err := New(k8s, "identity").Update(ctx, organizationID, &openapi.QuotasWrite{Quotas: openapi.QuotaWriteList{{Kind: "gpus", Quantity: 2}, {Kind: "bogus", Quantity: 1}}})
	require.True(t, servererrors.IsBadRequest(err), "an unknown kind is a bad request, got %v", err)

	var stored unikornv1.QuotaList

	require.NoError(t, k8s.List(ctx, &stored))
	require.Empty(t, stored.Items, "the rejected request writes nothing")
}
