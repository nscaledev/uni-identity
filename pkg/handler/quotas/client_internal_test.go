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
	"context"
	goerrors "errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreerrors "github.com/unikorn-cloud/core/pkg/errors"
	servererrors "github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common/fixtures"
	"github.com/unikorn-cloud/identity/pkg/ids"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	coordinationv1 "k8s.io/api/coordination/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var errLeaseDelete = goerrors.New("lease delete failed")

type releaseFailureClient struct {
	client.Client
}

func (c releaseFailureClient) Delete(ctx context.Context, object client.Object, options ...client.DeleteOption) error {
	if _, ok := object.(*coordinationv1.Lease); ok {
		return errLeaseDelete
	}

	return c.Client.Delete(ctx, object, options...)
}

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

func allocationObj(committed, reserved string) unikornv1.Allocation {
	return unikornv1.Allocation{
		Spec: unikornv1.AllocationSpec{Allocations: []unikornv1.ResourceAllocation{{Kind: "gpus", Committed: qty(committed), Reserved: qty(reserved)}}},
	}
}

func TestUpdateRendersRequestListAndGetNormalises(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
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

	stored := &unikornv1.Quota{}
	require.NoError(t, c.client.Get(ctx, client.ObjectKey{Namespace: "org-a", Name: quotaName}, stored))
	require.Equal(t, quotaName, stored.Name, "new quotas use the fixed persisted name")

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

	var leases coordinationv1.LeaseList

	require.NoError(t, c.client.List(ctx, &leases))
	require.Empty(t, leases.Items, "quota updates release their organization Lease")
}

func TestUpdateRejectsFirstQuotaBelowLiveAllocations(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	organizationID := ids.MustParseOrganizationID("a1111111-1111-4111-8111-111111111111")
	organization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{Namespace: "identity", Name: organizationID.String()},
		Status:     unikornv1.OrganizationStatus{Namespace: "org-a"},
	}
	gpus := metaObj("gpus", "1")
	allocation := allocationObj("3", "0")
	allocation.ObjectMeta = metav1.ObjectMeta{
		Name:      "allocation",
		Namespace: "project-a",
		Labels:    map[string]string{constants.OrganizationLabel: organizationID.String()},
	}

	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(organization, &gpus, &allocation).Build()

	_, err := New(k8s, "identity").Update(fixtures.HandlerContextFixture(t.Context(), 0), organizationID, &openapi.QuotasWrite{Quotas: openapi.QuotaWriteList{{Kind: "gpus", Quantity: 2}}})
	require.True(t, servererrors.IsForbidden(err), "first quota creation cannot undercut current allocation")

	var quotas unikornv1.QuotaList

	require.NoError(t, k8s.List(t.Context(), &quotas))
	require.Empty(t, quotas.Items, "the rejected quota is not stored")

	var leases coordinationv1.LeaseList

	require.NoError(t, k8s.List(t.Context(), &leases))
	require.Empty(t, leases.Items, "the rejected quota releases its organization Lease")
}

func TestUpdateSucceedsWhenLeaseReleaseFails(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	organizationID := ids.MustParseOrganizationID("a1111111-1111-4111-8111-111111111111")
	organization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{Namespace: "identity", Name: organizationID.String()},
		Status:     unikornv1.OrganizationStatus{Namespace: "org-a"},
	}
	gpus := metaObj("gpus", "1")
	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(organization, &gpus).Build()

	result, err := New(releaseFailureClient{Client: k8s}, "identity").Update(fixtures.HandlerContextFixture(t.Context(), 0), organizationID, &openapi.QuotasWrite{Quotas: openapi.QuotaWriteList{{Kind: "gpus", Quantity: 2}}})
	require.NoError(t, err)
	require.Equal(t, 2, result.Quotas[0].Quantity)
}

// deadlineQuotaListClient fails a Quota list once the context has ended, as the
// API server does for a request that outlives its deadline.
type deadlineQuotaListClient struct {
	client.Client
}

func (c deadlineQuotaListClient) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	if _, ok := list.(*unikornv1.QuotaList); ok {
		<-ctx.Done()

		return ctx.Err()
	}

	return c.Client.List(ctx, list, options...)
}

// TestUpdateReportsDeadlineDuringReadAsConflict checks that a quota read that
// runs past the critical-section deadline is a retryable 409, not a 400.
func TestUpdateReportsDeadlineDuringReadAsConflict(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	organizationID := ids.MustParseOrganizationID("a1111111-1111-4111-8111-111111111111")
	organization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{Namespace: "identity", Name: organizationID.String()},
		Status:     unikornv1.OrganizationStatus{Namespace: "org-a"},
	}
	gpus := metaObj("gpus", "1")
	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(organization, &gpus).Build()

	ctx, cancel := context.WithTimeout(fixtures.HandlerContextFixture(t.Context(), 0), 20*time.Millisecond)
	t.Cleanup(cancel)

	_, err := New(deadlineQuotaListClient{Client: k8s}, "identity").Update(ctx, organizationID, &openapi.QuotasWrite{Quotas: openapi.QuotaWriteList{{Kind: "gpus", Quantity: 2}}})
	require.Error(t, err)
	require.True(t, servererrors.IsConflict(err))
	require.False(t, servererrors.IsBadRequest(err))

	leases := &coordinationv1.LeaseList{}
	require.NoError(t, k8s.List(context.WithoutCancel(ctx), leases))
	require.Empty(t, leases.Items, "the failed update releases its organization Lease")
}

// metadataListObserver records, for each QuotaMetadata list, whether an
// organization Lease existed and whether the context carried a deadline.
type metadataListObserver struct {
	client.Client

	leaseHeld   []bool
	hasDeadline []bool
}

func (c *metadataListObserver) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	if _, ok := list.(*unikornv1.QuotaMetadataList); ok {
		var leases coordinationv1.LeaseList
		if err := c.Client.List(ctx, &leases); err != nil {
			return err
		}

		_, deadline := ctx.Deadline()
		c.hasDeadline = append(c.hasDeadline, deadline)
		c.leaseHeld = append(c.leaseHeld, len(leases.Items) > 0)
	}

	return c.Client.List(ctx, list, options...)
}

// TestUpdateRendersAfterReleasingLease checks that a committed quota is
// rendered with the request context after the Lease is gone, so the Lease
// deadline cannot fail a response for state already written.
func TestUpdateRendersAfterReleasingLease(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	organizationID := ids.MustParseOrganizationID("a1111111-1111-4111-8111-111111111111")
	organization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{Namespace: "identity", Name: organizationID.String()},
		Status:     unikornv1.OrganizationStatus{Namespace: "org-a"},
	}
	gpus := metaObj("gpus", "1")
	observer := &metadataListObserver{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(organization, &gpus).Build()}
	c := New(observer, "identity")
	ctx := fixtures.HandlerContextFixture(t.Context(), 0)

	// The first update creates the quota and the second patches it.
	for _, quantity := range []int{2, 3} {
		observer.leaseHeld, observer.hasDeadline = nil, nil

		result, err := c.Update(ctx, organizationID, &openapi.QuotasWrite{Quotas: openapi.QuotaWriteList{{Kind: "gpus", Quantity: quantity}}})
		require.NoError(t, err)
		require.Equal(t, quantity, result.Quotas[0].Quantity)
		require.NotEmpty(t, observer.leaseHeld)
		require.False(t, observer.leaseHeld[len(observer.leaseHeld)-1], "rendering runs after the Lease is released")
		require.False(t, observer.hasDeadline[len(observer.hasDeadline)-1], "rendering uses the request context")
	}
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
	used := allocationObj("3", "1")
	used.ObjectMeta = metav1.ObjectMeta{Name: "alloc", Namespace: "org-a", Labels: labels}

	scheme := runtime.NewScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
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
	require.NoError(t, coordinationv1.AddToScheme(scheme))
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

func TestUpdateAdoptsOneLegacyQuota(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	organizationID := ids.MustParseOrganizationID("a1111111-1111-4111-8111-111111111111")
	organization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{Namespace: "identity", Name: organizationID.String()},
		Status:     unikornv1.OrganizationStatus{Namespace: "org-a"},
	}
	gpus := metaObj("gpus", "1")
	legacy := &unikornv1.Quota{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "legacy-quota",
			Namespace: "org-a",
			Labels:    map[string]string{constants.OrganizationLabel: organizationID.String()},
		},
	}

	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(organization, &gpus, legacy).Build()
	_, err := New(k8s, "identity").Update(fixtures.HandlerContextFixture(t.Context(), 0), organizationID, &openapi.QuotasWrite{
		Quotas: openapi.QuotaWriteList{{Kind: "gpus", Quantity: 2}},
	})
	require.NoError(t, err)

	stored := &unikornv1.QuotaList{}
	require.NoError(t, k8s.List(t.Context(), stored, &client.ListOptions{Namespace: "org-a"}))
	require.Len(t, stored.Items, 1)
	require.Equal(t, "legacy-quota", stored.Items[0].Name)
}

func TestUpdateRejectsMultipleLegacyQuotas(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	organizationID := ids.MustParseOrganizationID("a1111111-1111-4111-8111-111111111111")
	organization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{Namespace: "identity", Name: organizationID.String()},
		Status:     unikornv1.OrganizationStatus{Namespace: "org-a"},
	}
	gpus := metaObj("gpus", "1")
	labels := map[string]string{constants.OrganizationLabel: organizationID.String()}
	first := &unikornv1.Quota{ObjectMeta: metav1.ObjectMeta{Name: "legacy-quota-a", Namespace: "org-a", Labels: labels}}
	second := &unikornv1.Quota{ObjectMeta: metav1.ObjectMeta{Name: "legacy-quota-b", Namespace: "org-a", Labels: labels}}

	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(organization, &gpus, first, second).Build()
	_, err := New(k8s, "identity").Update(fixtures.HandlerContextFixture(t.Context(), 0), organizationID, &openapi.QuotasWrite{
		Quotas: openapi.QuotaWriteList{{Kind: "gpus", Quantity: 2}},
	})

	require.ErrorIs(t, err, coreerrors.ErrConsistency)
}

func TestUpdateConcurrentCreatesOneQuota(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))
	require.NoError(t, unikornv1.AddToScheme(scheme))

	organizationID := ids.MustParseOrganizationID("a1111111-1111-4111-8111-111111111111")
	organization := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{Namespace: "identity", Name: organizationID.String()},
		Status:     unikornv1.OrganizationStatus{Namespace: "org-a"},
	}
	gpus := metaObj("gpus", "1")
	k8s := fake.NewClientBuilder().WithScheme(scheme).WithObjects(organization, &gpus).Build()
	quotas := New(k8s, "identity")
	request := &openapi.QuotasWrite{Quotas: openapi.QuotaWriteList{{Kind: "gpus", Quantity: 2}}}
	start := make(chan struct{})
	errs := make(chan error, 2)

	var wg sync.WaitGroup

	for range 2 {
		wg.Go(func() {
			<-start

			_, err := quotas.Update(fixtures.HandlerContextFixture(t.Context(), 0), organizationID, request)
			errs <- err
		})
	}

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}

	stored := &unikornv1.QuotaList{}
	require.NoError(t, k8s.List(t.Context(), stored, &client.ListOptions{Namespace: "org-a"}))
	require.Len(t, stored.Items, 1)
	require.Equal(t, quotaName, stored.Items[0].Name)
}
