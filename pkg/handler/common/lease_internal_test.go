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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	servererrors "github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/ids"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const leaseTestNamespace = "identity"

func leaseTestClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, coordinationv1.AddToScheme(scheme))

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func TestOrganizationLease(t *testing.T) {
	t.Parallel()

	organizationA := ids.MustParseOrganizationID("a1111111-1111-4111-8111-111111111111")
	organizationB := ids.MustParseOrganizationID("b1111111-1111-4111-8111-111111111111")
	now := time.Now().UTC()

	t.Run("acquires independent leases for different organizations", func(t *testing.T) {
		client := leaseTestClient(t)
		options := []LeaseOption{WithLeaseDuration(4 * time.Second), withLeaseMargin(time.Second), withLeaseClock(func() time.Time { return now })}

		first, firstContext, err := AcquireOrganizationLease(t.Context(), client, leaseTestNamespace, organizationA, options...)
		require.NoError(t, err)
		require.NoError(t, first.Check(firstContext))
		t.Cleanup(func() { require.NoError(t, first.Release(context.WithoutCancel(t.Context()))) })

		second, secondContext, err := AcquireOrganizationLease(t.Context(), client, leaseTestNamespace, organizationB, options...)
		require.NoError(t, err)
		require.NoError(t, second.Check(secondContext))
		t.Cleanup(func() { require.NoError(t, second.Release(context.WithoutCancel(t.Context()))) })
	})

	t.Run("takes over only after an unchanged lease lasts a full duration", func(t *testing.T) {
		client := leaseTestClient(t, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: leaseTestNamespace, Name: organizationLeaseName(organizationA)}})
		calls := 0
		clock := func() time.Time {
			calls++
			if calls < 3 {
				return now
			}

			return now.Add(time.Second)
		}

		lease, _, err := AcquireOrganizationLease(t.Context(), client, leaseTestNamespace, organizationA,
			WithLeaseDuration(time.Second),
			withLeaseMargin(100*time.Millisecond),
			withLeaseRetry(time.Millisecond),
			withLeaseClock(clock),
		)
		require.NoError(t, err)
		require.NoError(t, lease.Release(context.WithoutCancel(t.Context())))
	})

	t.Run("reports contention as a retryable conflict", func(t *testing.T) {
		client := leaseTestClient(t, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: leaseTestNamespace, Name: organizationLeaseName(organizationA)}})
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		t.Cleanup(cancel)

		lease, _, err := AcquireOrganizationLease(ctx, client, leaseTestNamespace, organizationA,
			withLeaseRetry(time.Millisecond),
			withLeaseClock(func() time.Time { return now }),
		)
		require.Nil(t, lease)
		require.Error(t, err)
		require.True(t, servererrors.IsConflict(err))
	})

	t.Run("rejects writes after the holder deadline", func(t *testing.T) {
		t.Parallel()

		fakeClient := leaseTestClient(t)
		lease, lockedContext, err := AcquireOrganizationLease(t.Context(), fakeClient, leaseTestNamespace, organizationA)
		require.NoError(t, err)
		require.NoError(t, lease.Release(context.WithoutCancel(t.Context())))
		require.True(t, servererrors.IsConflict(lease.Check(lockedContext)))

		expired, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
		t.Cleanup(cancel)
		require.True(t, servererrors.IsConflict(lease.Check(expired)))
	})
	t.Run("does not release a lease another holder has taken over", func(t *testing.T) {
		fakeClient := leaseTestClient(t)
		lease, _, err := AcquireOrganizationLease(t.Context(), fakeClient, leaseTestNamespace, organizationA)
		require.NoError(t, err)

		current := &coordinationv1.Lease{}
		require.NoError(t, fakeClient.Get(t.Context(), client.ObjectKey{Namespace: leaseTestNamespace, Name: organizationLeaseName(organizationA)}, current))
		current.Spec.HolderIdentity = ptr.To("other")
		require.NoError(t, fakeClient.Update(t.Context(), current))
		require.NoError(t, lease.Release(context.WithoutCancel(t.Context())))
		require.NoError(t, fakeClient.Get(t.Context(), client.ObjectKey{Namespace: leaseTestNamespace, Name: organizationLeaseName(organizationA)}, current))
	})
}
