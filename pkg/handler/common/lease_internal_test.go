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
	goerrors "errors"
	"fmt"
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
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const leaseTestNamespace = "identity"

var errRead = goerrors.New("read failed")

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
		t.Parallel()

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
		t.Parallel()

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
		t.Parallel()

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
		t.Parallel()

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

	// Every server version must contend on the same stored name.
	t.Run("stores the lease under the fixed organization name", func(t *testing.T) {
		t.Parallel()

		fakeClient := leaseTestClient(t)
		lease, _, err := AcquireOrganizationLease(t.Context(), fakeClient, leaseTestNamespace, organizationA)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, lease.Release(context.WithoutCancel(t.Context()))) })

		stored := &coordinationv1.Lease{}
		require.NoError(t, fakeClient.Get(t.Context(), client.ObjectKey{Namespace: leaseTestNamespace, Name: "unikorn-identity-allocation-a1111111-1111-4111-8111-111111111111"}, stored))
	})

	t.Run("reports an API call cut off by the request deadline as a conflict", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		fakeClient := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, _ client.WithWatch, _ client.Object, _ ...client.CreateOption) error {
				cancel()

				return ctx.Err()
			},
		}).Build()

		lease, _, err := AcquireOrganizationLease(ctx, fakeClient, leaseTestNamespace, organizationA)
		require.Nil(t, lease)
		require.True(t, servererrors.IsConflict(err))
	})

	t.Run("times the unchanged duration from completed observations", func(t *testing.T) {
		t.Parallel()

		var firstObserved, updatedAt time.Time

		duration := time.Second
		current := now
		delayed := false

		fakeClient := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
			// The first Create is throttled for most of a Lease duration.
			Create: func(ctx context.Context, cli client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if !delayed {
					delayed = true
					current = current.Add(900 * time.Millisecond)
				}

				return cli.Create(ctx, obj, opts...)
			},
			Get: func(ctx context.Context, cli client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				err := cli.Get(ctx, key, obj, opts...)
				if firstObserved.IsZero() {
					firstObserved = current
				}

				current = current.Add(100 * time.Millisecond)

				return err
			},
			Update: func(ctx context.Context, cli client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				updatedAt = current

				return cli.Update(ctx, obj, opts...)
			},
		}).WithObjects(&coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: leaseTestNamespace, Name: organizationLeaseName(organizationA)}}).Build()

		lease, _, err := AcquireOrganizationLease(t.Context(), fakeClient, leaseTestNamespace, organizationA,
			WithLeaseDuration(duration),
			withLeaseMargin(100*time.Millisecond),
			// Only the synthetic clock needs to advance between attempts.
			withLeaseRetry(0),
			withLeaseClock(func() time.Time { return current }),
		)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, lease.Release(context.WithoutCancel(t.Context()))) })
		require.GreaterOrEqual(t, updatedAt.Sub(firstObserved), duration)
	})

	// A request deadline of OrganizationLeaseTakeoverBudget must cover takeover of a
	// crashed holder and the critical section that follows it.
	t.Run("fits takeover and the critical section in the takeover budget", func(t *testing.T) {
		t.Parallel()

		client := leaseTestClient(t, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: leaseTestNamespace, Name: organizationLeaseName(organizationA)}})
		start := time.Now()
		calls := 0
		clock := func() time.Time {
			calls++
			if calls <= 2 {
				return start
			}

			return start.Add(organizationLeaseDuration + organizationLeaseRetry)
		}

		lease, lockedContext, err := AcquireOrganizationLease(t.Context(), client, leaseTestNamespace, organizationA,
			withLeaseRetry(time.Millisecond),
			withLeaseClock(clock),
		)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, lease.Release(context.WithoutCancel(t.Context()))) })

		deadline, ok := lockedContext.Deadline()
		require.True(t, ok)
		require.LessOrEqual(t, deadline.Sub(start), OrganizationLeaseTakeoverBudget)
		require.Positive(t, organizationLeaseDuration-organizationLeaseMargin, "the holder has a critical section")
	})
}

func TestOrganizationLeaseError(t *testing.T) {
	t.Parallel()

	organizationA := ids.MustParseOrganizationID("a1111111-1111-4111-8111-111111111111")

	fakeClient := leaseTestClient(t)
	lease, lockedContext, err := AcquireOrganizationLease(t.Context(), fakeClient, leaseTestNamespace, organizationA)
	require.NoError(t, err)

	require.Equal(t, errRead, lease.Error(lockedContext, errRead), "a failure before the deadline is reported as it is")

	require.NoError(t, lease.Release(context.WithoutCancel(t.Context())))

	err = lease.Error(lockedContext, errRead)
	require.True(t, servererrors.IsConflict(err))
	require.ErrorIs(t, err, errRead)
}

func TestWithOrganizationLease(t *testing.T) {
	t.Parallel()

	organizationA := ids.MustParseOrganizationID("a1111111-1111-4111-8111-111111111111")

	t.Run("runs the critical section under the lease and releases it", func(t *testing.T) {
		t.Parallel()

		fakeClient := leaseTestClient(t)

		result, err := WithOrganizationLease(t.Context(), fakeClient, leaseTestNamespace, organizationA, func(ctx context.Context, _ *OrganizationLease) (string, error) {
			leases := &coordinationv1.LeaseList{}
			require.NoError(t, fakeClient.List(ctx, leases))
			require.Len(t, leases.Items, 1)

			_, bounded := ctx.Deadline()
			require.True(t, bounded)

			return "written", nil
		})
		require.NoError(t, err)
		require.Equal(t, "written", result)

		leases := &coordinationv1.LeaseList{}
		require.NoError(t, fakeClient.List(t.Context(), leases))
		require.Empty(t, leases.Items)
	})

	t.Run("reports a critical-section deadline as a retryable conflict", func(t *testing.T) {
		t.Parallel()

		fakeClient := leaseTestClient(t)
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		t.Cleanup(cancel)

		_, err := WithOrganizationLease(ctx, fakeClient, leaseTestNamespace, organizationA, func(ctx context.Context, _ *OrganizationLease) (struct{}, error) {
			<-ctx.Done()

			return struct{}{}, fmt.Errorf("list quotas: %w", ctx.Err())
		})
		require.True(t, servererrors.IsConflict(err))
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
}
