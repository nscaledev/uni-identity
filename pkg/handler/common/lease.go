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
	"time"

	"github.com/google/uuid"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/ids"

	coordinationv1 "k8s.io/api/coordination/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	organizationLeaseDuration       = 10 * time.Second
	organizationLeaseMargin         = 2 * time.Second
	organizationLeaseRetry          = 50 * time.Millisecond
	organizationLeaseReleaseTimeout = time.Second
)

var ErrLeaseDeadline = goerrors.New("organization allocation lease deadline passed")

type leaseOptions struct {
	duration time.Duration
	margin   time.Duration
	retry    time.Duration
	now      func() time.Time
}

type LeaseOption func(*leaseOptions)

func WithLeaseDuration(duration time.Duration) LeaseOption {
	return func(options *leaseOptions) {
		options.duration = duration
	}
}

func withLeaseMargin(margin time.Duration) LeaseOption {
	return func(options *leaseOptions) {
		options.margin = margin
	}
}

func withLeaseRetry(retry time.Duration) LeaseOption {
	return func(options *leaseOptions) {
		options.retry = retry
	}
}

func withLeaseClock(now func() time.Time) LeaseOption {
	return func(options *leaseOptions) {
		options.now = now
	}
}

// OrganizationLease serializes quota and allocation decisions for one organization.
type OrganizationLease struct {
	client client.Client
	lease  *coordinationv1.Lease
	cancel context.CancelFunc
}

func organizationLeaseName(organizationID ids.OrganizationID) string {
	return "unikorn-identity-allocation-" + organizationID.String()
}

func organizationLeaseOptions(options []LeaseOption) *leaseOptions {
	result := &leaseOptions{
		duration: organizationLeaseDuration,
		margin:   organizationLeaseMargin,
		retry:    organizationLeaseRetry,
		now:      time.Now,
	}

	for _, option := range options {
		option(result)
	}

	return result
}

func leaseConflict(err error) error {
	return errors.HTTPConflict().WithError(err)
}

// AcquireOrganizationLease waits for the organization Lease, then returns a context
// whose deadline leaves time to abandon an overdue write.
func AcquireOrganizationLease(ctx context.Context, cli client.Client, namespace string, organizationID ids.OrganizationID, options ...LeaseOption) (*OrganizationLease, context.Context, error) {
	config := organizationLeaseOptions(options)
	name := organizationLeaseName(organizationID)
	identity := uuid.NewString()

	var observedResourceVersion string
	var observedAt time.Time

	for {
		now := config.now()
		lease := &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Spec: coordinationv1.LeaseSpec{
				HolderIdentity:       ptr.To(identity),
				LeaseDurationSeconds: ptr.To(int32(config.duration / time.Second)),
				AcquireTime:          &metav1.MicroTime{Time: now},
				RenewTime:            &metav1.MicroTime{Time: now},
			},
		}

		if err := cli.Create(ctx, lease); err == nil {
			return newOrganizationLease(ctx, cli, lease, now, config.margin)
		} else if !kerrors.IsAlreadyExists(err) {
			return nil, nil, fmt.Errorf("create organization lease: %w", err)
		}

		if err := cli.Get(ctx, client.ObjectKeyFromObject(lease), lease); err != nil {
			if kerrors.IsNotFound(err) {
				continue
			}

			return nil, nil, fmt.Errorf("get organization lease: %w", err)
		}

		if observedResourceVersion != lease.ResourceVersion {
			observedResourceVersion = lease.ResourceVersion
			observedAt = now
		} else if now.Sub(observedAt) >= config.duration {
			lease.Spec.HolderIdentity = ptr.To(identity)
			lease.Spec.LeaseDurationSeconds = ptr.To(int32(config.duration / time.Second))
			lease.Spec.AcquireTime = &metav1.MicroTime{Time: now}
			lease.Spec.RenewTime = &metav1.MicroTime{Time: now}

			if err := cli.Update(ctx, lease); err == nil {
				return newOrganizationLease(ctx, cli, lease, now, config.margin)
			} else if !kerrors.IsConflict(err) {
				return nil, nil, fmt.Errorf("take over organization lease: %w", err)
			}
		}

		timer := time.NewTimer(config.retry)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, nil, leaseConflict(fmt.Errorf("organization is busy: %w", ctx.Err()))
		case <-timer.C:
		}
	}
}

func newOrganizationLease(ctx context.Context, cli client.Client, lease *coordinationv1.Lease, acquiredAt time.Time, margin time.Duration) (*OrganizationLease, context.Context, error) {
	until := acquiredAt.Add(time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second).Add(-margin)
	if !until.After(acquiredAt) {
		return nil, nil, fmt.Errorf("organization lease margin leaves no critical section")
	}

	lockedContext, cancel := context.WithDeadline(ctx, until)

	return &OrganizationLease{client: cli, lease: lease.DeepCopy(), cancel: cancel}, lockedContext, nil
}

// Check rejects a write once the holder's critical-section deadline has passed.
func (l *OrganizationLease) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return leaseConflict(fmt.Errorf("%w: %w", ErrLeaseDeadline, err))
	}

	return nil
}

// Release deletes the Lease only if it has not been taken over.
func (l *OrganizationLease) Release(ctx context.Context) error {
	l.cancel()

	resourceVersion := l.lease.ResourceVersion

	err := l.client.Delete(ctx, l.lease, client.Preconditions{ResourceVersion: &resourceVersion})
	if kerrors.IsNotFound(err) || kerrors.IsConflict(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("release organization lease: %w", err)
	}

	return nil
}

// ReleaseOrganizationLease keeps cleanup bounded after the request has ended.
func ReleaseOrganizationLease(ctx context.Context, lease *OrganizationLease) {
	releaseContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), organizationLeaseReleaseTimeout)
	defer cancel()

	if err := lease.Release(releaseContext); err != nil {
		log.FromContext(ctx).Error(err, "unable to release organization allocation lease")
	}
}
