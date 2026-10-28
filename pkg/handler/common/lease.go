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
	organizationLeaseDuration = 3 * time.Second
	organizationLeaseMargin   = time.Second
	organizationLeaseRetry    = 50 * time.Millisecond

	// OrganizationLeaseReleaseTimeout bounds Lease cleanup, which may run after the
	// request deadline has passed.
	OrganizationLeaseReleaseTimeout = time.Second

	// OrganizationLeaseTakeoverBudget is the request time needed to take over a crashed
	// holder's Lease and still have the full critical section.
	OrganizationLeaseTakeoverBudget = organizationLeaseDuration + organizationLeaseRetry + organizationLeaseDuration - organizationLeaseMargin
)

var (
	ErrLeaseDeadline = goerrors.New("organization allocation lease deadline passed")
	ErrLeaseMargin   = goerrors.New("organization lease duration and margin leave no critical section")
)

type leaseOptions struct {
	duration time.Duration
	margin   time.Duration
	retry    time.Duration
	now      func() time.Time
}

type LeaseOption func(*leaseOptions)

func withLeaseDuration(duration time.Duration) LeaseOption {
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

// organizationLeaseOptions applies the options and rejects a duration and margin
// that leave no critical section, before any Lease is written.
func organizationLeaseOptions(options []LeaseOption) (*leaseOptions, error) {
	result := &leaseOptions{
		duration: organizationLeaseDuration,
		margin:   organizationLeaseMargin,
		retry:    organizationLeaseRetry,
		now:      time.Now,
	}

	for _, option := range options {
		option(result)
	}

	// The Lease stores whole seconds, so contenders must wait the stored duration.
	result.duration = result.duration.Truncate(time.Second)

	if result.duration < time.Second || result.margin >= result.duration {
		return nil, ErrLeaseMargin
	}

	return result, nil
}

// hold marks the Lease as held by identity from now.
func (o *leaseOptions) hold(lease *coordinationv1.Lease, identity string, now time.Time) {
	lease.Spec.HolderIdentity = ptr.To(identity)
	lease.Spec.LeaseDurationSeconds = ptr.To(int32(o.duration / time.Second)) //nolint:gosec // durations are validated by organizationLeaseOptions.
	lease.Spec.AcquireTime = &metav1.MicroTime{Time: now}
	lease.Spec.RenewTime = &metav1.MicroTime{Time: now}
}

func leaseConflict(err error) error {
	return errors.HTTPConflict().WithError(err)
}

// isContextError reports whether a call failed because its context ended, however
// it was wrapped on the way back.
func isContextError(err error) bool {
	return goerrors.Is(err, context.DeadlineExceeded) || goerrors.Is(err, context.Canceled)
}

// acquireError reports an API call cut off by the request deadline as the same
// retryable conflict as waiting too long. Any other failure keeps its cause, even
// if the deadline has also passed.
func acquireError(action string, err error) error {
	if isContextError(err) {
		return leaseConflict(fmt.Errorf("organization is busy: %w", err))
	}

	return fmt.Errorf("%s organization lease: %w", action, err)
}

// AcquireOrganizationLease waits for the organization Lease, then returns a context
// whose deadline leaves time to abandon an overdue write.
//
//nolint:cyclop,wsl // Lease creation and takeover share the retry loop.
func AcquireOrganizationLease(ctx context.Context, cli client.Client, namespace string, organizationID ids.OrganizationID, options ...LeaseOption) (*OrganizationLease, context.Context, error) {
	config, err := organizationLeaseOptions(options)
	if err != nil {
		return nil, nil, err
	}

	name := organizationLeaseName(organizationID)
	identity := uuid.NewString()

	var observedResourceVersion string
	var observedAt time.Time

	for {
		now := config.now()
		lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
		config.hold(lease, identity, now)

		if err := cli.Create(ctx, lease); err == nil {
			return newOrganizationLease(ctx, cli, lease, now, config)
		} else if !kerrors.IsAlreadyExists(err) {
			return nil, nil, acquireError("create", err)
		}

		if err := cli.Get(ctx, client.ObjectKeyFromObject(lease), lease); err != nil {
			if kerrors.IsNotFound(err) {
				continue
			}

			return nil, nil, acquireError("get", err)
		}

		// Time the observation after Get returns, so a slow Create or Get cannot
		// count towards the unchanged duration.
		observed := config.now()

		if observedResourceVersion != lease.ResourceVersion {
			observedResourceVersion = lease.ResourceVersion
			observedAt = observed
		} else if observed.Sub(observedAt) >= config.duration {
			config.hold(lease, identity, observed)

			if err := cli.Update(ctx, lease); err == nil {
				return newOrganizationLease(ctx, cli, lease, observed, config)
			} else if !kerrors.IsConflict(err) {
				return nil, nil, acquireError("take over", err)
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

func newOrganizationLease(ctx context.Context, cli client.Client, lease *coordinationv1.Lease, acquiredAt time.Time, config *leaseOptions) (*OrganizationLease, context.Context, error) {
	lockedContext, cancel := context.WithDeadline(ctx, acquiredAt.Add(config.duration-config.margin))

	return &OrganizationLease{client: cli, lease: lease.DeepCopy(), cancel: cancel}, lockedContext, nil
}

// Check rejects a write once the holder's critical-section deadline has passed.
func (l *OrganizationLease) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return leaseConflict(fmt.Errorf("%w: %w", ErrLeaseDeadline, err))
	}

	return nil
}

// Error reports a failure inside the critical section. A call cut off by the
// critical-section deadline is the same retryable conflict as waiting too long for
// the Lease, whatever status the caller wrapped it in. Any other failure, such as a
// rejected request, is reported as it is.
func (l *OrganizationLease) Error(err error) error {
	if isContextError(err) {
		return leaseConflict(fmt.Errorf("%w: %w", ErrLeaseDeadline, err))
	}

	return err
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
	releaseContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), OrganizationLeaseReleaseTimeout)
	defer cancel()

	if err := lease.Release(releaseContext); err != nil {
		log.FromContext(ctx).Error(err, "unable to release organization allocation lease")
	}
}

// WithOrganizationLease runs fn under the organization Lease with the bounded context,
// releases the Lease, and reports a call cut off by the deadline as a retryable conflict.
func WithOrganizationLease[T any](ctx context.Context, cli client.Client, namespace string, organizationID ids.OrganizationID, fn func(ctx context.Context, lease *OrganizationLease) (T, error), options ...LeaseOption) (T, error) {
	var zero T

	lease, lockedContext, err := AcquireOrganizationLease(ctx, cli, namespace, organizationID, options...)
	if err != nil {
		return zero, err
	}
	defer ReleaseOrganizationLease(ctx, lease)

	result, err := fn(lockedContext, lease)
	if err != nil {
		return zero, lease.Error(err)
	}

	return result, nil
}
