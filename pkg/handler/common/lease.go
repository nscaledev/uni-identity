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
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/constants"
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

	// organizationLeaseBackoff caps the wait between attempts as a multiple of the
	// first. Every waiter on a replica polls through one client rate limiter for
	// Leases, so fixed fast polling starves other organizations' Lease calls.
	organizationLeaseBackoff = 8

	// OrganizationLeaseReleaseTimeout bounds Lease cleanup, which may run after the
	// request deadline has passed.
	OrganizationLeaseReleaseTimeout = time.Second

	// OrganizationLeaseTakeoverBudget is the request time needed to take over a crashed
	// holder's Lease and still have the full critical section.
	OrganizationLeaseTakeoverBudget = organizationLeaseDuration + organizationLeaseBackoff*organizationLeaseRetry + organizationLeaseDuration - organizationLeaseMargin
)

var (
	ErrLeaseDeadline = goerrors.New("organization allocation lease deadline passed")
	ErrLeaseMargin   = goerrors.New("organization lease duration and margin leave no critical section")
)

// Lease metric names, with the outcomes recorded in their result label.
const (
	leaseAcquisitionsName = "unikorn_identity_organization_lease_acquisitions"
	leaseWaitName         = "unikorn_identity_organization_lease_wait_seconds"
	leaseSectionsName     = "unikorn_identity_organization_lease_sections"
	leaseReleasesName     = "unikorn_identity_organization_lease_releases"

	leaseResultCreated     = "created"
	leaseResultTakenOver   = "taken_over"
	leaseResultTimedOut    = "timed_out"
	leaseResultRateLimited = "rate_limited"
	leaseResultError       = "error"
	leaseResultOK          = "ok"
	leaseResultOverdue     = "overdue"
	leaseResultFailed      = "failed"
	leaseResultReleased    = "released"
	leaseResultLost        = "lost"
	leaseResultAbandoned   = "abandoned"
)

// leaseMetrics surfaces the Lease failures that wedge an organization: holders
// that crash or overrun, contenders that give up, and Leases left behind.
type leaseMetrics struct {
	acquisitions metric.Int64Counter
	wait         metric.Float64Histogram
	sections     metric.Int64Counter
	releases     metric.Int64Counter
}

func newLeaseMetrics(meter metric.Meter) *leaseMetrics {
	// The errors only report an invalid instrument configuration; the names,
	// descriptions and units are static, and the API returns usable no-op
	// instruments regardless, so there is nothing actionable to handle.
	acquisitions, _ := meter.Int64Counter(leaseAcquisitionsName,
		metric.WithDescription("Organization Lease acquisitions by result: created a new Lease; taken_over from a crashed or overrun holder; timed_out when the request context ended; rate_limited when the client refused a call before its deadline; error for other API failures."),
		metric.WithUnit("{acquisition}"))
	wait, _ := meter.Float64Histogram(leaseWaitName,
		metric.WithDescription("Time spent waiting to acquire an organization Lease, for acquisitions that succeeded."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0, 0.05, 0.1, 0.25, 0.5, 1, 2, 3, 4, 6, 8))
	sections, _ := meter.Int64Counter(leaseSectionsName,
		metric.WithDescription("Organization Lease critical sections by result: ok completed successfully; overdue ended with a context error; rate_limited when the client refused a call before its deadline; failed for other errors."),
		metric.WithUnit("{section}"))
	releases, _ := meter.Int64Counter(leaseReleasesName,
		metric.WithDescription("Organization Lease releases by outcome. Lost means another replica had already taken the Lease over; abandoned means a cut-off write left it to expire on purpose; failed means a delete failed and left it to expire."),
		metric.WithUnit("{release}"))

	return &leaseMetrics{acquisitions: acquisitions, wait: wait, sections: sections, releases: releases}
}

func leaseResult(result string) metric.MeasurementOption {
	return metric.WithAttributes(attribute.String("result", result))
}

func (m *leaseMetrics) acquired(ctx context.Context, result string, waited time.Duration) {
	m.acquisitions.Add(ctx, 1, leaseResult(result))
	m.wait.Record(ctx, waited.Seconds())
}

//nolint:gochecknoglobals // The default instruments are created once on the application meter.
var (
	defaultLeaseMetricsOnce sync.Once
	defaultLeaseMetrics     *leaseMetrics
)

func leaseMetricsDefault() *leaseMetrics {
	defaultLeaseMetricsOnce.Do(func() {
		defaultLeaseMetrics = newLeaseMetrics(otel.Meter(constants.Application))
	})

	return defaultLeaseMetrics
}

type leaseOptions struct {
	duration time.Duration
	margin   time.Duration
	retry    time.Duration
	now      func() time.Time
	metrics  *leaseMetrics
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

func withLeaseMeter(meter metric.Meter) LeaseOption {
	return func(options *leaseOptions) {
		options.metrics = newLeaseMetrics(meter)
	}
}

// OrganizationLease serializes quota and allocation decisions for one organization.
type OrganizationLease struct {
	client  client.Client
	lease   *coordinationv1.Lease
	cancel  context.CancelFunc
	metrics *leaseMetrics
	// writing is set once the holder has passed Check, so a write may be in flight.
	writing bool
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

	if result.metrics == nil {
		result.metrics = leaseMetricsDefault()
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

// leaseConflict tells the client the organization is busy and the request can be
// retried. The default conflict description says the resource already exists,
// which is wrong here.
func leaseConflict(err error) error {
	return errors.FromOpenAPIError(http.StatusConflict, nil, &coreopenapi.Error{
		Error:            coreopenapi.Conflict,
		ErrorDescription: "another quota or allocation change for this organization is in progress, retry the request",
	}).WithError(err)
}

// isContextError reports whether a call failed because its context ended, however
// it was wrapped on the way back.
func isContextError(err error) bool {
	return goerrors.Is(err, context.DeadlineExceeded) || goerrors.Is(err, context.Canceled)
}

func leaseFailureResult(err error, contextResult, fallback string) string {
	// A context error wins over a rate-limit match: the cut-off call may have been
	// a write that was sent, and WithOrganizationLease abandons the Lease for it.
	if isContextError(err) {
		return contextResult
	}

	if isRateLimited(err) {
		return leaseResultRateLimited
	}

	return fallback
}

// isRateLimited reports whether the client rate limiter refused a call because it
// could not start before the deadline. The limiter's error has no type and does not
// wrap the context error, so it is matched by its message at each level of the
// chain: a caller may have wrapped it in an error whose message hides the cause.
func isRateLimited(err error) bool {
	for ; err != nil; err = goerrors.Unwrap(err) {
		if strings.Contains(err.Error(), rateLimiterDeadline) {
			return true
		}
	}

	return false
}

// rateLimiterDeadline is the message golang.org/x/time/rate gives when a wait
// would outlast the context.
const rateLimiterDeadline = "would exceed context deadline"

// backoff returns the wait before the next attempt: twice the last, up to the cap,
// with jitter so waiters on different replicas spread out.
func (o *leaseOptions) backoff(last time.Duration) time.Duration {
	next := min(max(2*last, o.retry), organizationLeaseBackoff*o.retry)

	return next/2 + rand.N(next/2+1) //nolint:gosec // jitter, not a secret
}

// acquireError reports an API call cut off by the request deadline as the same
// retryable conflict as waiting too long. Any other failure keeps its cause, even
// if the deadline has also passed.
func acquireError(ctx context.Context, config *leaseOptions, action string, err error) error {
	result := leaseFailureResult(err, leaseResultTimedOut, leaseResultError)
	config.metrics.acquisitions.Add(ctx, 1, leaseResult(result))

	if result != leaseResultError {
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
	var observedAt, start time.Time
	var wait time.Duration

	for {
		now := config.now()
		if start.IsZero() {
			start = now
		}

		lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
		config.hold(lease, identity, now)

		if err := cli.Create(ctx, lease); err == nil {
			config.metrics.acquired(ctx, leaseResultCreated, now.Sub(start))

			return newOrganizationLease(ctx, cli, lease, now, config)
		} else if !kerrors.IsAlreadyExists(err) {
			return nil, nil, acquireError(ctx, config, "create", err)
		}

		if err := cli.Get(ctx, client.ObjectKeyFromObject(lease), lease); err != nil {
			if kerrors.IsNotFound(err) {
				continue
			}

			return nil, nil, acquireError(ctx, config, "get", err)
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
				config.metrics.acquired(ctx, leaseResultTakenOver, observed.Sub(start))

				return newOrganizationLease(ctx, cli, lease, observed, config)
			} else if !kerrors.IsConflict(err) {
				return nil, nil, acquireError(ctx, config, "take over", err)
			}
		}

		wait = config.backoff(wait)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}

			config.metrics.acquisitions.Add(ctx, 1, leaseResult(leaseResultTimedOut))

			return nil, nil, leaseConflict(fmt.Errorf("organization is busy: %w", ctx.Err()))
		case <-timer.C:
		}
	}
}

func newOrganizationLease(ctx context.Context, cli client.Client, lease *coordinationv1.Lease, acquiredAt time.Time, config *leaseOptions) (*OrganizationLease, context.Context, error) {
	lockedContext, cancel := context.WithDeadline(ctx, acquiredAt.Add(config.duration-config.margin))

	return &OrganizationLease{client: cli, lease: lease.DeepCopy(), cancel: cancel, metrics: config.metrics}, lockedContext, nil
}

// Check rejects a write once the holder's critical-section deadline has passed,
// and otherwise records that a write may now be in flight.
func (l *OrganizationLease) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return leaseConflict(fmt.Errorf("%w: %w", ErrLeaseDeadline, err))
	}

	l.writing = true

	return nil
}

// Error reports a failure inside the critical section. A call cut off by the
// critical-section deadline is the same retryable conflict as waiting too long for
// the Lease, whatever status the caller wrapped it in. Any other failure, such as a
// rejected request, is reported as it is.
func (l *OrganizationLease) Error(ctx context.Context, err error) error {
	result := leaseFailureResult(err, leaseResultOverdue, leaseResultFailed)
	l.metrics.sections.Add(ctx, 1, leaseResult(result))

	if result != leaseResultFailed {
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
		l.metrics.releases.Add(ctx, 1, leaseResult(leaseResultLost))

		return nil
	}

	if err != nil {
		l.metrics.releases.Add(ctx, 1, leaseResult(leaseResultFailed))

		return fmt.Errorf("release organization lease: %w", err)
	}

	l.metrics.releases.Add(ctx, 1, leaseResult(leaseResultReleased))

	return nil
}

// abandon leaves the Lease to expire. A write that was sent and then cut off by
// the deadline may still be committed by the API server, so contenders must wait
// out a full Lease duration rather than read straight after a release.
func (l *OrganizationLease) abandon(ctx context.Context) {
	l.cancel()
	l.metrics.releases.Add(ctx, 1, leaseResult(leaseResultAbandoned))
	log.FromContext(ctx).Info("leaving organization allocation lease to expire after a cut-off write", "lease", l.lease.Name)
}

// ReleaseOrganizationLease keeps cleanup bounded after the request has ended.
func ReleaseOrganizationLease(ctx context.Context, lease *OrganizationLease) {
	releaseContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), OrganizationLeaseReleaseTimeout)
	defer cancel()

	if err := lease.Release(releaseContext); err != nil {
		log.FromContext(ctx).Error(err, "unable to release organization allocation lease")
	}
}

// WithOrganizationLease runs fn under the organization Lease with the bounded context
// and reports a call cut off by the deadline as a retryable conflict. It releases the
// Lease afterwards, unless the cut-off call may have been the write itself, in which
// case the Lease is left to expire.
func WithOrganizationLease[T any](ctx context.Context, cli client.Client, namespace string, organizationID ids.OrganizationID, fn func(ctx context.Context, lease *OrganizationLease) (T, error), options ...LeaseOption) (T, error) {
	var zero T

	lease, lockedContext, err := AcquireOrganizationLease(ctx, cli, namespace, organizationID, options...)
	if err != nil {
		return zero, err
	}

	writeCutOff := false

	defer func() {
		if writeCutOff {
			lease.abandon(ctx)
		} else {
			ReleaseOrganizationLease(ctx, lease)
		}
	}()

	result, err := fn(lockedContext, lease)
	if err != nil {
		// A write the rate limiter refused was never sent, so the Lease can go.
		writeCutOff = lease.writing && isContextError(err)

		return zero, lease.Error(ctx, err)
	}

	lease.metrics.sections.Add(ctx, 1, leaseResult(leaseResultOK))

	return result, nil
}
