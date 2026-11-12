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

//nolint:revive,testpackage // Ginkgo DSL; inspect watch state without widening the production API.
package readiness

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	toolscache "k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"
)

func TestWatches(t *testing.T) {
	t.Parallel()

	RegisterFailHandler(Fail)
	RunSpecs(t, "Read cache watch readiness")
}

var _ = Describe("Read cache watches", func() {
	const grace = 30 * time.Second
	var (
		ctx       context.Context
		clock     *clocktesting.FakeClock
		health    *Watches
		parent    *toolscache.ListWatch
		tracked   *toolscache.ListWatch
		forbidden *kerrors.StatusError
	)

	BeforeEach(func() {
		ctx = context.Background()
		clock = clocktesting.NewFakeClock(time.Date(2026, time.November, 12, 0, 0, 0, 0, time.UTC))
		health = NewWatches(grace)
		health.clock = clock
		forbidden = kerrors.NewForbidden(schema.GroupResource{Resource: "users"}, "", ErrWatchFailed)
		parent = &toolscache.ListWatch{
			ListWithContextFunc: func(context.Context, metav1.ListOptions) (runtime.Object, error) {
				return &unikornv1.UserList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}}, nil
			},
			WatchFuncWithContext: func(context.Context, metav1.ListOptions) (watch.Interface, error) {
				return nil, forbidden
			},
		}
		tracked = health.track(parent, &unikornv1.User{})
	})

	open := func() (*watch.RaceFreeFakeWatcher, watch.Interface) {
		source := watch.NewRaceFreeFake()
		parent.WatchFuncWithContext = func(context.Context, metav1.ListOptions) (watch.Interface, error) { return source, nil }
		stream, err := tracked.WatchWithContext(ctx, metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(stream.Stop)

		return source, stream
	}

	failWatch := func() {
		_, err := tracked.WatchWithContext(ctx, metav1.ListOptions{})
		Expect(err).To(MatchError(forbidden))
	}

	Context("When list succeeds but watch fails", func() {
		Describe("Given repeated denied watches", func() {
			It("withdraws readiness after the first failure's grace period", func() {
				failWatch()
				Expect(health.Check(ctx)).To(Succeed())
				clock.Step(grace - time.Second)
				_, err := tracked.ListWithContext(ctx, metav1.ListOptions{})
				Expect(err).NotTo(HaveOccurred())
				failWatch()
				Expect(health.Check(ctx)).To(Succeed())
				clock.Step(time.Second)
				Expect(health.Check(ctx)).To(MatchError(ContainSubstring(ErrWatchFailed.Error())))
			})
		})
	})

	Context("When list fails", func() {
		Describe("Given a cache that cannot relist", func() {
			It("withdraws readiness even without another watch attempt", func() {
				parent.ListWithContextFunc = func(context.Context, metav1.ListOptions) (runtime.Object, error) { return nil, forbidden }
				_, err := tracked.ListWithContext(ctx, metav1.ListOptions{})
				Expect(err).To(HaveOccurred())
				clock.Step(grace)
				Expect(health.Check(ctx)).To(HaveOccurred())
			})
		})
	})

	Context("When a watch reconnects", func() {
		Describe("Given an existing failure episode", func() {
			BeforeEach(func() { failWatch(); clock.Step(grace) })

			It("recovers only after a quiet stream stays open for the grace period", func() {
				_, _ = open()
				Expect(health.Check(ctx)).To(HaveOccurred())
				clock.Step(grace - time.Second)
				Expect(health.Check(ctx)).To(HaveOccurred())
				clock.Step(time.Second)
				Expect(health.Check(ctx)).To(Succeed())
			})

			It("keeps failing across successful opens followed by error events", func() {
				for range 3 {
					source, stream := open()
					source.Modify(&unikornv1.User{ObjectMeta: metav1.ObjectMeta{Name: "user", ResourceVersion: "2"}})
					Expect((<-stream.ResultChan()).Type).To(Equal(watch.Modified))
					clock.Step(10 * time.Second)
					source.Error(&forbidden.ErrStatus)
					Expect((<-stream.ResultChan()).Type).To(Equal(watch.Error))
					Eventually(stream.ResultChan()).Should(BeClosed())
					Expect(health.Check(ctx)).To(HaveOccurred())
				}
			})

			It("keeps failing across short streams that close without errors", func() {
				for range 3 {
					source, stream := open()
					clock.Step(10 * time.Second)
					source.Stop()
					Eventually(stream.ResultChan()).Should(BeClosed())
					Expect(health.Check(ctx)).To(HaveOccurred())
				}
			})

			It("records stable recovery on closure even without an intervening probe", func() {
				source, stream := open()
				clock.Step(grace)
				source.Stop()
				Eventually(stream.ResultChan()).Should(BeClosed())
				Expect(health.Check(ctx)).To(Succeed())
			})

			It("does not let one healthy informer conceal another failed informer", func() {
				other := health.track(&toolscache.ListWatch{WatchFuncWithContext: parent.WatchFuncWithContext}, &unikornv1.User{})
				_, _ = open()
				clock.Step(grace)
				// These are distinct informer instances of the same resource kind.
				_, err := other.WatchWithContext(ctx, metav1.ListOptions{})
				Expect(err).To(HaveOccurred())
				clock.Step(grace)
				Expect(health.Check(ctx)).To(HaveOccurred())
			})
		})
	})

	Context("When a watch expires or is stopped", func() {
		Describe("Given routine lifecycle events", func() {
			It("does not classify an expired error followed by closure as a failure", func() {
				source, stream := open()
				expired := kerrors.NewResourceExpired("relist needed")
				source.Error(&expired.ErrStatus)
				source.Stop()
				Expect((<-stream.ResultChan()).Type).To(Equal(watch.Error))
				Eventually(stream.ResultChan()).Should(BeClosed())
				clock.Step(grace)
				Expect(health.Check(ctx)).To(Succeed())
			})

			It("stops forwarding when cancelled while delivery is blocked", func() {
				source, stream := open()
				source.Add(&unikornv1.User{})
				stream.Stop()
				Eventually(stream.ResultChan()).Should(BeClosed())
				clock.Step(grace)
				Expect(health.Check(ctx)).To(Succeed())
			})

			It("does not let an old stream's closure erase a replacement watch", func() {
				_, old := open()
				_, _ = open()
				old.Stop()
				Eventually(old.ResultChan()).Should(BeClosed())
				health.mu.Lock()
				defer health.mu.Unlock()
				Expect(health.streams[0].active).NotTo(BeNil())
			})
		})
	})

	Context("When client-go handles watch errors internally", func() {
		Describe("Given the stock informer and a watch error event", func() {
			It("withdraws readiness although the outer watch error callback never runs", func() {
				opened := make(chan *watch.RaceFreeFakeWatcher, 10)
				retried := make(chan struct{})
				calls := 0
				parent.WatchFuncWithContext = func(ctx context.Context, _ metav1.ListOptions) (watch.Interface, error) {
					calls++
					if calls > 1 {
						close(retried)
						<-ctx.Done()

						return nil, ctx.Err()
					}

					source := watch.NewRaceFreeFake()
					opened <- source

					return source, nil
				}
				informer := health.NewInformer(parent, &unikornv1.User{}, 0, toolscache.Indexers{})
				callback := make(chan error, 10)
				Expect(informer.SetWatchErrorHandlerWithContext(func(_ context.Context, _ *toolscache.Reflector, err error) { callback <- err })).To(Succeed())
				stopped := make(chan struct{})
				runCtx, cancel := context.WithCancel(ctx)
				go func() { defer close(stopped); informer.RunWithContext(runCtx) }()
				DeferCleanup(func() { cancel(); Eventually(stopped).Should(BeClosed()) })
				var source *watch.RaceFreeFakeWatcher
				Eventually(opened).Should(Receive(&source))
				// Complete WatchList's initial snapshot before sending the failure.
				source.Action(watch.Bookmark, &unikornv1.User{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "1", Annotations: map[string]string{metav1.InitialEventsAnnotationKey: "true"}}})
				Eventually(informer.HasSynced).Should(BeTrue())
				source.Error(&forbidden.ErrStatus)
				Eventually(retried, 3*time.Second).Should(BeClosed())
				Eventually(func() bool { health.mu.Lock(); defer health.mu.Unlock(); return !health.streams[1].failure.IsZero() }).Should(BeTrue())
				clock.Step(grace)
				Expect(health.Check(ctx)).To(HaveOccurred())
				Expect(callback).To(BeEmpty())
			})
		})
	})
})
