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

package readiness

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	toolscache "k8s.io/client-go/tools/cache"
	"k8s.io/utils/clock"
)

var ErrWatchFailed = errors.New("read cache list/watch failing")

// Watches tracks reported failures, not the age of cached authorization data.
type Watches struct {
	mu      sync.Mutex
	streams []*watchHealth
	grace   time.Duration
	clock   clock.PassiveClock
}

// NewWatches allows brief reconnects. Recovery requires a watch to remain open
// for the same interval, even when its collection has no changes.
func NewWatches(grace time.Duration) *Watches {
	return &Watches{grace: grace, clock: clock.RealClock{}}
}

// NewInformer installs through controller-runtime's cache.Options.NewInformer.
// The error callback alone misses errors retried inside client-go's watch loop.
func (w *Watches) NewInformer(lw toolscache.ListerWatcher, object runtime.Object, resync time.Duration, indexes toolscache.Indexers) toolscache.SharedIndexInformer {
	return toolscache.NewSharedIndexInformer(w.track(lw, object), object, resync, indexes)
}

func (w *Watches) track(lw toolscache.ListerWatcher, object runtime.Object) *toolscache.ListWatch {
	health := &watchHealth{owner: w, name: fmt.Sprintf("%T", object)}
	w.mu.Lock()
	w.streams = append(w.streams, health)
	w.mu.Unlock()

	parent := toolscache.ToListerWatcherWithContext(lw)

	return &toolscache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, options metav1.ListOptions) (runtime.Object, error) {
			result, err := parent.ListWithContext(ctx, options)
			health.failed(ctx, err, nil)

			return result, err
		},
		WatchFuncWithContext: func(ctx context.Context, options metav1.ListOptions) (watch.Interface, error) {
			stream, err := parent.WatchWithContext(ctx, options)
			if err != nil {
				health.failed(ctx, err, nil)

				return nil, err
			}

			return health.monitor(ctx, stream), nil
		},
	}
}

func (w *Watches) Check(context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := w.clock.Now()

	for _, health := range w.streams {
		health.recover(now)

		if !health.failure.IsZero() && now.Sub(health.failure) >= w.grace {
			return fmt.Errorf("%w: %s", ErrWatchFailed, health.name)
		}
	}

	return nil
}

type watchHealth struct {
	owner   *Watches
	name    string
	failure time.Time
	active  *monitoredWatch
}

func (h *watchHealth) recover(now time.Time) {
	if h.active != nil && now.Sub(h.active.started) >= h.owner.grace {
		h.failure = time.Time{}
	}
}

func (h *watchHealth) failed(ctx context.Context, err error, stream *monitoredWatch) {
	if err == nil || ctx.Err() != nil || kerrors.IsResourceExpired(err) || kerrors.IsGone(err) {
		return
	}

	h.owner.mu.Lock()
	defer h.owner.mu.Unlock()

	if stream != nil && h.active != stream {
		return
	}

	now := h.owner.clock.Now()
	h.recover(now)
	h.active = nil

	if h.failure.IsZero() {
		h.failure = now
	}
}

type monitoredWatch struct {
	watch.Interface
	result  chan watch.Event
	done    chan struct{}
	once    sync.Once
	started time.Time
}

func (w *monitoredWatch) Stop() {
	w.once.Do(func() {
		close(w.done)
		w.Interface.Stop()
	})
}

func (w *monitoredWatch) ResultChan() <-chan watch.Event {
	return w.result
}

func (h *watchHealth) monitor(ctx context.Context, source watch.Interface) watch.Interface {
	w := &monitoredWatch{Interface: source, result: make(chan watch.Event), done: make(chan struct{}), started: h.owner.clock.Now()}
	h.owner.mu.Lock()
	h.active = w
	h.owner.mu.Unlock()

	go h.forward(ctx, w)

	return w
}

func (h *watchHealth) forward(ctx context.Context, w *monitoredWatch) {
	defer close(w.result)
	defer w.Stop()
	defer h.closed(w)

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case event, ok := <-w.Interface.ResultChan():
			if !ok {
				h.closedUnexpectedly(ctx, w)

				return
			}

			if !h.deliver(ctx, w, event) {
				return
			}
		}
	}
}

func (h *watchHealth) deliver(ctx context.Context, w *monitoredWatch, event watch.Event) bool {
	if event.Type == watch.Error {
		h.failed(ctx, kerrors.FromObject(event.Object), w)
	}

	select {
	case w.result <- event:
		return event.Type != watch.Error
	case <-ctx.Done():
		return false
	case <-w.done:
		return false
	}
}

func (h *watchHealth) closedUnexpectedly(ctx context.Context, w *monitoredWatch) {
	select {
	case <-w.done:
	default:
		if h.owner.clock.Since(w.started) < h.owner.grace {
			h.failed(ctx, ErrWatchFailed, w)
		}
	}
}

func (h *watchHealth) closed(w *monitoredWatch) {
	h.owner.mu.Lock()
	defer h.owner.mu.Unlock()

	if h.active == w {
		h.recover(h.owner.clock.Now())
		h.active = nil
	}
}
