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

package main

import (
	"context"
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/readiness"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	toolscache "k8s.io/client-go/tools/cache"
)

func TestWatchReadiness(t *testing.T) {
	t.Parallel()
	gomega.RegisterFailHandler(ginkgo.Fail)
	ginkgo.RunSpecs(t, "Authorization cache readiness")
}

var _ = ginkgo.Describe("Read cache readiness wiring", func() {
	for _, scenario := range []struct {
		name   string
		object runtime.Object
		list   runtime.Object
		gates  bool
	}{
		{"a User watch", &unikornv1.User{}, &unikornv1.UserList{}, true},
		{"a Quota watch", &unikornv1.Quota{}, &unikornv1.QuotaList{}, false},
		{"an Allocation watch", &unikornv1.Allocation{}, &unikornv1.AllocationList{}, false},
	} {
		ginkgo.Context("When "+scenario.name+" is forbidden", func() {
			ginkgo.Describe("Given an otherwise synchronized informer", func() {
				ginkgo.It("gates readiness only when authorization uses the cached records", func(ctx ginkgo.SpecContext) {
					watches := readiness.NewWatches(0)
					options := readCacheOptions(runtime.NewScheme(), "identity", watches)
					lw := &toolscache.ListWatch{
						ListWithContextFunc: func(context.Context, metav1.ListOptions) (runtime.Object, error) { return scenario.list, nil },
						WatchFuncWithContext: func(context.Context, metav1.ListOptions) (watch.Interface, error) {
							return nil, kerrors.NewUnauthorized("watch denied")
						},
					}
					informer := options.NewInformer(lw, scenario.object, 0, toolscache.Indexers{})
					failures := make(chan error, 10)
					gomega.Expect(informer.SetWatchErrorHandlerWithContext(func(_ context.Context, _ *toolscache.Reflector, err error) {
						select {
						case failures <- err:
						default:
						}
					})).To(gomega.Succeed())
					runCtx, cancel := context.WithCancel(ctx)
					stopped := make(chan struct{})
					go func() { defer close(stopped); informer.RunWithContext(runCtx) }()
					ginkgo.DeferCleanup(func() { cancel(); gomega.Eventually(stopped).Should(gomega.BeClosed()) })
					gomega.Eventually(failures).Should(gomega.Receive())
					gomega.Expect(informer.HasSynced()).To(gomega.BeTrue())
					if scenario.gates {
						gomega.Expect(watches.Check(ctx)).To(gomega.HaveOccurred())
					} else {
						gomega.Expect(watches.Check(ctx)).To(gomega.Succeed())
					}
				})
			})
		})
	}
})
