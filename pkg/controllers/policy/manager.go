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

package policy

import (
	"context"
	"fmt"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coremanager "github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/manager/options"
	"github.com/unikorn-cloud/core/pkg/util"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	policycontroller "github.com/unikorn-cloud/identity/pkg/authz/cerbos/controller"
	"github.com/unikorn-cloud/identity/pkg/constants"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// policyStoreRequestName names the single synthetic reconcile request every
// Role event collapses to.  The reconciler regenerates the whole store from
// a full Role list, so per-object requests would only cause redundant runs;
// one fixed key also means the workqueue dedups bursts for free.
const policyStoreRequestName = "cerbos-policy-store"

// Factory provides methods that can build a type specific controller.
//
// Unlike the sibling factories this one does not construct
// coremanager.NewReconciler: that is a strict 1:1 object-lifecycle reconciler
// (finalizers, status conditions) and does not fit a fan-in controller whose
// reconciled unit is the whole Role set.  The domain logic lives in
// pkg/authz/cerbos/controller; this factory stays thin.
type Factory struct {
	// controllerOptions is the flag set returned by Options, retained so
	// Initialize can validate it after flag parsing.
	controllerOptions *policycontroller.Options

	// client is the uncached client built by Initialize.  The reconciler
	// must not read the policy store ConfigMap through the manager's
	// cache-backed client: that would start a cluster-wide ConfigMap
	// informer, which the chart's deliberately narrow namespaced RBAC
	// forbids.
	client client.Client

	// namespace is the identity namespace (--namespace), captured in
	// Initialize so RegisterWatches can scope the ConfigMap watch to it.
	namespace string

	// configMapCache is a namespace-scoped cache dedicated to watching the
	// managed policy store ConfigMap.  It exists precisely because the
	// manager's own cache is cluster-wide: watching ConfigMaps through that
	// would start a cluster-wide ConfigMap informer — the same anti-pattern
	// the reconciler's uncached client avoids, and one the controller's
	// namespaced RBAC (list/watch on configmaps in --namespace only, no
	// ClusterRole) forbids.  A cache scoped to --namespace issues a namespaced
	// list/watch the chart's Role already permits.
	configMapCache cache.Cache
}

var _ coremanager.ControllerFactory = &Factory{}

var _ coremanager.ControllerInitializer = &Factory{}

// Metadata returns the application, version and revision.
func (*Factory) Metadata() util.ServiceDescriptor {
	return constants.ServiceDescriptor()
}

// Options returns any options to be added to the CLI flags and passed to the reconciler.
func (f *Factory) Options() coremanager.ControllerOptions {
	f.controllerOptions = &policycontroller.Options{}

	return f.controllerOptions
}

// Initialize validates the parsed options and builds the uncached client,
// failing the manager fast on unusable configuration.
func (f *Factory) Initialize(_ context.Context, manager manager.Manager, options *options.Options) error {
	if err := f.controllerOptions.Validate(); err != nil {
		return err
	}

	if options.Namespace == "" {
		return fmt.Errorf("%w: --namespace is required", policycontroller.ErrOptions)
	}

	client, err := client.New(manager.GetConfig(), client.Options{Scheme: manager.GetScheme()})
	if err != nil {
		return err
	}

	f.client = client
	f.namespace = options.Namespace

	// Build a cache scoped to --namespace for the ConfigMap watch and hand it
	// to the manager to start and stop.  It must not be the manager's
	// cluster-wide cache (see the configMapCache field comment): a namespaced
	// cache lists/watches ConfigMaps only in --namespace, which the chart's
	// Role permits.
	configMapCache, err := cache.New(manager.GetConfig(), cache.Options{
		Scheme:            manager.GetScheme(),
		DefaultNamespaces: map[string]cache.Config{options.Namespace: {}},
	})
	if err != nil {
		return err
	}

	if err := manager.Add(configMapCache); err != nil {
		return err
	}

	f.configMapCache = configMapCache

	return nil
}

// Reconciler returns a new reconciler instance.
func (f *Factory) Reconciler(options *options.Options, _ coremanager.ControllerOptions, manager manager.Manager) reconcile.Reconciler {
	gate := policycontroller.NewExecGate(f.controllerOptions.CerbosBinary)

	return policycontroller.New(f.client, manager.GetEventRecorderFor(constants.Application), options.Namespace, f.controllerOptions, gate)
}

// RegisterWatches adds any watches that would trigger a reconcile.
func (f *Factory) RegisterWatches(manager manager.Manager, controller controller.Controller) error {
	if err := controller.Watch(source.Kind(manager.GetCache(), &unikornv1.Role{}, handler.TypedEnqueueRequestsFromMapFunc(enqueuePolicyStore), rolePredicate())); err != nil {
		return err
	}

	// Also watch the managed policy store ConfigMap itself, so a delete (it is
	// mounted as an optional volume — while it is missing Cerbos serves
	// deny-by-default) or an out-of-band data mutation self-heals on the very
	// next reconcile rather than waiting for an unrelated Role event or the
	// ~10h informer resync.  The event collapses into the same synthetic
	// fan-in request as a Role event.  This uses the namespace-scoped cache,
	// not the manager's cluster-wide one (see the Factory.configMapCache field
	// comment).
	if err := controller.Watch(source.Kind(f.configMapCache, &corev1.ConfigMap{}, handler.TypedEnqueueRequestsFromMapFunc(enqueueConfigMapPolicyStore), configMapPredicate(f.namespace, f.controllerOptions.ConfigMapName))); err != nil {
		return err
	}

	return nil
}

// Schemes allows controllers to add types to the client beyond
// the defaults defined in this repository.
func (*Factory) Schemes() []coreclient.SchemeAdder {
	return []coreclient.SchemeAdder{
		unikornv1.AddToScheme,
	}
}

// enqueuePolicyStore collapses every Role event into the one synthetic
// fan-in request.
func enqueuePolicyStore(_ context.Context, _ *unikornv1.Role) []reconcile.Request {
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: policyStoreRequestName}}}
}

// enqueueConfigMapPolicyStore collapses a managed-ConfigMap event into the
// same synthetic fan-in request a Role event uses, so a deleted or tampered
// store re-enters the one reconcile that regenerates it (and the workqueue
// dedups it against any concurrent Role event).
func enqueueConfigMapPolicyStore(_ context.Context, _ *corev1.ConfigMap) []reconcile.Request {
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: policyStoreRequestName}}}
}

// rolePredicate filters Role events like the sibling controllers do.  The
// generation-changed predicate only overrides UpdateFunc, so Create and —
// crucially for a generated store that must shrink — Delete events pass
// (pinned by unit test, not assumed).
func rolePredicate() predicate.TypedPredicate[*unikornv1.Role] {
	return &predicate.TypedGenerationChangedPredicate[*unikornv1.Role]{}
}

// configMapPredicate passes events only for the controller-owned policy store
// ConfigMap (its exact name in --namespace).  The namespace-scoped informer
// still observes every ConfigMap in --namespace, so matching name AND namespace
// keeps unrelated ConfigMap churn from triggering pointless store
// regenerations.
func configMapPredicate(namespace, name string) predicate.TypedPredicate[*corev1.ConfigMap] {
	return predicate.NewTypedPredicateFuncs(func(configMap *corev1.ConfigMap) bool {
		return configMap.GetNamespace() == namespace && configMap.GetName() == name
	})
}
