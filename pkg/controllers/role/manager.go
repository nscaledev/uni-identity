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

package role

import (
	"context"
	"os"

	"go.opentelemetry.io/otel"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coremanager "github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/manager/options"
	"github.com/unikorn-cloud/core/pkg/util"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/constants"
	controllermetrics "github.com/unikorn-cloud/identity/pkg/controllers/metrics"

	"k8s.io/apimachinery/pkg/api/equality"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// Factory provides methods that can build a type specific controller.
type Factory struct{}

var _ coremanager.ControllerFactory = &Factory{}

// Metadata returns the application, version and revision.
func (*Factory) Metadata() util.ServiceDescriptor {
	return constants.ServiceDescriptor()
}

// Options returns any options to be added to the CLI flags and passed to the reconciler.
func (*Factory) Options() coremanager.ControllerOptions {
	return nil
}

// Initialize registers metrics that follow the manager lifecycle.
func (*Factory) Initialize(_ context.Context, manager manager.Manager, _ *options.Options) error {
	reporter, err := controllermetrics.New(otel.Meter(constants.Application), constants.ServiceDescriptor())
	if err != nil {
		return err
	}

	return manager.Add(reporter)
}

// Reconciler returns a new reconciler instance.  Roles have no provisioning
// lifecycle and no finalizer, so this does not use the shared provisioner
// reconciler: it only computes status.
func (*Factory) Reconciler(_ *options.Options, _ coremanager.ControllerOptions, manager manager.Manager) reconcile.Reconciler {
	return &Reconciler{
		client:   manager.GetClient(),
		recorder: manager.GetEventRecorder(constants.Application),
	}
}

// RegisterWatches adds any watches that would trigger a reconcile.  A change
// to any role can change any aggregating role, through selectors, refs and
// chains, so every change enqueues every aggregating role in the namespace.
// Labels are watched as well as generation, because a label is how a role
// opts in.  Status changes are watched too: a stuck role reads its own and
// its cycle sources' last status, and a status someone else wrote must be
// put right.  The controller's own writes wake it once and then compute to
// no change.
//
// Only roles in the controller's own namespace (POD_NAMESPACE, set by the
// chart) are watched, so a second identity release in the same cluster
// never writes status on this release's roles.
func (*Factory) RegisterWatches(manager manager.Manager, controller controller.Controller) error {
	cli := manager.GetClient()
	namespace := os.Getenv("POD_NAMESPACE")

	enqueue := handler.TypedEnqueueRequestsFromMapFunc(func(ctx context.Context, role *unikornv1.Role) []reconcile.Request {
		return aggregatingRoles(ctx, cli, role)
	})

	inNamespace := predicate.NewTypedPredicateFuncs(func(role *unikornv1.Role) bool {
		return namespace == "" || role.Namespace == namespace
	})

	return controller.Watch(source.Kind(manager.GetCache(), &unikornv1.Role{}, enqueue, roleChanged(), inNamespace))
}

// roleChanged passes creates, deletes and any update that changes the
// generation, labels, annotations or status.
func roleChanged() predicate.TypedPredicate[*unikornv1.Role] {
	changed := predicate.Or[*unikornv1.Role](
		predicate.TypedGenerationChangedPredicate[*unikornv1.Role]{},
		predicate.TypedLabelChangedPredicate[*unikornv1.Role]{},
		predicate.TypedAnnotationChangedPredicate[*unikornv1.Role]{},
	)

	return predicate.TypedFuncs[*unikornv1.Role]{
		UpdateFunc: func(e event.TypedUpdateEvent[*unikornv1.Role]) bool {
			if e.ObjectOld == nil || e.ObjectNew == nil {
				return false
			}

			return changed.Update(e) || !equality.Semantic.DeepEqual(e.ObjectOld.Status, e.ObjectNew.Status)
		},
	}
}

// aggregatingRoles returns a request for the changed role and for every
// aggregating role in its namespace.
func aggregatingRoles(ctx context.Context, cli client.Client, changed *unikornv1.Role) []reconcile.Request {
	requests := []reconcile.Request{
		{NamespacedName: client.ObjectKeyFromObject(changed)},
	}

	roles := &unikornv1.RoleList{}

	if err := cli.List(ctx, roles, client.InNamespace(changed.Namespace)); err != nil {
		log.FromContext(ctx).Error(err, "failed to list roles, only the changed role will be reconciled")

		return requests
	}

	for i := range roles.Items {
		role := &roles.Items[i]

		if role.IsAggregating() && role.Name != changed.Name {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(role)})
		}
	}

	return requests
}

// Schemes allows controllers to add types to the client beyond
// the defaults defined in this repository.
func (*Factory) Schemes() []coreclient.SchemeAdder {
	return []coreclient.SchemeAdder{
		unikornv1.AddToScheme,
	}
}
