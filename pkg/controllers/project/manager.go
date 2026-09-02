/*
Copyright 2022-2024 EscherCloud.
Copyright 2024-2025 the Unikorn Authors.
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

package project

import (
	coreclient "github.com/unikorn-cloud/core/pkg/client"
	coremanager "github.com/unikorn-cloud/core/pkg/manager"
	"github.com/unikorn-cloud/core/pkg/manager/options"
	"github.com/unikorn-cloud/core/pkg/util"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/provisioners/project"

	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// Factory provides methods that can build a type specific controller.
type Factory struct {
	// reconciler is remembered from Reconciler() so RegisterWatches() can hand it
	// to the generation predicate, which reads a field the reconciler writes.
	reconciler *coremanager.Reconciler
}

var _ coremanager.ControllerFactory = &Factory{}

// Metadata returns the application, version and revision.
func (*Factory) Metadata() util.ServiceDescriptor {
	return constants.ServiceDescriptor()
}

// Options returns any options to be added to the CLI flags and passed to the reconciler.
func (*Factory) Options() coremanager.ControllerOptions {
	return nil
}

// Reconciler returns a new reconciler instance.
func (f *Factory) Reconciler(options *options.Options, controllerOptions coremanager.ControllerOptions, manager manager.Manager) reconcile.Reconciler {
	f.reconciler = coremanager.NewReconciler(options, controllerOptions, manager, project.New)

	return f.reconciler
}

// RegisterWatches adds any watches that would trigger a reconcile.
func (f *Factory) RegisterWatches(manager manager.Manager, controller controller.Controller) error {
	// A project provisions once and is done, and this is its only watch, so a
	// restart has nothing to catch up on.  GenerationUnprocessed therefore drops
	// the start up create event for any project already reconciled at its current
	// generation, rather than re-provisioning the whole fleet.  It must be
	// composed with And: TypedGenerationChangedPredicate passes every create, so
	// an Or would let everything through and filter nothing.
	predicates := predicate.And(
		&predicate.TypedGenerationChangedPredicate[*unikornv1.Project]{},
		coremanager.GenerationUnprocessed[*unikornv1.Project](f.reconciler),
	)

	if err := controller.Watch(source.Kind(manager.GetCache(), &unikornv1.Project{}, &handler.TypedEnqueueRequestForObject[*unikornv1.Project]{}, predicates)); err != nil {
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
