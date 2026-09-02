# Controllers

## Purpose

This package contains the controller-factory layer for the identity service.
It adapts concrete identity resource types into the shared controller framework
provided by [`core/pkg/manager`](https://github.com/nscaledev/uni-core/blob/main/pkg/manager/README.md).

The important point is that these packages do **not** contain the resource
lifecycle semantics themselves. They are intentionally thin factories that:

- identify the controller as part of the identity service
- construct the shared reconciler with the correct provisioner
- register watches for the concrete resource type
- register the local API scheme needed by that controller

The actual reconcile behaviour lives in the provisioners:

- [organization](../provisioners/organization/README.md)
- [project](../provisioners/project/README.md)
- [oauth2client](../provisioners/oauth2client/README.md)

## Pattern

Each controller package in this repository follows the same pattern:

- implement `coremanager.ControllerFactory`
- return [pkg/constants](../constants/README.md) service metadata
- expose no controller-local CLI options
- construct `coremanager.NewReconciler(...)` with the concrete provisioner, and keep a
  reference to it for the watch predicates
- watch the concrete CRD type
- trigger reconciles on generation changes, and skip the start-up create event for a
  resource already reconciled at its current generation
- register `unikorn/v1alpha1` types with the controller manager scheme

The controller layer is therefore deliberately boring. Its job is to make the
shared manager framework runnable for a specific resource kind without
re-implementing reconcile logic locally.

## Why Generation Watches

The controllers use generation-changed predicates so normal reconcile is driven
by desired-state changes in `spec`, rather than by incidental metadata churn.

This keeps the controller role aligned with the manager/provisioner contract in
[`core/pkg/manager`](https://github.com/nscaledev/uni-core/blob/main/pkg/manager/README.md): desired state is
expressed on the resource, the provisioner acts on it, and status/finalizer
management happens within that shared lifecycle model.

## Why Generation Processing

A generation-changed predicate does not filter *create* events, and on start up the
informer lists the whole fleet and delivers every resource as a create. Without more,
a restart therefore re-provisions everything from scratch — a burst of work that
achieves nothing, because it was all done before the process went down.

All three controllers here compose `coremanager.GenerationUnprocessed` with the
generation-changed predicate using `predicate.And`, so that start-up create is dropped
for any resource whose `status.processedGeneration` already matches its
`metadata.generation`. The reconciler in `core` writes that field when a pass finishes
with no further work scheduled.

Three things follow, and none of them are optional:

- **`And`, never `Or`.** `TypedGenerationChangedPredicate` passes every create event, so
  an `Or` lets the whole fleet through and the filter does nothing at all.
- **The predicate needs the reconciler**, because it reads a field the reconciler writes
  and disables itself when the reconciler polls. That is why `Reconciler()` stashes what
  it built on the `Factory` for `RegisterWatches()` to pick up. The manager calls the two
  in that order.
- **Only these three resource types opt in.** They provision once and are done, and each
  has a single watch on its own type, so a restart genuinely has nothing to catch up on.
  A controller that watched another service's resource would miss every change to it while
  the process was down, and its start-up create is the only chance it gets to notice —
  dropping that would leave it permanently behind. The same goes for a polling controller.

The cost is that a controller upgrade no longer re-converges the fleet: a settled resource
is filtered on restart, so a new version that provisions differently does not reach existing
resources until each spec is edited. Toggling `spec.pause` off and on bumps the generation
and is the way to force it.

## Relationship To Provisioners

The clean split in this repository is:

- controllers define how a resource is attached to the shared manager runtime
- provisioners define what provisioning and deprovisioning actually mean

That means documentation and review effort should usually focus on the
provisioners rather than the controller packages, unless the watch strategy,
reconciler construction, or service registration behaviour changes.
