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

The actual reconcile behaviour lives in the provisioners (or, for the policy
controller, in its domain package):

- [organization](../provisioners/organization/README.md)
- [project](../provisioners/project/README.md)
- [oauth2client](../provisioners/oauth2client/README.md)
- [policy](../authz/cerbos/README.md#the-policy-controller) — domain logic in
  `pkg/authz/cerbos/controller`

## Pattern

Each lifecycle controller package in this repository follows the same pattern:

- implement `coremanager.ControllerFactory`
- return [pkg/constants](../constants/README.md) service metadata
- expose no controller-local CLI options
- construct `coremanager.NewReconciler(...)` with the concrete provisioner
- watch the concrete CRD type
- trigger reconciles on generation changes
- register `unikorn/v1alpha1` types with the controller manager scheme

The controller layer is therefore deliberately boring. Its job is to make the
shared manager framework runnable for a specific resource kind without
re-implementing reconcile logic locally.

## The Policy Controller (fan-in)

[policy](../authz/cerbos/README.md#the-policy-controller) is the one
deliberate deviation: it regenerates the Cerbos policy store from the *whole*
`Role` set, so `coremanager.NewReconciler`'s strict 1:1 object-lifecycle
model (finalizers, status conditions) does not fit. The factory stays thin
but:

- returns a custom fan-in reconciler from `pkg/authz/cerbos/controller`
  instead of constructing the shared one
- collapses every `Role` event into a single synthetic request, so bursts
  dedup in the workqueue
- still uses the generation-changed predicate, which passes create *and
  delete* events (pinned by unit test — a deleted `Role` must shrink the
  generated store)
- exposes controller-local CLI options (`--cerbos-policies-configmap`,
  `--cerbos-binary`) and validates them via the factory `Initialize` hook,
  which also builds the uncached client the reconciler needs (a cache-backed
  ConfigMap read would demand cluster-wide RBAC the chart deliberately does
  not grant)

## Why Generation Watches

The controllers use generation-changed predicates so normal reconcile is driven
by desired-state changes in `spec`, rather than by incidental metadata churn.

This keeps the controller role aligned with the manager/provisioner contract in
[`core/pkg/manager`](https://github.com/nscaledev/uni-core/blob/main/pkg/manager/README.md): desired state is
expressed on the resource, the provisioner acts on it, and status/finalizer
management happens within that shared lifecycle model.

## Relationship To Provisioners

The clean split in this repository is:

- controllers define how a resource is attached to the shared manager runtime
- provisioners define what provisioning and deprovisioning actually mean

That means documentation and review effort should usually focus on the
provisioners rather than the controller packages, unless the watch strategy,
reconciler construction, or service registration behaviour changes.
