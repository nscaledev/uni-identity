# Controllers

## Purpose

This package contains the controller-factory layer for the identity service.
It adapts concrete identity resource types into the shared controller framework
provided by [`core/pkg/manager`](../../core/pkg/manager/README.md).

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
- construct `coremanager.NewReconciler(...)` with the concrete provisioner
- watch the concrete CRD type
- trigger reconciles on generation changes
- register `unikorn/v1alpha1` types with the controller manager scheme

The controller layer is therefore deliberately boring. Its job is to make the
shared manager framework runnable for a specific resource kind without
re-implementing reconcile logic locally.

## Why Generation Watches

The controllers use generation-changed predicates so normal reconcile is driven
by desired-state changes in `spec`, rather than by incidental metadata churn.

This keeps the controller role aligned with the manager/provisioner contract in
[`core/pkg/manager`](../../core/pkg/manager/README.md): desired state is
expressed on the resource, the provisioner acts on it, and status/finalizer
management happens within that shared lifecycle model.

## Relationship To Provisioners

The clean split in this repository is:

- controllers define how a resource is attached to the shared manager runtime
- provisioners define what provisioning and deprovisioning actually mean

That means documentation and review effort should usually focus on the
provisioners rather than the controller packages, unless the watch strategy,
reconciler construction, or service registration behaviour changes.
