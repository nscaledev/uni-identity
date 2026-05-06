# `pkg/provisioners/organization`

This package implements the organization-level lifecycle boundary in identity's current controller
model.

## Intent

The provisioner projects an `Organization` resource into a managed namespace and records that
projected namespace in status.

That is the mechanism behind two different current behaviours:

- the `v1` organization namespace handoff consumed by the API/handler layer
- the hierarchy-level deletion model where deleting a parent should cascade teardown to its
  descendants and block visibly at the parent until that work completes

So this package is not just "create a namespace". It is the organization-level control-plane
realization of the current compatibility-era tenancy and lifecycle model.

## What Is Specific Here

### Namespace Projection For Current `v1`

The provisioner derives resource labels from the `Organization` CRD, looks up a matching
namespace, and creates one if none exists.

It then writes `Status.Namespace`, which becomes the operational handoff point consumed later by
the current `v1` handler layer.

As documented elsewhere in this repo, this namespace-projection model is current operational
reality, not the preferred long-term architecture.

### Parent-Level Delete Coordination

The namespace projection also serves the older hierarchical deletion model:

- deleting the organization should cascade deletion to descendants that live beneath it
- the organization should remain the visible top-level deletion point until that teardown completes

This gave the system two practical benefits:

- one top-level delete instead of manual dependency hunting
- visible blockage at the parent when teardown hangs, instead of silently orphaning subordinate
  state

### Trivial Side Effect, Trivial Adapter

Because the managed side effect here is still just namespace existence/deletion, the provisioner
uses the legacy `core/pkg/provisioners/resource` adapter rather than a richer purpose-built child
resource workflow.

That is acceptable here because the operational side effect is simple.

## Invariants

- one organization should resolve to exactly one projected namespace under the label contract
- `Status.Namespace` should reflect the namespace actually found or created
- deprovision should treat an already-absent namespace as success
- organization deletion should remain the visible coordination point for descendant teardown in the
  current hierarchy model

## Caveats

- The namespace-projection mechanism is part of current compatibility behaviour, not the desired
  final architecture for newer services.
- The provisioner depends on the label contract being strong enough for namespace lookup to resolve
  exactly one namespace.
- The package uses the legacy `core/pkg/provisioners/resource` adapter because the managed side
  effect is simple, not because that adapter is generally preferred.

## Related Documentation

- [`pkg/apis/unikorn/v1alpha1`](../../apis/unikorn/v1alpha1/README.md), which defines the
  `Organization` resource and its current scoping/lifecycle context
- [`pkg/handler/organizations`](../../handler/organizations/README.md), which consumes
  `Status.Namespace` as the current `v1` organization handoff
- [`../core/pkg/manager`](../../../core/pkg/manager/README.md), which defines the shared manager
  lifecycle this provisioner plugs into
- [`../core/pkg/provisioners/resource`](../../../core/pkg/provisioners/resource/README.md), which
  provides the simple single-object adapter used here for namespace create/delete
- [`../core/pkg/provisioners/util`](../../../core/pkg/provisioners/util/README.md), which provides
  the shared namespace lookup helper used here
