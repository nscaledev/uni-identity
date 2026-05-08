# `pkg/provisioners/project`

This package implements the project-level lifecycle boundary in identity's current controller model.

## Intent

On provision, this package behaves much like the organization provisioner:

- project the `Project` into a managed namespace
- record that namespace in status

What makes it distinctive is deprovisioning. The package must coordinate descendant teardown before
allowing the project namespace itself to disappear.

## What Is Specific Here

### Namespace Projection For Current `v1`

The provisioner derives labels from the `Project`, resolves or creates the projected namespace, and
writes `Status.Namespace`.

That is part of the current `v1` compatibility model and the live handoff consumed later by the
API/handler layer. It is not the preferred long-term architecture.

### Legacy Descendant Sweep Before Namespace Deletion

The project delete path is much more specific than the organization one.

Before deleting the project namespace, this provisioner explicitly discovers and deletes selected
namespaced resources inside that namespace, then yields until they are gone.

This is legacy safety machinery, not generic elegance. It existed to avoid deleting the in-namespace
Kubernetes service / vcluster-based cluster manager before the cloud resources represented inside
that vcluster had been torn down correctly.

So the high-level invariant is still important:

- parent deletion should remain the visible coordination point
- descendant teardown should happen before the parent is considered gone

But the specific descendant-sweep mechanism here is highly topology-specific and should not be
mistaken for the general future pattern.

## Invariants

- one project should resolve to exactly one projected namespace under the label contract
- `Status.Namespace` should reflect the namespace actually found or created
- descendant teardown should complete before namespace deletion is allowed to finish
- deprovision should yield while descendant deletion is still in progress

## Caveats

- The namespace-projection mechanism is current compatibility behaviour, not the desired final
  architecture.
- The descendant cleanup logic is intentionally legacy-specific and tied to an older control-plane
  topology.
- The current descendant sweep is hardcoded and selective rather than a general resource-lifecycle
  framework.

## Related Documentation

- [`pkg/provisioners/organization`](../organization/README.md), which shows the simpler parent
  namespace-projection pattern without the legacy descendant sweep
- [`pkg/handler/projects`](../../handler/projects/README.md), which consumes `Status.Namespace` in
  the current `v1` API model
- [`../core/pkg/manager`](../../../core/pkg/manager/README.md), which defines the shared manager
  lifecycle and `ErrYield` behaviour used here
- [`../core/pkg/client`](../../../core/pkg/client/README.md), which provides the scoped client
  context used during descendant cleanup
