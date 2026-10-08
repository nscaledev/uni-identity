# `pkg/handler/allocations`

This package records the consumption ledger checked against organization quotas.

## Intent

Allocations are the usage-side of the quota system.

They record committed and reserved quantities for a referenced resource within a project context,
and they are validated against the organization-wide quota envelope before being written.

So this package is not generic project-scoped CRUD. It is the ledger half of the quota/allocation
subsystem.

## What Is Specific Here

### Project-Scoped Consumption Records

Allocations are stored in the project namespace and carry organization, project, and referenced
resource identity in metadata and labels.

That makes them the per-resource consumption record that ties an abstract quota number back to an
actual project-scoped object.

### Serialized Capacity Decisions

Allocation create/update and quota update operations hold a per-organization Kubernetes Lease.
The Lease lasts ten seconds, and the holder stops writing two seconds before its expiry. The
holder is deleted on either success or failure; a crashed holder delays only that organization
until the first contender has observed its unchanged Lease for a full duration.

Contenders receive a retryable HTTP 409 when their request context expires. Different
organizations use different Leases and do not wait for each other. The holder checks its bounded
context immediately before writing, although an API-server write sent before that deadline can
still be committed after the Lease expires.

This is a clear example of the handler layer implementing application-level accounting discipline
on top of Kubernetes storage.

### Referenced Resource Identity

Each allocation is tied to a referenced resource through kind and ID labels today.

That identity should likely converge with the shared reference model documented in
[`../core/pkg/manager`](../../../core/pkg/manager/README.md), so allocation identity can reuse the
platform's existing referenced-resource contract instead of maintaining a parallel allocation-ID
linkage model.

## Invariants

- allocations are the consumption ledger checked against organization quotas
- allocation writes must pass quota-consistency checks before being persisted
- committed and reserved quantities are both part of the effective used total
- allocation and quota decisions are serialized per organization

## Caveats

- Allocation identity is still weaker than it should be. The current model labels the referenced
  resource, but does not yet treat that reference identity as the canonical unique key.
- Like quotas, this package is part of a best-effort accounting system built on Kubernetes objects
  rather than transactional storage.
- The current model records project/resource consumption, but not project-level quota envelopes or
  ring-fenced budget partitions.

## TODO

- Adopt the shared `core` reference identity as the canonical allocation identifier so logical
  uniqueness is enforced naturally and owning resources do not need a parallel allocation-ID
  linkage.
- Reject duplicate logical allocations for the same referenced resource until that shared-reference
  identity model is in place.

## Related Documentation

- [`pkg/handler/quotas`](../quotas/README.md), which defines the organization-wide capacity
  contract enforced here
- [`../core/pkg/manager`](../../../core/pkg/manager/README.md), which documents the shared
  resource-reference model this package should align with
- [`pkg/apis/unikorn/v1alpha1`](../../apis/unikorn/v1alpha1/README.md), which defines the stored
  `Allocation` resource
