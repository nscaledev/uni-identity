# `pkg/handler/quotas`

This package manages the organization-wide capacity contract for allocatable resources.

## Intent

Quotas define how much of each abstract resource kind an organization is allowed to consume.

This package is not just a CRUD wrapper over stored quota numbers. It assembles the user-facing
quota view by combining:

- the stored organization quota object
- the shared `QuotaMetadata` catalogue that explains what each quota kind means
- live allocation totals recorded elsewhere

So the package acts as the contract half of the quota/allocation subsystem.

## What Is Specific Here

### Organization-Wide Capacity Contract

The current model defines one quota envelope per organization.

That envelope is the top-level capacity contract against which allocations are checked. A quota
update is only allowed if the resulting values still cover current committed and reserved usage.

### Derived Read Model

Quota reads are materialized views rather than raw stored state.

The package combines numeric quota values with mandatory `QuotaMetadata` so clients can interpret
each abstract resource kind correctly and present meaningful display names, descriptions, defaults,
formatting hints, used, free, committed, and reserved totals.

Without that metadata, the numeric values are not meaningfully usable.

`Convert` in `convert.go` is the single rendering path. The per-organization GET renders the
normalised quota list through it. The PUT response renders the written quota list through the
same call. `Convert` reads quantities only with `Value()`.

### Built-In Volume Capacity

The Identity Helm chart registers `volume` as the quota kind for the total requested block storage
capacity of an organization's Volumes. Region reports that capacity in GiB. The built-in default is
`0`, so Volume allocation remains denied until an operator configures capacity, and the metadata
uses binary formatting. The public quota read model exposes that formatting hint to clients. Volume
count is not quota-controlled.

### Missing Internal Partitioning

The main current model gap is that quotas are organization-wide only.

There is not yet a first-class way to ring-fence part of an organization's quota for a specific
project. That pushes users who want hard internal budget boundaries toward splitting work across
multiple organizations, which then turns an internal accounting problem into a cross-organization
reporting and dashboard problem.

## Invariants

- quotas are organization-scoped capacity contracts
- quota reads are derived from stored quota values, quota metadata, and current allocation totals
- quota updates must not reduce capacity below already committed plus reserved usage
- `QuotaMetadata` is mandatory contextual data, not optional display garnish
- `quotas.Convert` returns a consistency error, not a crash, for a quota kind with no matching
  `QuotaMetadata` entry or a nil quantity. `common.Normalise` drops a kind with no metadata as
  retired, and returns a consistency error for a nil quantity.
- a quota write that names a kind with no `QuotaMetadata` entry returns 400 before it stores
  anything

## Caveats

- The package only models organization-wide quota envelopes today; it does not yet provide
  project-level capacity partitioning.
- Quota correctness depends on cross-object consistency with both `QuotaMetadata` and live
  allocation records.
- This is one half of a small accounting subsystem built on Kubernetes objects rather than an ACID
  backing store.
- `GetQuota` lists `QuotaMetadata` in all namespaces, and the render paths list it from the
  identity namespace. The two agree because the chart installs `QuotaMetadata` only there.

## TODO

- Add first-class project-level quota partitioning so organizations can reserve capacity internally
  without splitting into multiple organizations.

## Related Documentation

- [`pkg/handler/allocations`](../allocations/README.md), which records the consumption ledger
  checked against the quota contract defined here
- [`pkg/apis/unikorn/v1alpha1`](../../apis/unikorn/v1alpha1/README.md), which defines the stored
  `Quota` and `QuotaMetadata` resources
