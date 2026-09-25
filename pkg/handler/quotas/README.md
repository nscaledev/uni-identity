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

Two pure functions render quota reads. `common.Normalise` folds the stored
quota against the QuotaMetadata kinds. It adds defaults for missing kinds,
drops retired kinds and copies every quantity. `Convert` sums committed and
reserved usage per kind from allocations and sorts by kind. `GET` normalises.
`PUT` renders the request's own list. The client reads QuotaMetadata once per
request from the identity namespace, where the chart installs it.

Without that metadata, the numeric values are not meaningfully usable.

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

## Caveats

- The package only models organization-wide quota envelopes today; it does not yet provide
  project-level capacity partitioning.
- Quota correctness depends on cross-object consistency with both `QuotaMetadata` and live
  allocation records.
- This is one half of a small accounting subsystem built on Kubernetes objects rather than an ACID
  backing store.
- Rendering skips a kind without QuotaMetadata. A nil quota quantity or a nil
  QuotaMetadata default is a data fault and returns an error.

## TODO

- Add first-class project-level quota partitioning so organizations can reserve capacity internally
  without splitting into multiple organizations.
- Reject a `PUT` that names a kind without `QuotaMetadata` instead of silently
  skipping it on render.

## Related Documentation

- [`pkg/handler/allocations`](../allocations/README.md), which records the consumption ledger
  checked against the quota contract defined here
- [`pkg/apis/unikorn/v1alpha1`](../../apis/unikorn/v1alpha1/README.md), which defines the stored
  `Quota` and `QuotaMetadata` resources
