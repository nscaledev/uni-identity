# `pkg/userdb`

This package is the local identity-resolution boundary for authn and authorization code.

## Intent

The main purpose of `pkg/userdb` is not to be a generic database abstraction. Its more important
role is to segregate identity's internal storage model from consumers such as `pkg/rbac`,
`pkg/oauth2`, and higher-level handlers.

It gives those packages a small read-side facade for resolving:

- global users by subject
- active users only
- active organization membership for a user
- service accounts as principal-like actors
- the set of active organizations a subject belongs to

That keeps RBAC and authn flows from having to understand all of the current joins, labels, and
lookup patterns in the underlying Kubernetes-backed identity model.

## What Is Specific Here

### Internal Model Segregation

Identity stores several related principal records:

- global `User`
- organization-scoped `OrganizationUser`
- organization-scoped `ServiceAccount`

This package hides the storage correlation logic between those records from consumers that only
need answers to questions like:

- "who is this subject?"
- "is this identity active?"
- "is this user active in this organization?"
- "which organizations does this subject belong to?"

That makes it easier for RBAC and authn code to evolve independently of the exact internal storage
layout, which matters if third-party IdP integrations become more prominent.

### Read-Only Identity Resolution

The package is deliberately narrow and read-only.

It does not own user mutation, organization membership mutation, or token lifecycle. It only
normalizes local identity lookups for other parts of the system.

### Active-State Gatekeeping

The package treats "active" as part of identity resolution rather than as downstream policy.

Several methods do not just resolve objects; they enforce that the resolved user or
organization-local membership is active before returning it.

## Invariants

- subject is the lookup key for global users
- active-state checks are part of the package contract
- organization membership is resolved through labeled `OrganizationUser` records
- service accounts are part of the same local identity-resolution surface as users
- unresolved, inactive, or multiply-resolved identities are normalized into
  `ErrResourceReference`

## Caveats

- The package is tightly coupled to the current Kubernetes-backed identity storage model even
  though its purpose is to shield other packages from that coupling.
- Several lookups are implemented as list-and-filter operations, so they depend on label hygiene
  and on the current storage layout remaining coherent.
- The package intentionally flattens several different unusable-identity cases into one read-side
  failure surface. Missing, inactive, and multiply-resolved identities are all treated as "not a
  usable local reference" for callers.
- The package intentionally does not provide mutation or transactional semantics; it is a read-side
  adapter boundary only.

## Related Documentation

- [`pkg/rbac`](../rbac/README.md), which consumes this package to resolve local identity state
  without binding directly to raw storage joins
- [`pkg/oauth2`](../oauth2/README.md), which uses local user and organization membership state
  during authentication and token handling
- [`pkg/handler/users`](../handler/users/README.md), which owns mutation of the user and
  organization-user resources that this package reads
- [`pkg/apis/unikorn/v1alpha1`](../apis/unikorn/v1alpha1/README.md), which defines the stored
  `User`, `OrganizationUser`, and `ServiceAccount` resources resolved here
