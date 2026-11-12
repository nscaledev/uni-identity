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

`GetUser` reads the deterministic User name derived from the folded subject, so a claim in any
case finds a record stored in any case. On a miss, it selects random-named legacy records by the
subject-ID label, which is derived the same way. Unlabelled records are a final fallback, found
through the subject index (see Readers). The returned record is owned by the caller.

### Readers

`NewUserDatabase` takes one `client.Reader`, and it MUST be the informer cache with the indexes in
`Indexes` registered by `IndexUsers` before the cache starts. The package never reads live and
never takes a live client: the API server cannot serve a field index on a custom resource, so a
live reader fails every user and membership lookup.

The indexes are the canonical subject of each User (`SubjectIndexField`, the unlabelled legacy
lookup), the subject-ID label of each User (`SubjectLabelIndexField`), and the user label of each
OrganizationUser (`MembershipUserIndexField`, every membership lookup). The cache indexes only by
namespace and by registered field, and a List with a label selector and no namespace walks every
cached object of the kind. The label lookups therefore go through the indexes: the cost follows the
user's own memberships, not the number of organizations. The organization of a membership is
filtered after the index, in memory, from the few records the user has.

Records come from the cache, so they can lag a write by the watch delay. A caller that decides a
write on a record, such as sign-in or refresh in `pkg/oauth2`, reads the canonical record live by
name, and uses this package only to find a legacy record's key, then reads the record live itself,
and checks it again on the live copy (see
[`pkg/oauth2`](../oauth2/README.md), "Readers"). Legacy records are no longer created, so the index
lag cannot hide one.

The index holds exactly the records whose canonical subject matches, which is the set
`MatchSubject` would pick from in a full list, so the result is the same without listing every
user.

Tests build the reader with `userdbtest.NewClientBuilder`, a fake client with the indexes. The
benchmarks use `cachetest.Reader`, built on the client-go indexer the cache is built on, because a
fake client scans every object for any selector and hides the saving. Both packages are for
`_test.go` files and `test/` only.

`GetServiceAccount` reads the account by key, in the namespace of the organization its token names.

A lookup that finds the deterministic record trusts it without checking for another record with
the same subject. User creation refuses that state (see
[`pkg/handler/users`](../handler/users/README.md)), and the subject-label backfill refuses to run
while it exists.

### Active-State Gatekeeping

The package treats "active" as part of identity resolution rather than as downstream policy.

Several methods do not just resolve objects; they enforce that the resolved user or
organization-local membership is active before returning it.

### Subject Resolution

`GetUser` resolves a subject through
[`MatchSubject`](../apis/unikorn/v1alpha1/README.md#subject-matching). An exact match wins. If no
record matches exactly, the one record with the same canonical form matches. As a result, a login
works whether the stored subject is folded or not. `GetActiveUser` and the subject-based
`GetOrganizationIDs` go through `GetUser`, so they resolve the same way. Callers that already hold
an active user can use `GetOrganizationIDsForUser` to avoid resolving it a second time.

The legacy lookup lists users in no fixed order. If the subject matches no record exactly but folds onto
two or more, a pick depends on that order. It can give a different user from one call to the next.
`GetUser` returns `ErrAmbiguousSubject` in that case and does not pick.

## Invariants

- subject is the lookup key for global users
- an email subject resolves in either stored case, and an ambiguous fold resolves to no user
- active-state checks are part of the package contract
- organization membership is resolved through labeled `OrganizationUser` records
- service accounts are part of the same local identity-resolution surface as users
- unresolved, inactive, or multiply-resolved identities are normalized into
  `ErrResourceReference`, with the wrapped errors noted under Caveats

## Caveats

- The package is tightly coupled to the current Kubernetes-backed identity storage model even
  though its purpose is to shield other packages from that coupling.
- Canonical users use their deterministic name. Labelled legacy users are found through the
  `SubjectLabelIndexField` field index; unlabelled legacy users through the subject index.
- A database built on the cache sees writes within the watch lag. A revoked or suspended user is
  refused once the change reaches the cache, not on the next request.
- Missing and multiply-resolved identities return `ErrResourceReference`. `GetActiveUser` instead
  returns `ErrUserInactive` for an inactive global user, which wraps `ErrResourceReference` so
  existing `errors.Is` callers are unaffected; `GetActiveOrganizationUser` still returns the plain
  error. See
  [`docs/multi-issuer-token-contract.md#membership-resolution`](../../docs/multi-issuer-token-contract.md#membership-resolution)
  for the bearer-admission consequences and the organization-suspension gap this leaves open.
- `GetUser` returns `ErrAmbiguousSubject` for an ambiguous fold. It wraps `ErrResourceReference` in
  the same way, so a caller that does not test for it treats the subject as a record it cannot
  resolve. The bearer path tests for it and refuses the subject, even under
  `allowExternalIdentity: true`, because the address is onboarded.
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
