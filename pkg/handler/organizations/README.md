# `pkg/handler/organizations`

This package is the tenancy-root handler client for the identity API.

## Intent

Most handler clients operate inside an organization or project scope that has already been
resolved. This client is different: it is responsible for turning authenticated caller context
into the set of organizations that caller can see, and for exposing the organization metadata
that the rest of the handler tree depends on.

Its main responsibilities are:

- list organizations visible to the current caller
- return individual organization details
- create, update, and delete organization resources
- provide organization metadata, especially the namespace currently used by `v1` org-scoped
  handlers

## What Is Specific Here

### Membership-Driven Listing

Organization listing is not ordinary namespace CRUD.

For callers with global organization-read authority, the client lists every organization from
the controller-runtime cache without deep copies (`UnsafeDisableDeepCopy`). Those objects are
shared with the cache and are read-only. Otherwise it derives visibility from identity
membership:

- users are mapped through their active `OrganizationUser` records.
  `userdb.ActiveOrganizationIDs` removes duplicates. The client then reads each distinct
  organization with one cached `Get` without a deep copy
- service accounts are mapped to their bound organization
- an optional email filter can be used to ask "which organizations is this user in?", with
  additional permission checks when the caller is not querying their own identity

`ActiveOrganizationIDs` returns only active memberships. A pending or suspended membership does
not make its organization visible here. This matches the `orgIds` that a caller's token carries,
because both use the same resolver. Both branches read cache objects without deep copies, and
those objects are read-only.

In `v2`, both branches feed one paging step:

1. Build `(lower-case display name, display name, ID)` keys.
2. Apply the `v2` `name` substring filter.
3. Sort the keys.
4. Seek past the cursor.
5. Slice one page.
6. Convert only that page.

`v1` is ordered by ID. `v2` is ordered by display name: the order ignores case, and the exact
display name, then the ID, break ties.

The package enforces the `v2` walk rules itself, in addition to request validation:

- `limit` is 1-500. When `limit` is absent, the package uses the configured default. When the
  configured default is 0, the package uses 50.
- `name` is a case-insensitive substring over the label-value charset (letters, digits, `.`,
  `_`, `-`, at most 63 characters). It binds to the walk case-insensitively.
- `email` binds to the walk exactly.
- An empty `name` or `email` counts as absent.
- The cursor is at most 4096 bytes. It carries the walk's filters verbatim, including `email`.
  Treat a cursor like the query that produced it.

`id` selects organizations by ID instead of a walk. A request takes up to 100 IDs, and `id`
excludes every other parameter except `include`. The response holds them in one page, in
display-name order. The response omits an ID that the caller cannot see. On the global branch, it
also omits an ID that does not exist. Clients repeat the parameter (`?id=a&id=b`). The server
rejects a comma-separated list with `400`.

**Cost.** On the global branch, one request costs one shallow list plus one sort of N keys,
`O(N log N)`, regardless of `limit`. The caller controls `limit`, so a full `v2` walk over the
same N organizations costs `O(N^2/limit)`. The membership branch scans every OrganizationUser
record in the cache to find the caller's memberships. It then reads one organization per
membership. `userdb.GetUser` scans every user to resolve one subject.

`list_benchmark_internal_test.go` measures these figures at 11,000 organizations (Apple M-series,
go1.25.8). The figures are approximate:

- The unlimited `v1` list is about 16 MB and 115k allocations per request. Before cache reads
  stopped making deep copies, it was about 25 MB and 147k allocations.
- One `v2` page is about 5.4 MB and 4k allocations, whatever the limit. A full walk at
  `limit=50` allocates about 1.2 GB.

A consumer that walks the full estate would justify a sorted index.

`GET /api/v2/organizations` pages by an opaque cursor: base64url JSON of the last key and the
walk's `name` and `email` filters. The server accepts a repeated identical filter. A different
filter, or a filter present when the cursor has none, causes a `400`. Each page re-runs RBAC and
the email privilege check, so a cursor grants nothing that its holder could not request directly.

`GET /api/v1/organizations` is deprecated. It sends `Deprecation` and `Link` headers and does not
page. It returns each organization once, in organization ID order, not in display-name order. It
returns at most `--v1-organization-list-limit` organizations. The value 0 (the default) means
unlimited. The cap truncates silently: the response gives the client no signal that organizations
are missing. Set the cap only when every consumer can accept a partial list.

`ListPage` returns an `OrganizationPage` whose items are `OrganizationListItem` values with base
fields only. The handler package fills the `include` extras afterwards. See
[`pkg/handler`](../README.md).

That makes this package the bridge between authenticated identity context and organization-level
visibility.

### Namespace Handoff To The Rest Of `v1`

For the current `v1` API model, the rest of the organization-scoped handler tree depends on this
client to expose the organization namespace from status metadata.

That namespace is then used by downstream clients such as projects, groups, users, service
accounts, quotas, and organization-scoped OAuth2 providers to find or store child resources.

This is important current behaviour, but it is also transition-bound. As described in
[`pkg/apis/unikorn/v1alpha1`](../../apis/unikorn/v1alpha1/README.md), the `v2` API direction
reduces the long-term architectural importance of namespace handoff by moving away from
organization/project-scoped routing.

### Secondary Support For Built-In Domain Login Routing

The organization resource also carries the domain/provider mapping used by the built-in
OAuth2/OIDC path when email-domain-based IdP selection is in use.

That is no longer the main production design center of identity, but it remains supported as part
of the low-friction built-in authn path used for development, testing, and self-contained
deployments. This package therefore still translates that configuration into and out of the
organization resource, even though membership and tenancy-root responsibilities are more central
to its present-day role.

## Invariants

- organization visibility is derived from authenticated identity context, not from unauthenticated
  query parameters
- service accounts only see their bound organization through this path
- the organization client is the source of namespace metadata used by the current `v1`
  org-scoped handler tree
- organization reads and writes use the same persisted organization resource contract defined in
  [`pkg/apis/unikorn/v1alpha1`](../../apis/unikorn/v1alpha1/README.md)
- domain/provider mapping, when used, is configuration on the organization resource rather than a
  separate lookup model in the handler layer

## Caveats

- This package makes stronger assumptions about cross-resource consistency than most of the other
  handler clients because a broken organization->membership edge affects the root of the visibility
  tree.
- The current namespace handoff behaviour is important for `v1`, but it is not the intended final
  API shape.
- Domain/provider-directed login behaviour remains supported, but it is a secondary path relative
  to the package's main tenancy-root and membership-resolution role.
- Objects from both branches are shared with the cache, and the converted page shares pointers
  into them (`Spec.Domain`, `ProviderID`, deletion time). Treat both as read-only. Deep copy
  before mutating.
- A dangling `OrganizationUser` fails the membership branch with HTTP 500, on a walk and on an
  `id` lookup. An unknown ID on the global branch is omitted.
- Both API versions ignore the `email` of a service-account caller and return the account's own
  organization.
- Cursor walks are keyset walks over a mutable key. A walk does not see an organization created
  before the cursor until the next walk. An organization renamed across the cursor can appear
  twice or not at all.

## TODO

- Fail closed when organization namespace metadata is unset or otherwise unusable before handing it
  to downstream `v1` org-scoped handler clients.
- Revisit membership-list resilience so orphaned `OrganizationUser` references do not necessarily
  break the entire organization listing path for the caller.

## Related Documentation

- [`pkg/apis/unikorn/v1alpha1`](../../apis/unikorn/v1alpha1/README.md), which defines the
  persisted `Organization` and `OrganizationUser` resources consumed here
- [`pkg/userdb`](../../userdb/README.md), which provides the local user and service-account
  membership lookups used by the organization visibility path
- [`pkg/rbac`](../../rbac/README.md), which defines the authority model that shapes which
  organizations a caller may enumerate or inspect
