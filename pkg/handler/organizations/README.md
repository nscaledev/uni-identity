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

For callers with global organization-read authority, the client returns all organizations.
Otherwise it derives visibility from identity membership:

- users are mapped through `OrganizationUser` records
- service accounts are mapped to their bound organization
- an optional email filter can be used to ask "which organizations is this user in?", with
  additional permission checks when the caller is not querying their own identity

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
