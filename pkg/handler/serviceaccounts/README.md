# `pkg/handler/serviceaccounts`

This package manages organization-local non-human identities.

## Intent

Structurally, this package is the service-account analogue of `pkg/handler/users`, but with one
important extra responsibility: issued credential lifecycle.

It manages service accounts that:

- exist only within an organization scope
- inherit authority indirectly through groups and roles
- receive issued access tokens from identity

## What Is Specific Here

### Organization-Local Actor Model

Unlike users, service accounts do not have a separate global identity layer plus an
organization-membership layer.

They are already organization-local actors, so this package operates directly on the
organization-scoped service account resource.

### Group-Based Authority Inheritance

Like users, service accounts do not receive roles directly here.

The package reconciles `groupIDs` into group membership, and those groups then define the effective
authority of the service account through their `RoleIDs`.

So this client participates in the same local delegation model as users, but without the global
identity split.

### Token Issuance And Rotation

This is the main behavioural difference from the users client.

Creating a service account also issues an access token. Updating metadata preserves the existing
token. Rotation is an explicit lifecycle operation that:

- issues a replacement token
- stores the new token and expiry on the resource
- invalidates the old token

Delete also invalidates the current token after unlinking group membership.

That makes this package both an identity-binding client and a credential-lifecycle client.

## Invariants

- service accounts are organization-bound actors
- service-account authority is still mediated through groups and roles
- create returns freshly issued credentials
- ordinary update preserves the current token
- rotate replaces the token and invalidates the old one
- delete removes group membership and invalidates the token

## Caveats

- Like `pkg/handler/users`, this package performs best-effort multi-object consistency across
  service accounts and groups on top of Kubernetes storage rather than an ACID backing store.
- The current access token is stored on the service-account resource and returned on create/rotate,
  so token-handling mistakes have more impact here than in most handler clients.
- The package is intentionally similar to the users client; the main value in documenting it is the
  lack of a global identity layer and the explicit token rotation lifecycle.

## Related Documentation

- [`pkg/handler/users`](../users/README.md), which shows the structurally similar human-identity
  path with a global identity layer
- [`pkg/handler/groups`](../groups/README.md), which binds service accounts to roles
- [`pkg/oauth2`](../../oauth2/README.md), which defines the issued token model and invalidation
  behaviour consumed here
