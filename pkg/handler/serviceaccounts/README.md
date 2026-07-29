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

### Membership Additions Are Grants

Putting a service account into a group hands it every role that group carries, so it is a grant and
is checked as one: the add branch of the reconciliation refuses unless the caller could grant each
of the group's roles in that organization. The refusal names the role. This is the same rule
[`pkg/handler/groups`](../groups/README.md) applies to membership written through the group itself
— the check lives in `pkg/handler/common` so both entry points share it, and a service-account
write cannot be used to sidestep the group write's guard.

Re-sending a group the account already belongs to confers nothing new and passes. Removing it from
a group takes authority away rather than handing it out, so the remove branch is unguarded, and
delete is exempt for the same reason: it reconciles against an empty group list, so it only ever
unlinks, and an account must remain deletable even when it sits in a group nobody can grant the
roles of.

Reconciliation is validate-then-apply: every group the account would newly join is grant-checked
before the first group is patched, so a write that joins one group the caller may grant and another
they may not is refused whole rather than applying the permitted half.

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
- adding a service account to a group is a grant of that group's roles, so it is allowed only where
  the caller could grant every role the group carries; removals and account deletion are not gated
- a refused membership addition applies none of the write's other additions
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
