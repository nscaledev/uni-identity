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

This is the path that matters most for authority a downgraded caller can keep hold of. A group
membership on a user takes effect through a session; a group membership on a service account rides
a token that lives for up to 90 days and that the account can keep renewing itself.

Re-sending a group the account already belongs to confers nothing new and passes. Removing it from
a group takes authority away rather than handing it out, so the remove branch is unguarded, and
delete is exempt for the same reason: it reconciles against an empty group list, so it only ever
unlinks, and an account must remain deletable even when it sits in a group nobody can grant the
roles of.

Reconciliation is validate-then-apply: every group the account would newly join is grant-checked
before the first group is patched, so a write that joins one group the caller may grant and another
they may not is refused whole rather than applying the permitted half.

That ordering is a guarantee about *refusals*, not about failures. What it buys is that no
authorization decision is ever discovered after a write has landed. It does not make the write
atomic — see the caveat on partial application below.

A group ID the organization does not have is refused rather than dropped. Reconciliation matches
the request against the groups that exist, so an ID matching nothing would otherwise leave the
caller with a success whose body does not mention the group it asked for.

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
- a requested group that does not exist in the organization is an error, not a silently dropped
  part of the write
- a refused membership addition applies none of the write's other additions, and on create issues
  no token
- create returns freshly issued credentials
- ordinary update preserves the current token
- rotate replaces the token and invalidates the old one
- delete removes group membership and invalidates the token

## Caveats

- Like `pkg/handler/users`, this package performs best-effort multi-object consistency across
  service accounts and groups on top of Kubernetes storage rather than an ACID backing store.
- **Create can strand a credentialled account.** The grants are settled first and the account is
  written second, but the group patches come third, and nothing rolls the account back if one of
  them fails. Two ways in: an infrastructure failure part-way through the loop, or a concurrent
  privileged writer changing a group between the pre-pass reading it and the reconciler patching
  it. The second is *detected* rather than silently allowed — the patch carries an optimistic lock
  against the version the pre-pass read, so a group modified underneath the request conflicts
  instead of quietly conferring a role nobody authorised — but detection still arrives after any
  earlier group in the same request has been patched. Either way the caller sees an error while a
  service account exists, holds a freshly issued token, and sits in some prefix of the groups it
  asked for.

  There is deliberately no rollback attempt: unpicking a partial write needs the same multi-object
  atomicity the storage layer does not offer, and a failed rollback leaves a worse state than the
  one it was trying to repair.

  What makes this worth knowing rather than merely untidy is that a stranded account is not inert.
  `Rotate` is gated on `identity:serviceaccounts` update or on the account rotating *itself*, and
  neither path re-checks group membership, so the account can keep renewing its own credential
  indefinitely and any update holder can re-token it. Callers that see create fail should treat the
  account as possibly created and delete by name; operators auditing this should look for service
  accounts whose group membership does not match anything a caller would have asked for.
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
