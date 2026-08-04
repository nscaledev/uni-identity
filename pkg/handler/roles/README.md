# `pkg/handler/roles`

This package exposes the user-facing role catalogue for a caller inside an organization context.

## Intent

The role resources themselves are globally stored and defined elsewhere in the system. This client
does not create or mutate them. Its job is narrower and security-sensitive:

- list roles that are safe to expose to the current caller
- hide internal-only (protected) roles entirely
- tell the caller, per role, whether they are allowed to grant it in the target organization

So although the implementation is small, the package is part of the user-facing boundary around
delegation of authority.

## What Is Specific Here

### Visibility Filtering And The Grantable Flag Are Two Different Things

This client is effectively a filtered, annotated view over the global role set.

It loads roles from the identity namespace and then removes protected roles, which are never
user-facing. Every remaining role is returned, annotated with a `grantable` flag computed for the
calling principal in the target organization.

Protected and ungrantable are two different reasons a role might not be freely delegated, and they
are handled differently:

- a protected role is internal and is never returned, regardless of caller
- a role the caller cannot grant is still returned, with `grantable: false`

`pkg/handler/groups` stores role membership by ID (see its `RoleIDs`), and API clients resolve
those IDs to display names and descriptions by calling this list endpoint. A group can carry a role
the current caller cannot themselves grant — for example one assigned by someone with broader
authority. Omitting ungrantable roles from this list, rather than flagging them, hides such a role
from any caller who cannot grant it, so a client that resends "the roles I can see" back to the group
drops the one it could not resolve. `pkg/handler/groups` refuses that write and names the role, so
the role is not lost — but the caller is left with an error about a role their tooling cannot show
them. `grantable: false` closes that gap: it lets a caller display and reason about a role it does
not itself hold, without being able to add or remove it (`pkg/rbac`'s `AllowRole` remains the actual
enforcement point on group writes).

### Current Global Definition, Future Local Customization

Today the roles exposed here are defined by the platform administrator and stored centrally.

That is the current operational model. The longer-term direction is to allow organization
administrators to define finer-grained custom roles within their own scope. When that happens,
this package will still be the user-facing projection layer, but the underlying role catalogue
will no longer be purely platform-defined.

That future model still needs to preserve the existing security invariants:

- organization administrators may only create or grant roles whose permissions they fully hold
- protected/internal roles must remain non-user-facing
- organization-local roles must remain clearly separated from platform-defined roles

### Organization-Aware Grantability

The `grantable` flag is organization-aware because grantability depends on the caller's effective
authority in that organization context; the same role can be `grantable: true` for a caller in one
organization and `grantable: false` for the same caller in another.

This is where the handler layer turns the deeper `pkg/rbac` anti-escalation rules into a concrete,
per-role, per-caller API value: `grantable` is exactly `rbac.AllowRole(ctx, role, organizationID) ==
nil`. It gates what the caller may do with the role (add it to or remove it from a group), not
whether the role appears in the list.

## Invariants

- protected roles are never returned through this user-facing list path
- every non-protected role is returned exactly once per `List` call, annotated with the caller's
  per-organization `grantable` flag; visibility and grantability are independent
- `grantable` reflects `rbac.AllowRole` for the supplied organization and does not imply the role can
  be hidden or shown differently — it only gates add/remove of the role on a group
- this package is read-only; it does not define or mutate the underlying role resources

## Caveats

- The package is intentionally thin because the real semantics of authority, protection, and
  grantability belong to `pkg/rbac`.
- Role visibility here hides only protected roles; it is not a projection of effective authority —
  that projection is carried by the per-role `grantable` flag instead of by omission.
- The current role source is still centrally administered even though the longer-term model is
  expected to allow organization-local custom roles.
- `grantable` becomes `false` for a role the moment any single permission it contains is not held by
  the caller. This makes the flag silently sensitive to gaps in the role definitions: if a service's
  endpoints are added to `user`/`reader` but omitted from the organization `administrator`, an
  administrator sees those roles as `grantable: false` even though they should be able to grant them.
  See the `pkg/rbac` caveats on consistent permission distribution across the hierarchy, the built-in
  role catalogue and grant lattice documented there, and the `TestBuiltinRoleGrantability` guard that
  pins those relationships to `charts/identity/values.yaml`.
- `grantable: false` says what the caller may not do with the role, not that the role can be ignored.
  A caller cannot add such a role to a group, and cannot drop it from one either: `pkg/handler/groups`
  refuses both and names the role in the error. A client updating a group that carries an ungrantable
  role must therefore send that role back unchanged rather than filtering it out of the payload.

## Related Documentation

- [`pkg/rbac`](../../rbac/README.md), which defines protected roles and the "you may only grant
  what you fully hold" rule surfaced here as `grantable`
- [`pkg/handler/groups`](../groups/README.md), which stores role membership by ID and guards both
  adding a role to a group and dropping one from it; API clients use this package's list endpoint to
  resolve and display roles a group references, including ones the current caller cannot grant
- [`pkg/apis/unikorn/v1alpha1`](../../apis/unikorn/v1alpha1/README.md), which defines the stored
  `Role` resource
