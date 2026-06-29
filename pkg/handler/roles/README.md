# `pkg/handler/roles`

This package exposes the user-facing role catalogue for a caller inside an organization context.

## Intent

The role resources themselves are globally stored and defined elsewhere in the system. This client
does not create or mutate them. Its job is narrower and security-sensitive:

- list roles that are safe to expose to the current caller
- hide internal-only roles
- hide roles the caller is not permitted to grant

So although the implementation is small, the package is part of the user-facing boundary around
delegation of authority.

## What Is Specific Here

### Visibility Filtering, Not General Role Management

This client is effectively a filtered view over the global role set.

It loads roles from the identity namespace and then removes:

- protected roles, which are never user-facing
- roles the caller is not allowed to grant in the target organization

That means the handler layer does not simply expose "all defined roles". It exposes the subset the
caller may legitimately reason about in administrative flows.

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

The filtering step is organization-aware because grantability depends on the caller's effective
authority in that organization context.

This is where the handler layer turns the deeper `pkg/rbac` anti-escalation rules into a concrete
API behaviour: if the caller cannot legally delegate a role, the role is omitted from the list.

## Invariants

- protected roles are never returned through this user-facing list path
- visible roles must also be grantable by the caller in the supplied organization context
- this package is read-only; it does not define or mutate the underlying role resources

## Caveats

- The package is intentionally thin because the real semantics of authority, protection, and
  grantability belong to `pkg/rbac`.
- Role visibility here is a projection of effective authority, not a complete dump of stored role
  definitions.
- The current role source is still centrally administered even though the longer-term model is
  expected to allow organization-local custom roles.
- A role becomes invisible here the moment any single permission it contains is not held by the
  caller. This makes the list silently sensitive to gaps in the role definitions: if a service's
  endpoints are added to `user`/`reader` but omitted from the organization `administrator`, those
  roles vanish from an administrator's view. See the `pkg/rbac` caveats on consistent permission
  distribution across the hierarchy.

## Related Documentation

- [`pkg/rbac`](../../rbac/README.md), which defines protected roles and the "you may only grant
  what you fully hold" rule enforced here
- [`pkg/apis/unikorn/v1alpha1`](../../apis/unikorn/v1alpha1/README.md), which defines the stored
  `Role` resource
