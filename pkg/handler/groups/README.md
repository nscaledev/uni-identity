# `pkg/handler/groups`

This package manages the primary local delegation unit inside an organization.

## Intent

Groups are the main attachment point between identities and authority.

They answer three related questions:

- which users are members of the group
- which service accounts are members of the group
- which roles those members inherit through the group

Projects then refer to groups rather than directly to users or roles, so this package sits at the
center of organization-local delegation.

## What Is Specific Here

### Primary Binding Layer For Local Authority

This client is where organization membership turns into inherited permissions.

Users and service accounts do not receive roles directly through this handler layer. Instead, they
become members of groups, and groups carry the `RoleIDs` that define the granted authority.

That makes groups the main local delegation unit for both human and non-human actors.

### Compatibility Bridge Between `UserIDs` And `Subjects`

The package still supports both:

- legacy `UserIDs`, which refer to `OrganizationUser` records
- newer `Subjects`, which can refer to local or external identities

When a request uses one of those representations, the client populates the other where possible so
old and new clients can coexist during the migration period.

This compatibility behaviour is one of the main reasons the package is more than simple CRUD.

### Role Assignment Guard Rails

Group role assignment is where the handler layer turns the deeper RBAC security model into a
concrete write-time check.

When roles are attached to a group, this client:

- verifies the role exists
- rejects protected roles, whether newly added or already on the group
- rejects newly added roles the caller is not permitted to grant in that organization
- rejects updates that drop a role the caller is not permitted to grant in that organization

The grant check on addition applies only to the delta: roles already on the group before the write
are not re-checked, so a caller can resend that group's existing role list without the write being
refused. A role being added is always grant-checked, on both create and update; create has no prior
state, so every role in the request counts as an addition. A refused grant names the role so the
caller knows which one to remove or delegate.

Removal is guarded symmetrically, on update only: dropping a role from the group's current
`RoleIDs` that is not present in the request is refused unless the caller could grant that role
themselves. Without that, a client that cannot resolve an ungrantable role — one that fetches only
the roles it is permitted to see and then round-trips the group as it received it — would revoke
that role by omitting it from the write. A refused removal names the role so the caller knows which
one it cannot drop.

Two cases are exempt from the removal guard, because dropping them is repair rather than
revocation:

- a role reference that no longer resolves to a `Role` resource. A dangling reference conveys no
  permissions, and dropping it is how a group carrying one gets repaired.
- a `protected` role. Protected roles must never be attached to a group in the first place, so a
  group that has one anyway — only reachable via direct CR access, since normal writes refuse
  `protected` roles on every re-send — needs this drop to stay updatable at all. Dropping it is the
  only way such a group can be updated: re-sending the `protected` role is refused every time, so
  any successful update has already dropped it. A client that blindly round-trips whatever the
  group reports keeps hitting that refusal, because `GET /groups` reports the `protected` role
  while `GET /roles` does not; only a client that filters its role list against `GET /roles` drops
  the role and gets through.

So group writes are also authority-delegation checks, for both grants and revocations.

### Membership Guard Rails

Adding a member to a group hands that member every role the group carries, so it is a grant like
any other and has to trace to a holder. A `PUT /groups/{id}` that puts a user, subject, or service
account on a group is refused unless the caller could grant each of the group's roles themselves.
The roles checked are the ones the group carries after the write, since that is what the new member
inherits. A refusal names the role.

Membership is compared by principal identity, not by stored record. A subject identifies a
principal by `(issuer, id)`; its `email` is display data that different writers populate from
different sources, so it takes no part in the comparison. Both membership representations count as
already-a-member: `pkg/rbac` resolves a principal's groups through `UserIDs` and through `Subjects`
alike, so a member listed in one representation and named through the other gains nothing, and the
write is not an addition. That matters for groups written before `Subjects` existed — re-sending
their membership fills in the missing half and must not be read as a grant, or such a group has no
legal update at all.

A group with no roles confers nothing, so membership in it is not a grant and nothing blocks the
addition. A role reference that no longer resolves is the opposite case and does block it — see
Decommissioning A Service's Roles below for why that direction is not symmetric with removal.

Create needs no separate membership check. Every role on a new group counts as an addition and is
already grant-checked, so the creator holds everything the new group confers.

This gate sits on the groups path. [`pkg/handler/users`](../users/README.md) and
[`pkg/handler/serviceaccounts`](../serviceaccounts/README.md) also write group membership, by
reconciling a requested `groupIDs` list into the groups that name the principal, and those paths do
not run this check.

Removals are ungated. Taking a member out of a group takes authority away rather than handing it
out, so a caller who could not add a member to a group may still remove one. Group DELETE is an
unguarded revocation path for the same reason: deleting a group is an explicit, whole-group action
by the caller, not a silent side effect of an update, so the role-removal guard — which exists to
catch omission — does not apply to it. Deleting a user or service account strips its memberships as
cleanup, and is likewise unguarded.

### Decommissioning A Service's Roles

Retiring a service that contributed roles (third-party or internal) has an order dependency, and
getting it backwards leaves a mess the API cannot clean up on its own.

Strip the service's roles from every group first, then delete its `Role` CRs — not the other way
round. Deleting a `Role` CR while groups still reference it breaks ACL computation for every member
of those groups: `pkg/rbac/rbac.go` returns a consistency error for the dangling reference, failing
closed. The correct order avoids exactly that window.

Once a `Role` CR is actually gone, cleanup is easy: a dangling reference may always be dropped from
a group, by any group-update holder whose own membership does not include the broken group, since
the removal guard treats a role that no longer resolves as cleanup rather than revocation. (A
member of the affected group cannot perform the repair through the API at all — their own ACL build
fails closed on the dangling reference — so if an organization's only admins sit in that group,
repair falls back to direct CR access.)

Adding a member to a group carrying a dangling reference is refused, and the refusal names the
unresolvable role ID. The two directions are deliberately asymmetric, and the reason is that role
IDs are not random: a role ID is derived from the role name, so deleting a `Role` CR and re-applying
it later brings back the *same* ID, which immediately re-binds to every group that still references
it. Anyone added to the group during that window silently acquires the role when it returns, without
a grant check ever having run — and for a service account, that authority rides a long-lived token.
Skipping an unresolvable role therefore errs towards less authority on a removal and towards more on
an addition, so only the removal side is safe to skip. Refusing additions also matches what
`pkg/rbac` already does with the same reference: it fails closed.

A side effect worth naming: because ACL construction fails closed, adding someone to a
dangling-reference group breaks their whole organization ACL, not just their access to that group.
Refusing the addition closes that off as well, at least on the groups path.

The trap is the window before that. While the `Role` CR still exists, removing it from a group is a
guarded revocation like any other — the caller must hold its permissions. That is unremarkable for a
live service, but once a service is being decommissioned, nobody may hold those permissions any
more, so waiting until after the `Role` CRs are deleted to start pulling references can leave a
group stuck with a reference the guard will not let anyone drop through the API (only direct CR
access would). Strip the references while permission holders still exist instead.

Protected roles are the one case exempt from that trap entirely: they are always droppable from a
group regardless of who holds what, as invariant repair (see Role Assignment Guard Rails above).

Membership is the easier half of the job. Emptying a group of its members needs no authority over
the roles it carries, so members can be pulled out of a group carrying a live ungrantable role at
any point in the sequence, and the group can then be deleted outright — group DELETE is unguarded.
Deleting the group takes the members with it, so it is only the right move when the group exists to
carry the retiring service's roles and nothing else. What does not work while the `Role` CR is still
installed is putting anyone *into* such a group through `PUT /groups/{id}`: a decommissioning
service's group cannot take on new members that way once nobody holds its permissions.

### Project Reference Cleanup

Projects use groups as access boundaries.

Because of that, deleting a group is not a local-only operation. The client must first remove the
group from any project `groupIDs` that still reference it, otherwise project-scoped access state
would drift.

## Invariants

- groups are the primary organization-local attachment point between members and roles
- `RoleIDs` are the actual delegated-authority payload of the group
- protected roles must never be attached to a group
- callers may only add roles they are allowed to grant in that organization; roles already on the
  group are not re-checked on subsequent writes
- callers may only drop a role from a group on update if they are allowed to grant that role,
  unless the role no longer resolves or is protected
- adding a member to a group through this client is a grant of that group's roles, so it is allowed
  only where the caller could grant every role the group carries
- a principal is the same member in either representation, identified by `(issuer, id)`; a subject's
  `email` is display data and takes no part in that comparison
- removing a member from a group confers nothing and is not gated
- group DELETE revokes without a role check, by design
- internal compatibility between `UserIDs` and `Subjects` should be maintained where possible
- group membership and role/service-account ID lists are normalized to first-occurrence unique values
- projects should not retain references to groups that no longer exist

## Caveats

- A group seeded with a role from a broader-authority admin is frozen for everyone who cannot grant
  that role: they can still rename it, resend its role list, remove members and delete it outright,
  but they cannot drop the role and cannot add a member through this client. That is the intended
  trade — dropping a role is a revocation, and adding a member is a grant, and the caller has to be
  entitled to make either — and the way out is to give the editor the role's permissions, not to
  relax the check.
- The membership gate covers `PUT /groups/{id}` only. The same membership can be written through
  `pkg/handler/users` and `pkg/handler/serviceaccounts`, which reconcile a requested `groupIDs` list
  without this check, so a caller holding `identity:users` or `identity:serviceaccounts` write can
  still put a principal into a group whose roles it cannot grant.
- The package is partly a migration bridge because it must support both deprecated `UserIDs` and
  forward-looking `Subjects`.
- Groups may include external subjects that do not resolve to local `User` objects, so not every
  group member is necessarily backed by a local user record.
- Referential integrity across groups, users, service accounts, and projects is best-effort on top
  of Kubernetes storage rather than atomically enforced by the backing store.

## Related Documentation

- [`pkg/handler/users`](../users/README.md), which establishes organization membership that groups
  then bind to roles
- [`pkg/handler/serviceaccounts`](../serviceaccounts/README.md), which establishes the
  organization-local non-human identities that groups also bind to roles
- [`pkg/handler/projects`](../projects/README.md), which uses groups as project access boundaries
- [`pkg/rbac`](../../rbac/README.md), which defines the security rules around protected and
  grantable roles enforced here
- [`pkg/apis/unikorn/v1alpha1`](../../apis/unikorn/v1alpha1/README.md), which defines the stored
  `Group` resource and the `UserIDs` to `Subjects` migration context
