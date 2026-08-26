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

The grant check on addition applies only to the delta: roles already on the group before the write
are not re-checked, so a caller can resend that group's existing role list without the write being
refused. A role being added is always grant-checked, on both create and update; create has no prior
state, so every role in the request counts as an addition. A refused grant names the role so the
caller knows which one to remove or delegate.

Removals are not gated. Dropping a role confers nothing on anybody, and group DELETE is an
unguarded revocation path anyway, so a removal guard would only move authority checks onto a path
that cannot escalate. Gating removals would also create a stuck state: a role whose permissions
nobody holds — a decommissioned service's role, say — could then never be removed from a group
through the API, which is the same class of stuck group this delta check exists to fix. The
consequence is that a client which omits a role from an update revokes it; a client editing a group
should round-trip the role list it read (`GET /roles` returns every non-protected role, including
ungrantable ones, exactly so that clients can do this).

So group writes are also authority-delegation checks.

### Membership Guard Rails

Adding a member to a group hands that member every role the group carries, so it is a grant like
any other and has to trace to a holder. A `PUT /groups/{id}` that puts a user, subject, or service
account on a group is refused unless the caller could grant each of the group's roles themselves.
The roles checked are the ones the group carries after the write, since that is what the new member
inherits. A refusal names the role.

Membership is compared the way `pkg/rbac` resolves it, not by the stored record. RBAC's
`groupSubjectFilter` matches a subject by `id` alone and deliberately ignores the recorded
`issuer` — subjects written before issuers were captured carry an empty one and must still
resolve — so the gate matches by `id` too (`HasMemberByID`). `email` is display data that different
writers populate from different sources and takes no part either. Both membership representations
count as already-a-member: `pkg/rbac` resolves a principal's groups through `UserIDs` and through
`Subjects` alike, so a member listed in one representation and named through the other gains
nothing, and the write is not an addition. That matters for a group written before `Subjects`
existed, and for a member stored as a legacy empty-issuer subject then re-sent as a `userID`: the
re-send derives a subject at this deployment's issuer, but it names the same principal, so it must
not read as a grant, or such a group has no legal update at all.

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
out, so a caller who could not add a member to a group may still remove one. Deleting a user or
service account strips its memberships as cleanup, and is likewise ungated. Group DELETE takes the
whole group away and is unguarded for the same reason.

### Decommissioning A Service's Roles

Retiring a service that contributed roles (third-party or internal) has an order dependency.

Strip the service's roles from every group first, then delete its `Role` CRs — not the other way
round. Deleting a `Role` CR while groups still reference it breaks ACL computation for every member
of those groups: `pkg/rbac/rbac.go` returns a consistency error for the dangling reference, failing
closed. The correct order avoids exactly that window.

If a `Role` CR is deleted while still referenced, cleanup is still possible: any group-update
holder whose own membership does not include the broken group can drop the dangling reference. (A
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
- adding a member to a group through this client is a grant of that group's roles, so it is allowed
  only where the caller could grant every role the group carries
- the gate treats a principal as already a member by subject `id` alone (`HasMemberByID`), mirroring
  how `pkg/rbac` resolves membership; the recorded `issuer` and the display-only `email` take no part
- removing a member from a group confers nothing and is not gated
- role removals and group DELETE revoke without a role check, by design
- internal compatibility between `UserIDs` and `Subjects` should be maintained where possible
- group membership and role/service-account ID lists are normalized to first-occurrence unique values
- projects should not retain references to groups that no longer exist

## Caveats

- A group carrying a role from a broader-authority admin is frozen for member additions for everyone
  who cannot grant that role: they can still rename it, resend its role list, drop the role, remove
  members and delete it outright, but they cannot add a member through this client, because adding
  one would confer that role. The way out is to give the editor the role's permissions, not to relax
  the check.
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
