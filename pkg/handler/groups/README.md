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
themselves, so a client that cannot resolve an ungrantable role — for example one that only fetches
the roles it is permitted to see and then round-trips the group as it received it — cannot silently
revoke that role by omitting it from the write.
A role reference that no longer resolves to a `Role` resource may always be dropped, since a
dangling reference conveys no permissions to revoke. A group carrying a `protected` role may also
always have it dropped: `protected` roles must never be attached to a group in the first place, so
a group that has one anyway (only reachable via direct CR access, since normal writes refuse
`protected` roles on every re-send) needs this drop to stay updatable at all — dropping it is
repair toward that invariant, not a revocation the caller needs permission for. Note the repair is
not just permitted but unavoidable: since re-sending a `protected` role is always refused, the
first successful update of such a group necessarily drops it, including from a client blindly
round-tripping the roles it can see — that is the intended outcome, not accidental silent
revocation. A refused removal names the role so the caller knows which one it cannot drop.

So group writes are also authority-delegation checks, for both grants and revocations.

### Membership Guard Rails

Adding a member to a group hands that member every role the group carries, so it is a grant like
any other and has to trace to a holder. An update that puts a user, subject, or service account on
a group is refused unless the caller could grant each of the group's roles themselves. The roles
checked are the ones the group carries after the write, since that is what the new member inherits.
A refusal names the role.

Two cases confer nothing and therefore never block an addition: a group with no roles at all, and a
role reference that no longer resolves to a `Role` resource.

Create needs no separate membership check. Every role on a new group counts as an addition and is
already grant-checked, so the creator holds everything the new group confers.

The gate applies wherever membership is written, not only through this client:
[`pkg/handler/users`](../users/README.md) and
[`pkg/handler/serviceaccounts`](../serviceaccounts/README.md) reconcile a requested `groupIDs` list
into group membership and run the same check on the branch that adds.

Removals are ungated throughout. Taking a member out of a group takes authority away rather than
handing it out, so a caller who could not add a member to a group may still remove one; deleting a
user or service account strips its memberships as cleanup and is likewise unguarded. Group DELETE
is an unguarded revocation path for the same reason: deleting a group is an explicit, whole-group
action by the caller, not a silent side effect of an update, so the role-removal guard — which
exists to catch omission — does not apply to it.

### Decommissioning A Service's Roles

Retiring a service that contributed roles (third-party or internal) has an order dependency, and
getting it backwards leaves a mess the API cannot clean up on its own.

Strip the service's roles from every group first, then delete its `Role` CRs — not the other way
round. Deleting a `Role` CR while groups still reference it breaks ACL computation for every member
of those groups: `pkg/rbac/rbac.go` returns a consistency error for the dangling reference, failing
closed. The correct order avoids exactly that window.

Once a `Role` CR is actually gone, cleanup is easy: a dangling reference may always be dropped from
a group, by any group-update holder whose own membership does not include the broken group, since
the removal guard above treats a role that no longer resolves as cleanup rather than revocation.
(A member of the affected group cannot perform the repair through the API at all — their own ACL
build fails closed on the dangling reference — so if an organization's only admins sit in that
group, repair falls back to direct CR access.)

The trap is the window before that. While the `Role` CR still exists, removing it from a group is a
guarded revocation like any other — the caller must hold its permissions. That is unremarkable for a
live service, but once a service is being decommissioned, nobody may hold those permissions any
more, so waiting until after the `Role` CRs are deleted to start pulling references can leave a
group stuck with a reference the guard will not let anyone drop through the API (only direct CR
access would). Strip the references while permission holders still exist instead. Roles carrying the
`rbac.unikorn-cloud.org/aggregate-to-administrator: "true"` label are intended to have their
permissions folded into the administrator role by a planned aggregation mechanism; until that
mechanism exists, the label only marks intent. Once it does, it narrows this trap for aggregated
third-party roles specifically: administrators then hold the role's permissions directly for as
long as it stays labelled and installed.

Protected roles are the one case exempt from that trap entirely: they are always droppable from a
group regardless of who holds what, as invariant repair (see Role Assignment Guard Rails above).

Membership is the easier half of the job. Emptying a group of its members needs no authority over
the roles it carries, so members can be pulled out of a group carrying a live ungrantable role at
any point in the sequence, and the group can then be deleted outright. What does not work while the
`Role` CR is still installed is putting anyone *into* such a group — a decommissioning service's
group cannot take on new members once nobody holds its permissions.

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
- callers may only drop roles from a group on update if they are allowed to grant that role, unless
  the role no longer exists
- adding a member to a group is a grant of that group's roles, so it is allowed only where the
  caller could grant every role the group carries
- removing a member from a group, and deleting a member principal, confer nothing and are not gated
- internal compatibility between `UserIDs` and `Subjects` should be maintained where possible
- group membership and role/service-account ID lists are normalized to first-occurrence unique values
- projects should not retain references to groups that no longer exist

## Caveats

- A group seeded with a role from a broader-authority admin becomes membership-frozen for everyone
  who cannot grant that role: they can still rename it, resend its role list, and remove members,
  but not add any. That is the intended trade — a member addition is a grant — and the way out is to
  give the editor the role's permissions, not to relax the check. The planned aggregation mechanism
  described under Decommissioning A Service's Roles above closes this for aggregated third-party
  roles specifically, by extending an administrator's own grantable surface to reach them.
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
