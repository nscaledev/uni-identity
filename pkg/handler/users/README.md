# `pkg/handler/users`

This package manages user membership at the boundary between global identity and
organization-local participation.

## Intent

Unlike most handler clients, this package does not manage a single resource kind in a single
scope.

It coordinates two related resources:

- the global `User` record in the identity namespace
- the organization-scoped `OrganizationUser` record in the organization namespace

Its job is to keep those two layers aligned while also reconciling group membership for the user
inside the organization.

## What Is Specific Here

### Global Identity Plus Organization Membership

User creation is not ordinary CRUD on one object.

The client first gets or creates the global `User` identified by subject, then gets or creates the
organization-local `OrganizationUser` membership, then reconciles group membership inside that
organization.

That makes this package the bridge between:

- "this identity exists in the system"
- "this identity is a member of this organization"
- "this identity belongs to these groups in this organization"

### Group Membership Reconciliation

Group membership is maintained indirectly through group resources rather than being stored only on
the user.

When a user is created, updated, or deleted in an organization, this client walks the group's list
and adds or removes both:

- the legacy `UserIDs` membership
- the newer subject-based membership

So this package is not just a membership record manager. It is also one side of the compatibility
bridge between old and new group-membership representations.

### Membership Additions Are Grants

Putting a user into a group hands them every role that group carries, so it is a grant and is
checked as one: the add branch of the reconciliation refuses unless the caller could grant each of
the group's roles in that organization. The refusal names the role. This is the same rule
[`pkg/handler/groups`](../groups/README.md) applies to membership written through the group itself
— the check lives in `pkg/handler/common` so both entry points share it, and a user write cannot be
used to sidestep the group write's guard.

The check keys on the change, not on the request: re-sending a group the user already belongs to
confers nothing new and passes. Membership has two representations, the deprecated `UserIDs` list
and the subject list, and `pkg/rbac` resolves a user into a group through either one. A user
present in one is therefore already a member, so filling in the other half confers nothing and is
not gated. That matters for groups written before subjects existed: re-sending their membership
derives the missing half for the first time, and reading that as a grant would leave such a group
with no legal user write at all.

For the same reason, the already-a-member test matches subjects by ID alone, mirroring how
`pkg/rbac` actually resolves membership (see `GroupSpec.HasMemberByID`). Subject records written
before issuers were recorded carry an empty issuer and still confer the group's roles, so an
issuer-qualified comparison would read a no-op re-send of such a membership as an addition and
refuse it — the frozen-group failure this gate exists to avoid. If RBAC matching ever becomes
issuer-qualified, the gate must move with it.

Removing a user from a group takes authority away rather than handing it out, so the remove branch
is unguarded. Deletion is exempt for the same reason — it reconciles against an empty group list,
so it only ever removes, and a user must remain deletable even when they sit in a group nobody can
grant the roles of.

Reconciliation is validate-then-apply: every group the user would newly join is grant-checked
before the first group is patched. A write that joins one group the caller may grant and another
they may not is refused whole, leaving both untouched, rather than applying the permitted half and
then failing. Without that, whether a partial grant landed would depend on the order the groups
came back in.

Create runs the same check earlier still — before the global `User` and the `OrganizationUser` are
written, not just before the group patches. A create refused on its group membership therefore
leaves no records at all, rather than an account the caller was told it could not create. Because
create is idempotent, the check resolves any records the subject already has first, so memberships
they already hold are exempt just as they are on update.

That ordering is a guarantee about *refusals*, not about failures. No authorization decision is
ever discovered after a write has landed. It does not make the write atomic — see the TODO on
partial-failure behaviour below.

A group ID the organization does not have is refused rather than dropped. Reconciliation walks the
groups that exist and asks of each whether the request names it, so an ID matching nothing matches
no branch: without the check the caller would get a success whose body simply does not mention the
group it asked for.

### Read Model Aggregation

The user read model is assembled from multiple sources:

- subject and session activity come from the global `User`
- organization-local state comes from the `OrganizationUser`
- group membership comes from the organization's groups

This is why list and get operations are more aggregation-oriented than most of the other handler
clients.

## Invariants

- global identity and organization membership are distinct layers and must not be collapsed into a
  single resource model
- an organization must have at most one `OrganizationUser` membership for a given global `User`
- repeated create requests reuse the existing `OrganizationUser` without mutating its state; callers
  must use update to intentionally change organization-local state
- organization membership changes must keep group membership consistent with the requested
  `groupIDs`
- a requested group that does not exist in the organization is an error, not a silently dropped
  part of the write
- adding a user to a group is a grant of that group's roles, so it is allowed only where the caller
  could grant every role the group carries; removals and user deletion are not gated
- a principal present in either membership representation is already a member, so completing the
  other half is not an addition
- a refused membership addition applies none of the write's other additions, and on create writes
  no user records either
- user read responses are assembled from global user state, organization membership state, and
  group membership state together
- the API-managed path only allows email-address subjects for normal user creation

## Caveats

- The package is more stateful than most handler clients because create, update, and delete can
  touch users, organization users, and groups in one logical operation.
- Because group membership compatibility is maintained here as well as in the groups client,
  cross-client consistency matters more than local code shape.

## TODO

- Revisit partial-failure behaviour in create/update/delete flows that mutate organization users
  and then reconcile groups, so membership state does not drift if later steps fail. Authorization
  no longer contributes: every grant in a request is settled before that request writes anything.
  What remains is infrastructure failure partway through a multi-object write — a conflict or an
  API-server error on the third of four group patches leaves the first two applied, and on update
  the organization user is patched before group reconciliation starts. Closing that needs a
  rollback or a single-object write.
- Revisit list resilience so an orphaned `OrganizationUser` -> `User` reference does not
  necessarily fail the entire organization user listing.

## Related Documentation

- [`pkg/handler/organizations`](../organizations/README.md), which provides the parent
  organization scope and namespace handoff used here
- [`pkg/handler/groups`](../groups/README.md), which owns the group resources this package
  reconciles membership into, and documents the guard rails on their roles
- [`pkg/userdb`](../../userdb/README.md), which shields authn/authz consumers from the raw local
  `User` and `OrganizationUser` storage joins that this package mutates
- [`pkg/apis/unikorn/v1alpha1`](../../apis/unikorn/v1alpha1/README.md), which defines the stored
  `User`, `OrganizationUser`, and group membership compatibility fields
- [`pkg/oauth2`](../../oauth2/README.md), which consumes global user state for authentication and
  session handling
