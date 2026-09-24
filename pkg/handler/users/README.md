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

### Global Account Deletion

`GlobalClient` owns the global account record. `Client` owns the organization membership. The
account's identifier is `status.globalUserId`. The membership's identifier is `metadata.id`. The
two identify different objects, not the same one.

**Permission.** The caller needs `identity:users/global` delete permission at global scope. This
scope is separate from `identity:users`, because global `identity:users` delete also removes
members from any organization, and an account delete cannot be undone. The chart's
`platform-administrator` role holds the new scope. A deployment that overrides the `roles` map
must add `identity:users/global: [delete]` to its `platform-administrator` role. A service that
calls the endpoint, such as org-service, needs the scope in its own role. The chart refuses to
render a `globalGroupRoleBindings` entry whose role carries the scope, as it does for the other
credential scopes.

Impersonation intersects the service's ACL with the end user's ACL (`getSystemAccountACL`), so an
impersonated call fails unless the end user themselves holds that permission. A service that
calls on an ordinary user's behalf, such as org-service during signup rollback, must therefore
use its own identity, not `X-Impersonate: true`.

**Refusals.** Account deletion refuses with 422, not 409, for a subject named by a configured
global role binding. This check runs first. This refusal is not retryable: the platform's
configuration blocks the delete, not the resource, so no retry changes the outcome.
`rbac.RBAC.bindings` already folds `platformAdministrators.subjects` into the same list as
`globalRoleBindings`, so one check, `HasGlobalSubjectBinding`, covers both configuration surfaces.
A wildcard binding is excluded from this check, because a wildcard names no subject.
`globalGroupRoleBindings` grants authority through a token's groups claim, with no subject to
compare against, so this refusal does not cover it. That is a known gap in the global role
binding protection, not an oversight.

Account deletion then refuses with 409 while any `OrganizationUser` names the record. The delete
does not cascade. The caller removes the memberships, then calls again, which is what
org-service's signup rollback already does. A retry without removing the memberships gets the
same 409.

Each refusal names the reason it fired. The membership refusal uses the local `conflict` helper. The
global role binding refusal uses core's exported `errors.HTTPUnprocessableContent`, which already
takes a description. The membership refusal states the number of remaining memberships. The global
role binding refusal states the fact only, not the subject. A caller that supplied only a UUID
cannot learn the account's email address from it. `ErrMembership` and `ErrGlobalBinding` still reach
the server log through `WithError`.

**Preconditions.** The delete carries the UID and the resource version from its read as
preconditions. If another change reaches the record during the call, the delete fails instead of
deleting a changed record. A login that adds a session is one example. `Delete` then reads the
record again and tries again, up to three times, so a 409 means only that memberships remain. If
every attempt conflicts, the call answers 500, and the caller retries with backoff.

**Not found.** A 404 with the description "the account does not exist" means that the account is
gone. A caller that retries after such a 404 can treat it as success. A 404 with another description
does not mean that. Core answers a request for a route that the server does not have with its own
"resource not found" text. This happens, for example, during a rollout or with a wrong base URL. A
membership ID also gives the account 404, because no account has that name, so the caller must pass
`status.globalUserId`.

**Uncached reads.** `GlobalClient` reads the account and the membership list through the uncached
client, not the cache the rest of this package reads through. A stale cache that reports no
membership deletes an account that still has one, and nothing restores it. The membership check
and the account delete are two separate calls, not one atomic step. A membership created in the
gap between them points at an account that no longer exists. After that, listing that
organization's users fails with 500, because `convertList` finds no account for the membership.
The organization-scoped delete cannot remove that membership either, because it also looks up the
account first. Two writers can hit this gap: a concurrent `Create` for the same subject, such as
a signup retry, and the uni-auth0 member sync, which also creates memberships. The package accepts
the gap because it lasts milliseconds. ID-532 and ID-533 track the fixes.

`Client.Create` finds the account for a subject, and the account's membership, through the uncached
client, `accountReader`, for the same reason. The cache can still hold an account after
`GlobalClient.Delete` removes it, and can miss a membership that a retried create wrote a moment
ago. A lookup through the cache then reuses the deleted account, or writes a second membership, and
either one breaks the organization's user list. `Create` looks the account up once and uses the same
answer for the grant check and for the write. The lookup uses the `spec.subject` selectable field on
the `User` CRD, so the API server returns only that account, not every account on the platform.
The CRD in the cluster must carry the field. Without it, the API server rejects the field selector,
and every membership create answers 500.

The membership list needs no new permission: `organizationusers` already had `list` and `watch`
in the chart's original rule. `GlobalClient` also fetches the account record itself, before
either refusal runs, through the uncached client. That fetch is a real call to the API server, so
the identity chart grants `get` on `users` in its own clusterrole rule.

**Tokens.** The session records go at once. Identity refuses the account's tokens as soon as its
informer cache observes the delete. `Verify` has one caller, `GetUserinfo`, and for a user token
`GetUserinfo` reads the `User` through that cache on every request. When the `User` is gone, it
refuses the token as "user identity not found or inactive", even if the verification cache still
holds the token. Until the informer cache observes the delete, identity accepts the token. That
gap is the delay of the informer, usually well under a second. In that gap the token usually has
no organization scope. The caller removed the memberships first, but the cache can still hold them
for the same short time. Only a wildcard binding or a `globalGroupRoleBindings` entry can still
give the token global authority.

One case gets through after the gap. A verification in the gap can put the token back in the
verification cache, for up to one hour or until the token expires. On a cache hit, `Verify` does
not check the session, and `GetUserinfo` finds the account by subject. So if a new account with
the same subject appears while that entry lives, the old token works for the new account. The
token belongs to the same subject. ID-501 tracks a fix that pins the check to the account.

`Delete` also evicts the session tokens from the verification cache, before the record delete and
again when `Delete` returns, also when the delete call fails. This is defense in depth. It does not
change the gap. It keeps the tokens of a deleted account out of the cache, in case a later path
trusts `Verify` alone.

A downstream service exchanges the token for a passport that lives 60 seconds, and caches it until
10 seconds before it expires. So it can accept the token for up to about 50 seconds after its last
exchange. It can also serve an ACL that it already cached for that token, one minute by default.

**uni-auth0.** With the matching change in uni-auth0's `UserSyncJob` controller, deleting the
account also removes the Auth0 database user behind it, for a Unikorn-sourced sync job. uni-auth0
reacts to the `User` delete event, and a synced job also checks its `User` on each reconcile. So a
delete that uni-auth0 misses, for example during a restart, is caught when it next starts. One case
can leave the Auth0 user in place. If the delete lands while uni-auth0 is still creating the Auth0
user, uni-auth0 must wait for an Auth0 webhook to learn its id. It stops waiting after 72 hours.

**Operator rule.** uni-auth0 treats every `User` delete as an account delete. Some bulk operations
on `User` objects or on the identity namespace are not real account deletes, for example an
uninstall, a GitOps prune or a restore. Before such an operation, stop the uni-auth0 user-sync
controller. Otherwise uni-auth0 deletes the Auth0 database user of each `User` that goes, and that
cannot be undone.

**Limit: an Auth0-sourced account keeps its Auth0 login.** An Auth0-sourced account exists only
when a user or a membership is created directly in Auth0, which is rare. An Auth0-sourced sync job
mirrors an Auth0 login into Unikorn. The login is the original, so the account delete does not
remove it. When the caller removed each `OrganizationUser`, uni-auth0 removed the matching Auth0
membership, so the login usually has no Auth0 organization memberships left. One race keeps a
membership: an `OrganizationUser` deleted within milliseconds of the time uni-auth0 created it.
ID-499 tracks that race. If an Auth0 administrator adds the login to an Auth0 organization again,
uni-auth0 imports it and creates a new `User`. A membership that the race kept can have the same
result. To remove the login, delete it in Auth0.

**What this does not remove.** `Group.Spec.Subjects` can list this subject with no matching
`OrganizationUser`, for example as a subject at an external issuer. That entry survives the
account delete. RBAC matches group subjects by ID alone and ignores the issuer, so if the subject
signs up again and is re-added to the organization, it silently reinherits the group's roles.
The deleted subject also stays in the `unikorn-cloud.org/creator` and `unikorn-cloud.org/modifier`
annotations of every resource it touched, across compute, kubernetes, and region, though those
grant nothing. This deletes an account. It does not erase a person. ID-484 tracks the annotation
residue. No ticket tracks the group entry.

**Why there is no `delete user` command in uni-kubectl-unikorn.** A `delete user` command has
exactly two possible implementations. It calls this endpoint, which duplicates nothing this
package does not already provide. Or it writes to the `User` CRD directly, skipping both refusals
above. Skipping those refusals is the hazard this endpoint exists to close, so uni-kubectl-unikorn
gets no `delete user` command.

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

The comparisons that write and read membership match the same way, and for the same reason.
`addToGroup` treats any subject with that ID as already present, so filling in a legacy membership
does not append a second, issuer-qualified record. `removeFromGroup` deletes every record with that
ID, so leaving a group removes a legacy empty-issuer member rather than stripping only the record
this deployment wrote — which would report success while leaving the principal an RBAC member. The
reported `groupIDs` are built from the same ID comparison, so a subject-only membership is not
invisible over the API.

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
- a global account delete refuses with 422 for a subject named by a configured global role
  binding, and then with 409 while any organization membership names the account

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
- [`pkg/rbac`](../../rbac/README.md), which provides `HasGlobalSubjectBinding` for the global
  account delete's 422 refusal
