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

### Read Model Aggregation

The user read model is assembled from multiple sources:

- subject and session activity come from the global `User`
- organization-local state comes from the `OrganizationUser`
- group membership comes from the organization's groups

This is why list and get operations are more aggregation-oriented than most of the other handler
clients.

### Obsolete Signup / Email Verification Path

The package still contains the built-in signup and email-verification path used by the local
first-party authn flow.

That path is now obsolete in the context of local development, testing, and third-party IdPs. It
is therefore retained as removable legacy surface rather than as part of the intended long-term
shape of the package.

## Invariants

- global identity and organization membership are distinct layers and must not be collapsed into a
  single resource model
- an organization must have at most one `OrganizationUser` membership for a given global `User`
- repeated create requests reuse the existing `OrganizationUser` without mutating its state; callers
  must use update to intentionally change organization-local state
- organization membership changes must keep group membership consistent with the requested
  `groupIDs`
- user read responses are assembled from global user state, organization membership state, and
  group membership state together
- the API-managed path only allows email-address subjects for normal user creation

## Caveats

- The package is more stateful than most handler clients because create, update, and delete can
  touch users, organization users, and groups in one logical operation.
- The built-in signup/email path is obsolete legacy surface and should not be treated as the
  package's intended future direction.
- Because group membership compatibility is maintained here as well as in the groups client,
  cross-client consistency matters more than local code shape.

## TODO

- Revisit partial-failure behaviour in create/update/delete flows that mutate organization users
  and then reconcile groups, so membership state does not drift if later steps fail.
- Revisit list resilience so an orphaned `OrganizationUser` -> `User` reference does not
  necessarily fail the entire organization user listing.
- Remove the obsolete signup/email verification path.

## Related Documentation

- [`pkg/handler/organizations`](../organizations/README.md), which provides the parent
  organization scope and namespace handoff used here
- [`pkg/userdb`](../../userdb/README.md), which shields authn/authz consumers from the raw local
  `User` and `OrganizationUser` storage joins that this package mutates
- [`pkg/apis/unikorn/v1alpha1`](../../apis/unikorn/v1alpha1/README.md), which defines the stored
  `User`, `OrganizationUser`, and group membership compatibility fields
- [`pkg/oauth2`](../../oauth2/README.md), which consumes global user state for authentication and
  session handling
