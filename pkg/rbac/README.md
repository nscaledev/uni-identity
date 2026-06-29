# `pkg/rbac`

This package computes effective authority inside UNI after authentication and identity propagation
 have already happened.

## Intent

The package is the platform's effective-authority engine.

It takes authenticated actor context and delegated identity context, resolves roles and group
membership from identity storage, and produces ACLs that the rest of the system can enforce.

Its main responsibilities are:

- resolve permissions for users, service accounts, and system accounts
- apply global, organization, and project scope
- prevent confused-deputy behaviour when a service acts as an impersonated principal
- constrain administrative delegation so callers cannot grant authority they do not themselves hold

This package is not just a convenience layer for handler checks. It is part of the security model.

## Security Model

The package enforces several important security rules:

- authority is derived from roles via group membership and actor type
- permissions are additive within the allowed role set
- protected roles are internal-only roles and are never user-facing
- a caller may only grant a role if the caller already holds all permissions contained in that role
- when a system service acts as an impersonated principal, the effective ACL is the intersection of
  the principal's ACL and the service's ACL

Those rules prevent several different forms of privilege escalation:

- user-facing exposure of internal platform roles
- granting permissions the caller does not personally hold
- confused-deputy expansion through service-to-service calls

## Scope Model

The package works with the same three logical scope levels defined by identity roles:

- global
- organization
- project

ACL construction and handler enforcement both follow that structure. Global permissions can satisfy
organization and project checks, organization permissions can satisfy some project checks, and
project permissions remain the narrowest scope.

This scoped structure is used both for direct authorization decisions and for query limiting in list
operations.

Each scope check comes in three argument flavours so callers pass whatever they already hold,
without re-deriving it:

- `AllowOrganizationScope` / `AllowProjectScope` / `AllowProjectScopeCreate` take plain `string`
  IDs. These are **deprecated** (marked `// Deprecated:` so tooling flags new use) but **retained
  for backwards compatibility** while callers that still deal in plain strings (IDs sourced from
  API response bodies, and repos that pre-date the typed ID types) migrate; they will be removed
  once that is done.
- `…ID` variants (`AllowOrganizationScopeID`, `AllowProjectScopeID`, `AllowProjectScopeCreateID`)
  take typed `ids.OrganizationID` / `ids.ProjectID`. **API handlers use these**, since the IDs
  arrive already decoded from URL path parameters.
- `…Reader` variants (`AllowOrganizationScopeReader`, `AllowProjectScopeReader`,
  `AllowProjectScopeCreateReader`) take a resource implementing `ids.OrganizationScopeReader` /
  `ids.ProjectScopeReader` and recover the IDs from it. **Callers holding a CRD use these** — the
  label-read-and-parse happens in one place behind the interface rather than at every call.

Rule of thumb: path-parameter handler → `…ID`; you have a CRD object in hand → `…Reader`.

## Actor Model

The package distinguishes three important actor classes:

- users
- service accounts
- system accounts

Users derive access from organization membership, groups, and roles.

Service accounts derive access from their bound organization and group membership.

System accounts derive access from configured platform roles mapped from their authenticated service
identity, typically an mTLS certificate common name.

When a system account carries an impersonated principal, RBAC does not simply switch to the
principal's ACL. Instead, it intersects the principal ACL with the system account ACL so the service
cannot exercise permissions that either side lacks.

## Invariants

- Effective authority is computed from stored identity state, not invented ad hoc in handlers.
- Protected roles are not part of normal user-facing role administration.
- Role grantability is bounded by the caller's own effective permissions.
- ACL intersection for impersonated system-account calls is deliberate least-privilege behaviour.
- Service accounts are organization-bound and their scoped access must remain consistent with that
  binding.
- Group membership is the main route from actors to roles.
- The ACL output is both an enforcement artifact and a visibility artifact, so incorrect ACL
  construction affects both authorization and UX.

## Caveats

- The package is tightly coupled to the identity storage and scoping model, including groups,
  projects, organization mappings, and label-based queries.
- Some migration-era behaviour is still present, especially compatibility with the deprecated
  `Group.UserIDs` field alongside the newer `Subjects` model.
- The package contains a mix of ACL construction, scope filtering, and handler-facing convenience
  checks, so it is broader than a pure policy-definition layer.
- Some pragmatic compatibility behaviour exists around scoped lookups and transition paths, so
  security-sensitive changes here should be reviewed in terms of end-to-end actor behaviour rather
  than local code shape alone.
- Role permission sets must be distributed *consistently across the role hierarchy*. Because
  grantability requires the caller to hold every permission a role contains (with project-scoped
  endpoints promoted to an organization-scope check), granting a service's endpoints to a lower
  role such as `user` or `reader` *without also granting them to the organization `administrator`*
  silently makes that lower role non-grantable and invisible to administrators. Any new service
  endpoint added to the roles in `charts/identity/values.yaml` must be added to every role that
  should be able to grant it — not just the leaf roles that consume it.
- The `application:*` endpoints (`application:applications`, `application:applicationsets`) were
  removed because the application service was never implemented and never will be — they were dead
  configuration. The removal also fixed a live bug: they were present on `platform-administrator`,
  `user`, and `reader` but absent from the organization `administrator`, which broke administrator
  grantability of `user`/`reader`. They are gone for good; there is no service to grant access to.

## TODO

- Re-check places where globally scoped callers are allowed to skip existence verification for
  user-supplied scoped resource identifiers, especially create paths that accept project IDs in the
  request body.
- Add test coverage for role grantability/visibility across the role hierarchy. The `application:*`
  regression went unnoticed because nothing asserts that every non-protected role remains grantable
  by the organization `administrator`; a guard test over the role definitions would have caught it.

## Relationship To Other Packages

- `pkg/oauth2` establishes actor identity and session/token validity
- `pkg/principal` carries delegated identity and impersonation signals
- `pkg/rbac` converts those inputs into effective local authority
- middleware and handlers consume the resulting ACLs to enforce access and shape responses

## Related Documentation

- [`pkg/oauth2`](../oauth2/README.md), which establishes actor identity, session validity, and local
  admission before RBAC resolution
- [`pkg/userdb`](../userdb/README.md), which shields RBAC from the raw local identity storage model
  when resolving users, organization memberships, and service accounts
- [`pkg/principal`](../principal/README.md), which carries delegated identity and impersonation
  signals consumed here
- [`pkg/apis/unikorn/v1alpha1`](../apis/unikorn/v1alpha1/README.md), which defines the stored role,
  group, organization, project, user, and service-account resources this package resolves
