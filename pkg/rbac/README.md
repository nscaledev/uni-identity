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
- platform-administrator matching is issuer-qualified: a subject is only recognized as a
  platform administrator when the token's `src_iss` matches the registered issuer entry

Those rules prevent several different forms of privilege escalation:

- user-facing exposure of internal platform roles
- granting permissions the caller does not personally hold
- confused-deputy expansion through service-to-service calls
- cross-issuer confused-deputy: an external IdP cannot impersonate a UNI-local admin subject, and
  a UNI-local admin subject cannot be promoted to admin via an external token

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

## Built-in Roles

The role catalogue is defined in `charts/identity/values.yaml` and rendered into `Role`
resources by `charts/identity/templates/roles.yaml`. That values file is the single
source of truth; `pkg/rbac` resolves those roles but never invents them. There are two
families.

### Protected (platform) roles

Roles marked `protected: true` are internal-only: never returned by the user-facing role
list and never grantable through the API. They are bound solely via Helm values at
deployment time.

- `platform-administrator` — global CRUD over every resource; can act in any organization
  or project.
- `region-service`, `kubernetes-service`, `compute-service`, `storage-service` — system
  accounts mapped from an mTLS certificate common name (see the Actor Model). Each holds
  only the global permissions the corresponding service actually exercises;
  over-permissioning here is a security defect.

### User-facing roles

These carry `organization` and/or `project` scope blocks and are the roles an
administrator grants to groups.

| Role | organization block | project block |
| --- | --- | --- |
| `administrator` | full CRUD across identity, region, storage, Kubernetes and compute | — |
| `auditor` | read-only across all of the above | — |
| `user` | org-wide reads, plus `region:images` create/delete | CRUD on workloads: networks, load balancers, security groups, file storage, object storage, SSH CAs, clusters, instances |
| `reader` | org-wide reads (`region:images` read only) | read-only on those same workloads |

`administrator` and `auditor` hold all their authority at organization scope. `user` and
`reader` keep a thin organization-wide read baseline but place their real workload
authority in the project block, so it applies only to the projects their group is linked
to.

### Grant relationships

A caller may grant a role only if they already hold every permission it contains, at the
grant's scope or broader (`AllowRole`, with the downward scope flow described above).
Because a grant hands out a subset of what the caller already holds, the built-in roles
form a superset lattice:

```
administrator ─┬─ auditor ─── reader
               └─ user ────── reader
```

- `administrator` can grant every user-facing role.
- `auditor` (read-only) can grant `reader` (also read-only) but not `user`, which needs
  write verbs `auditor` lacks.
- `user` can grant `reader` — the same project scope with fewer verbs (downscoping) — but
  not `auditor`, which needs `identity:*` reads `user` lacks.
- `reader` can grant only `reader`.

`user` and `auditor` are incomparable, and neither can grant `administrator`. This lattice
is locked down by `TestBuiltinRoleGrantability`, which drives `AllowRole` from the parsed
chart values for every ordered role pair, asserting each allowed edge and rejecting every
non-edge.

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

### Platform-administrator issuer-aware fast-path

User account ACL resolution includes a fast-path for platform administrators. The match is on the
pair `(srcIss, subject)` where `srcIss` is the issuer URL (verbatim, as the IdP emits it) carried in
the passport's `src_iss` claim (or the `"uni"` sentinel for UNI-local tokens). The match is an exact
string comparison against each `PlatformAdministratorSubject` entry registered via
`--platform-administrator-subjects`; the configured issuer must equal the emitted `iss` exactly
(for Auth0, including the trailing slash).

Platform-administrator subjects must be registered in `issuer::subject` form when any non-UNI
bearer-trust provider is configured. A bare subject (no `::` prefix) defaults the issuer to the
UNI sentinel, which is safe in single-issuer deployments because the sentinel is deliberately not
a valid URL and cannot be forged by an external token.

**`Options.Validate` is a startup-only, advisory migration gate.** When called during startup with
the list of non-UNI issuers currently present in the operator namespace, it rejects
startup if any admin entry is still in bare (UNI-sentinel) form. This prevents a single-issuer
admin list from being silently exploitable once a second issuer is trusted. However, this gate is
bypassable: a `bearerTrust` CRD created at runtime after startup is not checked by `Options.Validate`.
The always-on, runtime control is the issuer-qualified `(srcIss, subject)` match in
`processUserAccountACL`. Operators must not rely on `Options.Validate` as the sole protection.

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
- Platform-administrator matching is always issuer-qualified at runtime via `(srcIss, subject)`.
  `Options.Validate` is a startup-only advisory gate; it does not replace the runtime control.
- The confused-deputy invariant: a system service acting as an impersonated principal cannot hold
  permissions that either the principal's ACL or the service's ACL denies. The ACL intersection
  enforces this regardless of which IdP authenticated the principal.

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
- Role permission sets must be distributed *consistently across the role hierarchy*.
  Grantability requires the caller to hold every permission a role contains at the same
  scope or broader (`AllowRole`; project-scoped endpoints are satisfied by project, then
  organization, then global authority — not flattened to an organization-only check).
  Granting a service's endpoints to a lower role such as `user` or `reader` *without also
  granting them to every role above it in the grant lattice* — `administrator` for any
  operation, and `auditor` for reads — silently makes that lower role non-grantable and
  invisible to those roles. Any new endpoint added to a role in
  `charts/identity/values.yaml` must be added to every role that should be able to grant
  it, not just the leaf roles that consume it. `TestBuiltinRoleGrantability` enforces this
  over the parsed chart values.
- The `application:*` endpoints (`application:applications`, `application:applicationsets`) were
  removed because the application service was never implemented and never will be — they were dead
  configuration. The removal also fixed a live bug: they were present on `platform-administrator`,
  `user`, and `reader` but absent from the organization `administrator`, which broke administrator
  grantability of `user`/`reader`. They are gone for good; there is no service to grant access to.

## TODO

- Re-check places where globally scoped callers are allowed to skip existence verification for
  user-supplied scoped resource identifiers, especially create paths that accept project IDs in the
  request body.

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
