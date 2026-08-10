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
- global role binding matching is issuer-qualified: a principal is only granted a binding's
  roles when the token's `src_iss` matches the binding's registered issuer exactly — this covers
  both platform-administrator entries and the general `--global-role-binding` mechanism

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

- `platform-administrator` — global authority across platform resources; can act in any
  organization or project.
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
| `user` | org-wide reads, plus `region:images` create/delete | CRUD on workloads: networks, load balancers, security groups, volumes, file storage, object storage, SSH CAs, clusters, instances |
| `reader` | org-wide reads (`region:images` read only) | read-only on those same workloads |

`administrator` and `auditor` hold all their authority at organization scope. `user` and
`reader` keep a thin organization-wide read baseline but place their real workload
authority in the project block, so it applies only to the projects their group is linked
to.

Region block-storage scopes preserve that split:

- `region:volumeclasses:v2` follows the Region flavor-discovery model: every user-facing
  built-in role receives organization-scoped read access, while `platform-administrator`
  holds the read operation globally.
- `region:volumes:v2` is a project-owned lifecycle scope. `user` has project CRUD and
  `reader` has project read, while `administrator` and `auditor` carry the corresponding
  organization-wide CRUD and read permissions. `platform-administrator` holds global CRUD.

Identity is the rollout dependency for these Region APIs. Deploy the identity role catalogue
containing both scopes before enabling users to rely on VolumeClass listing or Volume lifecycle
operations; otherwise Region authorization receives an ACL without the required endpoint grants.

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

### Global role bindings

Global privileges are expressed through a single mechanism: a **global role binding** maps an
`(issuer, subject | "*")` pair to a set of role IDs. Every kind of global principal — platform
administrators today, and any future issuer-wide grant such as ID-399's planned platform-reader —
is expressed as data through this one mechanism; no per-class fast-path or role name is hardcoded
in Go. `resolveGlobalRoleBindings` is the only path by which global privileges are granted,
evaluated at the top of `processUserAccountACL` before membership resolution.

Bindings are configured with the repeated flag
`--global-role-binding=<issuer>::<subject>::<roleID>[,<roleID>...]`, rendered by the chart from
`globalRoleBindings` (`charts/identity/values.yaml`). Parsing is **right-anchored**: the role list
follows the *last* `::`, the subject sits between the second-to-last and last `::`, and everything
before that is the issuer — this keeps issuer URLs that themselves contain `::` (IPv6 literals such
as `https://[2001:db8::1]/`) unambiguous. `issuer` must be either the verbatim `iss` the IdP emits
(exact string match, including Auth0's trailing slash) or the `uni` sentinel for UNI-local tokens.
`subject` is either an exact subject (matched case-insensitively, with surrounding whitespace
trimmed on both sides) or the literal wildcard `*`, which matches any subject authenticated by
that issuer. Malformed grammar, empty segments (issuer, subject, or any role in the list), a
wildcard subject on the `uni` sentinel, and an issuer that is neither the sentinel nor an absolute
URL (no commas or whitespace) are all rejected at flag-parse time — the process does not boot on a
malformed binding.

**Replace, not additive.** When one or more bindings match the authenticated `(srcIss, subject)`,
the resulting ACL is exactly the union of those bindings' global scopes (read-clamped for wildcard
bindings), and organization/project membership resolution is skipped entirely for that session.
This is a deliberate session-level privilege separation: a hybrid principal (bound issuer/subject
*and* a UNI organization membership) loses their own-org write permissions while authenticated
through the bound issuer — authenticating via the other issuer restores them. Multiple matching
bindings (for example an exact and a wildcard entry on the same issuer) accumulate together.

**The wildcard clamp bounds verbs, not sensitivity.** A wildcard-subject binding is clamped in code
(`accumulateGlobalReadPermissions`) to the `read` operation of each referenced role's global scopes,
so pointing a wildcard at a CRUD role yields read-everything, never write. It says nothing about
what a read endpoint *returns* — some return credential material, such as object-storage access
keys — so any role referenced by a wildcard binding needs its own read-surface audit first.
`platform-reader` receives that audit under ID-399.

**A chart render-time guard complements the runtime clamp.** The chart
(`charts/identity/templates/identity/deployment.yaml`) fails to render if a wildcard binding
references a role whose global scopes include any non-`read` operation, naming the binding index,
role, and offending scope. That keeps the Role CRD authoritative for what an operator can
*configure*, but Roles are live and can gain write scopes after the render — which no render-time
check can see, so the clamp above remains the backstop. No role currently shipped in
`charts/identity/values.yaml` passes this guard; only a dedicated, audited read-only role
(`platform-reader`, ID-399) will.

**Sentinel and impersonation rules.** A wildcard subject can never match the `uni` sentinel or an
empty issuer — rejected at parse time for the sentinel, and guarded again at match time
(`resolveGlobalRoleBindings`) as defence in depth should a future caller leave the issuer unset;
today impersonated principals and pre-`src_iss` passports always carry the sentinel, so that branch
is unreachable. Bindings resolve against the *authenticating* issuer: impersonated principals are
evaluated against the sentinel (`processImpersonatedPrincipalACL` / `srcIssOrUNISentinel`), so an
external-issuer binding never applies on a delegated service hop — it fails closed — while a
`uni`-exact binding still applies there, intersected with the service's ACL, exactly as legacy bare
admin subjects always have.

**Legacy flags translate verbatim.** `--platform-administrator-subjects` and
`--platform-administrator-role-ids` continue to work: each subject is translated into an exact
(non-wildcard) `GlobalRoleBinding` at RBAC construction (`effectiveGlobalRoleBindings`),
byte-for-byte reproducing today's admin behavior, including the `pkg/server` mirroring onto the
deprecated `--auth0-exchange-issuer` flag for bare entries (see below). Translation is verbatim in
the literal sense too: a legacy subject that happens to be the string `*` stays an exact-match
subject and never gains wildcard semantics — only the new `--global-role-binding` flag's subject
`*` is treated as a wildcard.

A bare legacy subject (no `::` prefix) defaults the issuer to the UNI sentinel, which cannot be
forged by an external token because the sentinel is deliberately not a valid URL. **Bare entries
are mirrored onto the legacy Auth0 issuer at server construction:** when the deprecated
`--auth0-exchange-issuer` flag is set, `expandBareAdminSubjects` (in `pkg/server`) appends, for
every bare entry, a concrete issuer-qualified duplicate for that flag's issuer. This reproduces the
issuer-unaware matching that predates issuer qualification: a bare entry matches both UNI-login
sessions (via the retained sentinel entry) and Auth0-exchange sessions (via the mirror), and never
a CRD-declared `bearerTrust` issuer. The mirror grants nothing the old issuer-blind match did not
already grant.

`--platform-administrator-role-ids` supplies the role list for those translated bindings and has no
other consumer, so it is needed only while admin subjects are still expressed through
`--platform-administrator-subjects`. A deployment that expresses every admin through
`--global-role-binding` does not need it.

**Operator guidance.** An issuer-wide (wildcard) binding is only appropriate for an issuer whose
entire user population is itself an authorization decision — for example a staff-only IdP, where
"authenticated by this issuer" already means "should see this data" — never for a general-purpose
IdP with a mixed user base.

**There is no group-based path to global authority.** `acl.Global` is populated from exactly two
sources: `resolveGlobalRoleBindings` (feeding `accumulateGlobalPermissions` or, for wildcard
bindings, `accumulateGlobalReadPermissions`) and `processSystemAccountACL`'s X.509-CN-to-role
mapping for system accounts. Group membership resolves only `Role.Spec.Scopes.Organization` and
`Role.Spec.Scopes.Project` (`accumulateOrganizationPermissions`, `accumulateProjectPermissions`);
`accumulateGlobalPermissions` deliberately takes a role ID list rather than groups, precisely so
standard users cannot be granted global permissions through membership. This means "grant platform
administrators via a group" is not an available alternative to exact per-subject bindings — a
group-based grant would be runtime-mutable and centrally auditable in a way an exact binding is
not, so the absence of that path is a real limitation of the current mechanism, not just an
unused option.

**`Options.Validate` reports every finding from two advisory startup checks**, joined with the
stdlib `errors.Join` so `errors.Is` still matches each individually. It never blocks startup:
(1) a bare (UNI-sentinel) `--platform-administrator-subjects` entry while a non-UNI issuer is
trusted, and (2) a `--global-role-binding` issuer that is neither the UNI sentinel nor a currently
trusted non-UNI issuer (`ErrUntrustedBindingIssuer`). Check (2) excludes the deprecated
`--auth0-exchange-issuer` value from the trusted set, so a binding aimed at the legacy exchange
issuer warns even though it can still match a real token.

Only check (1) is gated on a non-empty trusted-issuer list — a bare admin entry only matters once
there is a non-UNI issuer to migrate away from. Check (2) runs even against an empty list, where
every non-UNI binding issuer is reported, so the caller must skip `Validate` entirely when it
cannot tell "no trusted issuers configured" from "the provider `List` call failed"
(`computeTrustedNonUNIIssuers` in `pkg/server` returns an error for that case). These warnings are
not the security control: that is the issuer-qualified `(srcIss, subject)` match performed by
`resolveGlobalRoleBindings` inside `processUserAccountACL`.

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
- Global role binding matching is always issuer-qualified at runtime via `(srcIss, subject)`,
  evaluated by `resolveGlobalRoleBindings`. `Options.Validate` is startup-only and advisory and
  does not replace it. Bare legacy admin entries match only the UNI sentinel plus, via the startup
  mirror in `pkg/server`, the legacy auth0-exchange flag issuer — never a CRD-declared issuer.
- A wildcard-subject binding is always clamped to `read` at authorization time. The clamp bounds
  verbs, not response sensitivity, so any role it references needs a read-surface audit first.
- The chart additionally refuses to render a wildcard binding on a role declaring any non-`read`
  global operation. This does not make the runtime clamp redundant: roles can gain write scopes
  after the render.
- Bindings resolve against the authenticating issuer, never a client-supplied one. Impersonated
  principals are evaluated against the UNI sentinel, so an external-issuer binding never applies
  on a delegated service hop — it fails closed.
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
