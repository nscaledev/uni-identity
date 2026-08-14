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
  platform-administrator entries, the general `--global-role-binding` mechanism, and the
  group-scoped `--global-group-role-binding` mechanism, which additionally requires the token's
  asserted IdP group to match

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
- `platform-reader` — global read-only visibility for staff support tooling; the
  read-projection of `platform-administrator` minus credential-bearing scopes,
  pinned by the contract test in `platform_reader_contract_test.go`. Audit
  record, revocation story, and runbook: [docs/platform-reader.md](../../docs/platform-reader.md).
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
administrators and platform-reader (ID-399's issuer-wide read grant) today, and any future
issuer-wide grant — is expressed as data through this one mechanism; no per-class fast-path or
role name is hardcoded in Go. `resolveGlobalRoleBindings` is the only path by which global
privileges are granted, evaluated at the top of `processUserAccountACL` before membership
resolution.

Bindings are configured with the repeated flag
`--global-role-binding=<issuer>::<subject>::<roleID>[,<roleID>...]`, rendered by the chart from
`globalRoleBindings` (`charts/identity/values.yaml`). Parsing is **right-anchored**: the role list
follows the *last* `::`, the subject sits between the second-to-last and last `::`, and everything
before that is the issuer — this keeps issuer URLs that themselves contain `::` (IPv6 literals such
as `https://[2001:db8::1]/`) unambiguous. `issuer` must be either the verbatim `iss` the IdP emits
(exact string match, including Auth0's trailing slash) or the `uni` sentinel for UNI-local tokens.
`subject` is either an exact subject (matched case-sensitively, with surrounding whitespace
trimmed on both sides) or the literal wildcard `*`, which matches any subject authenticated by
that issuer. Malformed grammar, empty segments (issuer, subject, or any role in the list), a
wildcard subject on the `uni` sentinel, and an issuer that is neither the sentinel nor an absolute
URL (no commas or whitespace) are all rejected at flag-parse time — the process does not boot on a
malformed binding.

**Subjects must be in their canonical lower-case form.** Matching is case-sensitive end to end: the
authenticated subject arrives already lower-cased (Auth0's `validateEmail` normalizes the claim
before it reaches RBAC), so a binding subject typed in any other case would simply stop matching.
The chart fails to render if a `globalRoleBindings` or `platformAdministrators.subjects` entry
contains an upper-case ASCII letter (the literal wildcard `*` is exempt, having no letters to
begin with), catching the mistake before deploy rather than deploying a binding that silently
never matches.

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
`platform-reader` received that audit — see [docs/platform-reader.md](../../docs/platform-reader.md).

**A chart render-time guard complements the runtime clamp.** The chart
(`charts/identity/templates/identity/deployment.yaml`) fails to render if a wildcard binding
references a role whose global scopes include any non-`read` operation, naming the binding index,
role, and offending scope. That keeps the Role CRD authoritative for what an operator can
*configure*, but Roles are live and can gain write scopes after the render — which no render-time
check can see, so the clamp above remains the backstop. `platform-reader` is the only role shipped in
`charts/identity/values.yaml` with a global scope block that passes this guard — a dedicated,
audited read-only role (see [docs/platform-reader.md](../../docs/platform-reader.md)).

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

#### Group bindings

A **global group role binding** grants the full global scopes of one or more roles to any
user-account subject whose bearer token, from a specific trusted issuer, carries a specific group
name in that issuer's configured `groupsClaim` (`BearerTrustSpec.GroupsClaim` — see
[`pkg/oauth2/README.md`](../oauth2/README.md#per-provider-claim-contract) and
[`docs/multi-issuer-token-contract.md`](../../docs/multi-issuer-token-contract.md)). It is a
second, group-shaped mechanism alongside subject bindings, resolved separately by
`resolveGroupRoleBindings` but combined into the same replace-semantics ACL.

Bindings are configured with the repeated flag
`--global-group-role-binding=<issuer>::<group>::<roleID>[,<roleID>...]`, rendered by the chart
from `globalGroupRoleBindings` (`charts/identity/values.yaml`). Parsing is right-anchored exactly
like `--global-role-binding`: the role list follows the *last* `::`, the group sits between the
second-to-last and last `::`, and everything before that is the issuer. The process rejects, at
flag-parse time, and does not boot on: malformed grammar (fewer than two `::` separators); an
empty issuer, empty group, or empty role-list member; the literal wildcard `*` as a group (group
bindings have no wildcard form — a wildcard-scope grant uses a wildcard *subject* binding
instead); and the `uni` sentinel as the issuer, because UNI-local tokens carry no groups claim, so
a sentinel group binding could never match anything and is rejected outright rather than shipped
as dead configuration.

**Matching is byte-exact and case-sensitive**, with the group value taken verbatim from the flag.
Unlike subject bindings, there is no chart lower-casing guard for the group value: subjects are
forced to their canonical lower-case form by a chart-render check, but IdP group names commonly
use Title Case or mixed case, and forcing lower-case on the configured value would just relocate
the mismatch rather than remove it. Consequently a group binding configured with the wrong case
for the IdP's actual group name **fails silently** — the token is still accepted, RBAC falls
through to ordinary organization/project membership resolution as if the group had never matched,
and there is no error, only the unmatched-groups log below. Get the case exactly right by copying
the group name from the IdP verbatim. `resolveGroupRoleBindings` logs a line whenever a token
carries at least one group and none of them matched any configured binding ("token groups matched
no global group role binding", with the subject, issuer, and groups attached) — the only
diagnostic surface for a wrong-case or wrong-name binding, since UNI has no way to enumerate an
IdP's groups to validate configuration against.

**Full global scopes, no read clamp, no UNI-user gate.** Group bindings accumulate roles' global
scopes through the same `accumulateGlobalPermissions` used for exact-subject bindings — never
through `accumulateGlobalReadPermissions`, which stays reserved for wildcard *subject* bindings.
A group binding referencing a CRUD role grants CRUD, globally, to every subject whose token
carries that group. There is also no check that the matched subject corresponds to an active UNI
`User` record, or to any UNI record at all: a subject admitted with `allowExternalIdentity: true`
and an empty `orgIds` slice matches a group binding exactly the same way a UNI-registered user
does. Both of these are deliberate — the mechanism exists precisely to hand a fixed set of
full-scope roles to an IdP-managed population without maintaining a parallel UNI-side membership
list for it. The consequence is that **the set of principals holding global write authority
through this path is no longer enumerable from UNI configuration.** A subject or wildcard binding
names every principal it can ever grant to, in the flag or chart value itself; a group binding
names only the group, and the actual principals are whoever the IdP currently places in that
group — a population UNI cannot see, list, or audit. Authority is delegated to IdP group
membership in the fullest sense: UNI's own configuration is no longer a complete description of
who can act with global authority.

**Replace semantics shared with subject bindings.** `processUserAccountACL` resolves subject
bindings and group bindings together and, if either kind matches, treats the match as a total
replacement: the resulting ACL is exactly the union of every matched binding's granted scopes, and
organization/project membership resolution is skipped entirely for that session.
`accumulateMatchedBindings` emits a single exercise-log line covering both kinds uniformly — the
matched subject, the matched groups, the granted role IDs for each, and the count of organization
memberships that were skipped as a result (`len(authz.OrgIds)`, already present in the claim, so
producing the count performs no extra membership resolution). Group membership lives in the IdP,
invisible to UNI storage, so this log line is the only place UNI records who exercised global
authority through a group and why.

**Direct-bearer-only.** Groups are populated on `authorization.Info.Groups` only for tokens that
go through external-bearer validation inside the identity process (the local authorizer and the
RFC 8693 passport-exchange path); a UNI-issued interactive-login access token carries no groups
claim at all — UNI does not proxy an external IdP's groups back onto its own tokens — so a staff
member who signs in through UNI's interactive login, even via the same federated IdP, authenticates
with a token that has no groups and can never match a group binding. Only a token presented
directly as a bearer, or as the token-exchange `subject_token`, can carry groups.

**Impersonated hops never carry groups — by design, not by gap.**
`processImpersonatedPrincipalACL` passes `nil` for `groups` when resolving an impersonated
principal's ACL, and, independently, always evaluates impersonated principals against the UNI
sentinel issuer, which no group binding can ever be configured against (rejected at flag-parse
time above). Either fact alone would already be sufficient; both hold together as defence in
depth (`TestImpersonatedPrincipalNeverMatchesGroupBindings` pins this by constructing a
sentinel-issuer group binding directly, isolating the groups-is-nil path from the sentinel-issuer
path). This is exactly the same shape as external-issuer *subject* bindings, which have never
applied across a delegated service hop either: group-derived global authority does not survive
impersonation, for the same reason subject-bound global authority never has. This is stated
plainly so a future reader does not mistake settled, deliberate behavior for a newly discovered
bug.

**The legacy Auth0-exchange issuer is permanently dead for group bindings.** The synthetic
`auth0-legacy` provider built from the deprecated `--auth0-exchange-issuer` /
`--auth0-exchange-audience` flags has no `groupsClaim` — that flag pair carries no such
configuration — so it always resolves to an empty claim. A group binding aimed at that issuer can
never match a real token, now or after any future flag-value change short of replacing the legacy
flags entirely; it is not merely "currently unconfigured."

**Two more advisories extend `Options.Validate`.** Beyond the subject-binding checks described
below, `Validate` also reports, per `--global-group-role-binding` issuer, one of two findings:
`ErrGroupBindingNoGroupsClaim` when the issuer is a recognized bearer-trust candidate (including
the synthetic legacy Auth0-exchange provider above) but its `groupsClaim` is empty — the binding
is dead configuration, because that issuer's tokens will never carry a groups claim to match
against — or `ErrUntrustedBindingIssuer` (shared with the subject-binding issuer check) when the
issuer is not a recognized bearer-trust candidate at all. Both run unconditionally, not gated on a
non-empty trusted-issuer list, and both are advisory only: they never block startup, and the
security control remains the runtime `(srcIss, group)` match performed by
`resolveGroupRoleBindings`.

**Revocation is not symmetric with grant.** Deleting a subject, wildcard, or group binding from
configuration and redeploying takes effect immediately: every ACL resolution reads the current
flag value, so there is no propagation delay on the *binding* side. But the *group membership*
side of a group binding is not under UNI's control at all. Removing a person from the IdP group
revokes nothing on the spot — it takes effect only once that person's currently outstanding access
tokens expire and they are forced to obtain a new one that no longer carries the group; UNI does
not track which tokens are outstanding and cannot invalidate them early. For a subject admitted
via `allowExternalIdentity: true` with no UNI `User` record at all, there is no UNI-side lever
whatsoever: deactivating a UNI user is not an option because there is no UNI user to deactivate,
and deleting the binding only stops *future* grants, not tokens already issued. The only
real-time revocation path for that population is on the IdP side — remove the group membership
and, if urgency demands it, revoke or rotate the subject's credentials at the IdP so its
outstanding tokens stop being renewable.

**Operator guidance.** A group binding is only appropriate for an issuer whose group namespace is
administratively controlled — the same population discipline a wildcard-subject binding requires
of its entire user base, scoped down to whichever subset of users the operator deliberately places
in that one group. Never reuse a `groupsClaim`-enabled issuer between a global group role binding
and any future self-service or organization-scoped group feature: this mechanism grants unclamped
global scopes to *every* current and future member of the named group, so a group namespace that
is administratively controlled today but becomes user-editable tomorrow — through some later
self-service feature reusing the same claim — would silently hand out global authority to whoever
a user later adds to that group.

**Rollout precondition.** Every downstream service (region, compute, kubernetes, storage, …) must
be running a build whose identity middleware keys its ACL cache by the presented token, not only
by subject (see [`pkg/middleware/openapi/README.md`](../middleware/openapi/README.md)), before any
group binding is enabled. Middleware that keys by subject alone can serve a subject's
non-elevated token a cached ACL that was actually computed for that same subject's group-elevated
token, until the stale entry's TTL expires. Deploy the token-keyed middleware everywhere the
binding's granted roles are enforced before enabling the binding, not after.

**UNI `Group` resources still never grant global authority; IdP-asserted groups now can, by
deployment configuration.** `acl.Global` is populated from three sources: `resolveGlobalRoleBindings`
(subject and wildcard-subject bindings, feeding `accumulateGlobalPermissions` or, for wildcard
bindings, `accumulateGlobalReadPermissions`), `resolveGroupRoleBindings` (group bindings, described
above, also feeding `accumulateGlobalPermissions`, unclamped), and `processSystemAccountACL`'s
X.509-CN-to-role mapping for system accounts. UNI `Group` membership resolves only
`Role.Spec.Scopes.Organization` and `Role.Spec.Scopes.Project` (`accumulateOrganizationPermissions`,
`accumulateProjectPermissions`); `accumulateGlobalPermissions` deliberately takes a role ID list
rather than a `Group`, precisely so membership in a UNI `Group` resource cannot itself confer
global permissions — that constraint is unchanged and still holds. What has changed is that this is
no longer the whole story: a subject's *IdP* group membership, asserted in a bearer token's
configured `groupsClaim`, now reaches global authority directly through a group binding, with no
read clamp and no requirement that the subject be a UNI user at all. "Grant global authority via
group membership" is consequently now an available mechanism — just not through UNI's own `Group`
resource, and not through anything UNI's own membership bookkeeping tracks. The practical
consequence is the one stated above: the set of principals holding global write authority is no
longer fully enumerable from UNI configuration, because a group binding names only a group, and
UNI has no visibility into who the IdP currently places in it.

**`Options.Validate` reports every finding from three advisory startup checks**, joined with the
stdlib `errors.Join` so `errors.Is` still matches each individually. It never blocks startup:
(1) a bare (UNI-sentinel) `--platform-administrator-subjects` entry while a non-UNI issuer is
trusted, (2) a `--global-role-binding` issuer that is neither the UNI sentinel nor a currently
trusted non-UNI issuer (`ErrUntrustedBindingIssuer`), and (3) a `--global-group-role-binding`
issuer that is either untrusted (`ErrUntrustedBindingIssuer` again) or a recognized bearer-trust
candidate configured with no `groupsClaim` (`ErrGroupBindingNoGroupsClaim`) — see
[Group bindings](#group-bindings) above for what that third check covers. Check (2) excludes the
deprecated `--auth0-exchange-issuer`
value from the trusted set, so a binding aimed at the legacy exchange issuer warns even though it
can still match a real token; check (3) instead reports that same legacy issuer as
dead-because-no-groupsClaim, because its groups-claim lookup runs before the trusted-issuer
fallback (`validateGroupBindingAdvisory`).

Only check (1) is gated on a non-empty trusted-issuer list — a bare admin entry only matters once
there is a non-UNI issuer to migrate away from. Checks (2) and (3) run even against an empty
trusted-issuer list, where every non-UNI binding issuer is reported, so the caller must skip
`Validate` entirely when it cannot tell "no trusted issuers configured" from "the provider `List`
call failed" (`computeTrustedNonUNIIssuers` in `pkg/server` returns an error for that case). These
warnings are not the security control: that is the issuer-qualified `(srcIss, subject)` match
performed by `resolveGlobalRoleBindings`, and the `(srcIss, group)` match performed by
`resolveGroupRoleBindings`, both inside `processUserAccountACL`.

## Invariants

- Effective authority is computed from stored identity state, not invented ad hoc in handlers.
- Protected roles are not part of normal user-facing role administration.
- Role grantability is bounded by the caller's own effective permissions.
- ACL intersection for impersonated system-account calls is deliberate least-privilege behaviour.
- Service accounts are organization-bound and their scoped access must remain consistent with that
  binding.
- UNI `Group` membership is the route from actors to organization- and project-scoped roles, and
  only those: `accumulateGlobalPermissions` accepts a role ID list, never a `Group`, so UNI group
  membership alone can never reach global authority. IdP-asserted groups are a separate route that
  can: a global group role binding grants global authority to a `groupsClaim` group by deployment
  configuration, unclamped to read and with no check that the subject is a UNI user. See
  [Group bindings](#group-bindings).
- The ACL output is both an enforcement artifact and a visibility artifact, so incorrect ACL
  construction affects both authorization and UX.
- Global role binding matching is always issuer-qualified at runtime via `(srcIss, subject)` for
  subject and wildcard-subject bindings (`resolveGlobalRoleBindings`) and via `(srcIss, group)` for
  group bindings (`resolveGroupRoleBindings`). `Options.Validate` is startup-only and advisory and
  does not replace either. Bare legacy admin entries match only the UNI sentinel plus, via the
  startup mirror in `pkg/server`, the legacy auth0-exchange flag issuer — never a CRD-declared
  issuer.
- A wildcard-subject binding is always clamped to `read` at authorization time. The clamp bounds
  verbs, not response sensitivity, so any role it references needs a read-surface audit first. A
  group binding carries no equivalent clamp — see [Group bindings](#group-bindings).
- The chart additionally refuses to render a wildcard binding on a role declaring any non-`read`
  global operation. This does not make the runtime clamp redundant: roles can gain write scopes
  after the render. The chart has no equivalent guard for group bindings, which are never clamped
  in the first place.
- Bindings — subject, wildcard-subject, and group — resolve against the authenticating issuer,
  never a client-supplied one. Impersonated principals are evaluated against the UNI sentinel with
  no groups, so neither an external-issuer subject binding nor any group binding ever applies on a
  delegated service hop — both fail closed.
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

## Formal Model

A machine-checked Lean 4 model of this package's enforcement core lives in
[`formal/`](../../formal/README.md). It proves the security properties this package relies on —
scope downward-flow, grant safety at global and organization scope (and the project-scope caveat,
which holds only under external invariants documented in `handler.go`), and the confused-deputy
soundness of `intersectACL` — and makes the `allowGrantProjectScope` "any accessible project"
subtlety explicit.

The model is also executable: it generates the conformance vectors in
[`testdata/model_vectors.json`](testdata/model_vectors.json) that `grant_model_test.go` runs the
real `AllowRole` against, so the code is checked to agree with the proven model. Regenerate with
`make regenerate-vectors` (needs a Lean toolchain); CI fails if the committed vectors drift. The
unit tests themselves need no Lean — they read the committed JSON.

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
- [`formal/`](../../formal/README.md), the machine-checked Lean model of this package's enforcement
  core and the source of the conformance vectors in `testdata/`
