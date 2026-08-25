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

This package is part of the security model, not a convenience layer for handler checks.

## Security Model

The package enforces several important security rules:

- authority is derived from roles via group membership and actor type
- permissions are additive within the allowed role set
- protected roles are internal-only roles and are never user-facing
- a caller may only grant a role if the caller already holds all permissions contained in that role
- when a system service acts as an impersonated principal, the effective ACL is the intersection of
  the principal's ACL and the service's ACL
- global role binding matching is issuer-qualified: a principal receives a binding's roles only
  when the token's `src_iss` matches the binding's registered issuer exactly. This covers
  platform-administrator entries, the general `--global-role-binding` mechanism, and the
  group-scoped `--global-group-role-binding` mechanism, which also requires the token's asserted
  IdP group to match

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
  accounts mapped from an mTLS certificate common name (see the Actor Model). By default each
  holds only the global permissions the corresponding service actually exercises. **Exception —
  the remote-authorization seam** (`docs/authorization/downstream-remote-authorization-design.md`): a
  consumer whose own API routes through identity's central PDP must have its service-account
  role provisioned as a **superset of what its API authorizes**, because that role is the cap in
  the `intersection(user, service)` a direct-user check resolves against — under-provisioning
  would deny legitimate users. `region-service` accordingly now grants the full `region:*` set,
  and `compute-service` grants the `compute:*` superset of what `administrator`/`user` hold
  (`compute:regions`/`flavors`/`images` read, `compute:instances`/`clusters` full CRUD).

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

`TestBuiltinRoleGrantability` proves the Go lattice is internally consistent, but `AllowRole` also
has to agree with Cerbos, which does the actual enforcement — the grant-guard trusts
`Role.Spec.Scopes` while Cerbos serves the generated policy. That cross-check is the grantability
cross-parity test `TestGrantabilityCrossParity` (integration, `make test-cerbos-decisions`): for
every role — the built-in nine plus the out-of-repo open-vocabulary shapes — it holds a principal
bound to exactly that role and asserts, in both directions, that the generated Cerbos policy grants
it exactly the scopes `AllowRole` trusts it to (with the downward flow). An over-grant would be an
escalation slipping past the grant-guard; an under-grant a role that under-functions. The test is
what lets `AllowRole` stay thin-Go: it guarantees its model and Cerbos enforcement cannot diverge
for any role.

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
administrators and platform-reader (the issuer-wide read grant) today, and any future
issuer-wide grant — is expressed as data through this one mechanism; no per-class fast-path or
role name is hardcoded in Go. `resolveGlobalRoleBindings` is the only path by which global
privileges are granted, evaluated at the top of `processUserAccountACL` before membership
resolution. The Cerbos decision path consumes the same resolution, through
`matchedGlobalBindings` in `cerbos_bindings.go`, so one configuration serves both engines. The
wildcard subject resolves on both: the legacy path clamps it to read, and the Cerbos path emits a
read-clamped binding that activates the role's `global-read` bucket, which the generator projects
from the same global block.

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

A **global group role binding** grants the full global scopes of one or more roles to a
user-account subject. The subject qualifies when its bearer token comes from a specific trusted
issuer and carries a specific group name in that issuer's configured `groupsClaim`
(`BearerTrustSpec.GroupsClaim` — see
[`pkg/oauth2/README.md`](../oauth2/README.md#per-provider-claim-contract) and
[`docs/multi-issuer-token-contract.md`](../../docs/multi-issuer-token-contract.md)).
`resolveGroupRoleBindings` resolves these bindings separately from subject bindings, but the result
joins the same replace-semantics ACL.

Configure bindings with the repeated flag
`--global-group-role-binding=<issuer>::<group>::<roleID>[,<roleID>...]`. The chart renders it from
`globalGroupRoleBindings` (`charts/identity/values.yaml`). Parsing is right-anchored exactly like
`--global-role-binding`: the role list follows the *last* `::`, the group sits between the
second-to-last and the last `::`, and the issuer is everything before that.

The process rejects the following at flag-parse time and does not boot:

- Malformed grammar: fewer than two `::` separators.
- An empty issuer, an empty group, or an empty role-list member.
- The literal wildcard `*` as a group. Group bindings have no wildcard form. Use a wildcard
  *subject* binding for a wildcard-scope grant.
- The `uni` sentinel as the issuer. UNI-local tokens carry no groups claim, so a sentinel group
  binding could never match.

**Matching is byte-exact and case-sensitive**, against the group value verbatim from the flag.
Subjects get a chart-render check that forces canonical lower case, group values do not: IdP group
names commonly use Title Case, and lower-casing the configured value would relocate the mismatch
rather than remove it. Copy the group name from the IdP verbatim.

A wrong-case binding therefore **fails silently**. UNI still accepts the token, and RBAC falls
through to ordinary organization and project membership resolution as if the group had never
matched. The only signal is a log line from `processUserAccountACL`, emitted whenever a token
carries groups and none of them matched a configured binding: "token groups matched no global group
role binding", with the subject, the issuer, and the group count at Info, and the group names on a
separate V(1) line. It fires even when a subject binding
matched, so an operator adding a group binding for someone who already has an exact subject binding
still gets the diagnostic. It is the only diagnostic surface here, because UNI cannot enumerate an
IdP's groups to check the configuration against.

**Full global scopes, no read clamp, no UNI-user gate.** Group bindings accumulate the roles' global
scopes through the same `accumulateGlobalPermissions` that exact-subject bindings use, never through
`accumulateGlobalReadPermissions`, which stays reserved for wildcard *subject* bindings. A group
binding that references a CRUD role grants CRUD globally. Nothing checks that the matched subject
corresponds to an active UNI `User` record, or to any UNI record at all: a subject admitted with
`allowExternalIdentity: true` and an empty `orgIds` slice matches exactly as a UNI-registered user
does. Both properties are deliberate, so that a fixed set of full-scope roles can go to an
IdP-managed population without a parallel UNI-side membership list.

One render-time guard bounds the role choice: the chart refuses a group binding on a role that
writes `identity:users`, `identity:groups`, `identity:roles`, `identity:serviceaccounts`, or
`identity:oauth2providers`. A write on those scopes mints credentials or edits issuer trust. That
converts a settings grant into an identity grant. The guard is render-time only, and roles can gain
write scopes after the render. It narrows the blast radius and does not replace the operator
guidance below.

The consequence is that **UNI configuration no longer enumerates the principals that hold global
write authority through this path.** A subject or wildcard binding names every principal it can ever
grant to, in the flag or chart value itself. A group binding names only the group, and the actual
principals are whoever the IdP currently places in it — a population UNI cannot see, list, or audit.

**Replace semantics shared with subject bindings.** `processUserAccountACL` resolves subject
bindings and group bindings together, and treats a match of either kind as a total replacement: the
ACL is exactly the union of every matched binding's granted scopes, and organization and project
membership resolution is skipped for that session. `accumulateMatchedBindings` emits one
exercise-log line covering both kinds: the matched subject, the matched groups, the granted role IDs
for each, and the count of skipped organization memberships (`len(authz.OrgIds)`, already in the
claim, so producing it resolves no membership). Group membership lives in the IdP, invisible to UNI
storage, so that line is the only place UNI records who exercised global authority through a group.

**Direct bearer tokens only.** UNI populates `authorization.Info.Groups` only for tokens that pass
external-bearer validation inside the identity process — the local authorizer and the RFC 8693
passport-exchange path. UNI does not proxy an external IdP's groups back onto its own tokens, so a
UNI-issued interactive-login access token carries no groups claim at all, even when that login
federates to the same IdP. Only a token presented directly as a bearer, or as the token-exchange
`subject_token`, can carry groups.

**Impersonated hops never carry groups. This is by design, not by gap.**
`processImpersonatedPrincipalACL` passes `nil` for `groups`, and, independently, always evaluates
impersonated principals against the UNI sentinel issuer, which no group binding can be configured
against (rejected at flag-parse time, above). Either fact alone is sufficient, and both hold as
defence in depth. `TestImpersonatedPrincipalNeverMatchesGroupBindings` constructs a sentinel-issuer
binding directly, which isolates the groups-is-nil path from the sentinel-issuer path.
External-issuer *subject* bindings have never applied across a delegated service hop either, so this
is settled behavior rather than a gap: group-derived global authority does not survive
impersonation, for the same reason subject-bound authority never has.

**The legacy Auth0-exchange issuer is dead for group bindings only while the flag path serves
it.** The deprecated `--auth0-exchange-issuer` and `--auth0-exchange-audience` flags build a
synthetic `auth0-legacy` provider that carries no `groupsClaim`, and no flag value can add one.
CRD providers precede the synthetic in the name-sorted candidate list. An `OAuth2Provider` whose
`spec.issuer` matches the legacy issuer therefore always wins against the synthetic: its
`groupsClaim` takes effect and the binding becomes live, with no flag replacement needed. One
migration hazard exists. The synthetic hardcodes `requireAuthzClaim: true`, while the CRD field
defaults to `false`, so a migration to a CRD provider silently relaxes authz-claim enforcement
unless the operator sets the field.

Group bindings also add two findings to `Options.Validate`, described with the other startup checks
below: `ErrGroupBindingNoGroupsClaim` for a bearer-trust candidate whose `groupsClaim` is empty, and
`ErrUntrustedBindingIssuer` for an issuer that is no candidate at all.

**Revocation is not symmetric with grant.** Deleting a binding from configuration and redeploying
takes effect immediately, because every ACL resolution reads the current flag value. The *group
membership* side is not under UNI's control at all: removing a person from the IdP group revokes
nothing until their outstanding access tokens expire and they must obtain a new one without the
group, and UNI neither tracks those tokens nor can invalidate them early. For a subject admitted
through `allowExternalIdentity: true`, with no UNI `User` record to deactivate, there is no UNI-side
lever at all. The only real-time path is at the IdP: remove the group membership and, if urgency
demands it, revoke or rotate the subject's credentials so its outstanding tokens stop being
renewable.

**Operator guidance.** Use a group binding only for an issuer whose group namespace is
administratively controlled — the same population discipline a wildcard-subject binding requires of
its entire user base, narrowed to the subset of users the operator deliberately places in that one
group. Never reuse a `groupsClaim`-enabled issuer between a group binding and any future
self-service or organization-scoped group feature: the binding grants unclamped global scopes to
*every* current and future member of the named group, so a namespace that becomes user-editable
tomorrow would silently hand global authority to whoever a user later adds to it.

**Rollout precondition.** Every downstream service (region, compute, kubernetes, storage, …) must
run a build whose identity middleware keys its ACL cache by the presented token, not only by subject
(see [`pkg/middleware/openapi/README.md`](../middleware/openapi/README.md)). Deploy it everywhere
the binding's granted roles are enforced before you enable the binding, not after. Middleware that
keys by subject alone can serve a subject's non-elevated token a cached ACL computed for that same
subject's group-elevated token, until the stale entry's TTL expires.

**UNI `Group` resources still never grant global authority. IdP-asserted groups now can, by
deployment configuration.** Three sources populate `acl.Global`:

1. `resolveGlobalRoleBindings` — subject and wildcard-subject bindings, feeding
   `accumulateGlobalPermissions`, or `accumulateGlobalReadPermissions` for wildcard bindings.
2. `resolveGroupRoleBindings` — group bindings, described above, also feeding
   `accumulateGlobalPermissions`, unclamped.
3. `processSystemAccountACL`'s X.509-CN-to-role mapping for system accounts.

UNI `Group` membership resolves only `Role.Spec.Scopes.Organization` and
`Role.Spec.Scopes.Project` (`accumulateOrganizationPermissions`, `accumulateProjectPermissions`).
`accumulateGlobalPermissions` deliberately takes a role ID list rather than a `Group`, precisely so
that membership in a UNI `Group` resource cannot itself confer global permissions. That constraint
still holds. What has changed is that a subject's *IdP* group membership now reaches global authority
directly through a group binding, unclamped and with no requirement that the subject be a UNI user.
"Grant global authority through group membership" is therefore an available mechanism — just not
through UNI's own `Group` resource, or anything UNI's membership bookkeeping tracks.

**`Options.Validate` reports every finding from four advisory startup checks.** It joins them with
the stdlib `errors.Join`, so `errors.Is` still matches each one individually. It never blocks
startup. The four checks report:

1. A bare (UNI-sentinel) `--platform-administrator-subjects` entry while a non-UNI issuer is
   trusted.
2. A `--global-role-binding` issuer that is neither the UNI sentinel nor a currently trusted non-UNI
   issuer (`ErrUntrustedBindingIssuer`).
3. A `--global-group-role-binding` issuer that is either untrusted (`ErrUntrustedBindingIssuer`
   again) or a recognized bearer-trust candidate configured with no `groupsClaim`
   (`ErrGroupBindingNoGroupsClaim`). See [Group bindings](#group-bindings) above for what this
   check covers.
4. A trusted issuer whose non-empty `groupsClaim` is not a namespaced URI
   (`ErrMalformedGroupsClaim`). This check examines every issuer in the claims map, not only bound
   ones. Validator construction rejects a malformed claim at the first token dispatched for the
   issuer, so the fault rejects every token from that issuer with HTTP 401, even when no binding
   references it.

Check (2) excludes the deprecated `--auth0-exchange-issuer` value from the trusted set. A binding
aimed at the legacy exchange issuer therefore warns, even though it can still match a real token.
Check (3) reports that same legacy issuer as dead-because-no-`groupsClaim` instead, because its
groups-claim lookup runs before the trusted-issuer fallback (`validateGroupBindingAdvisory`). When
a CRD provider shadows the synthetic and supplies a claim, the binding is live and the check stays
silent.

Only check (1) is gated on a non-empty trusted-issuer list. A bare admin entry only matters once
there is a non-UNI issuer to migrate away from. Checks (2) and (3) run even against an empty
trusted-issuer list, where they report every non-UNI binding issuer. The caller must therefore skip
`Validate` entirely when it cannot tell "no trusted issuers configured" from "the provider `List`
call failed" (`computeTrustedNonUNIIssuers` in `pkg/server` returns an error for that case).

The `groupsClaimByIssuer` map that feeds checks (3) and (4) has a narrower version of the same rule.
`Validate` treats a `nil` map as "the claims lookup failed" and skips check (3) alone, so a caller
with usable `trustedNonUNIIssuers` still runs checks (1) and (2) when the claims fetch fails. A
non-nil-but-empty map would misreport that situation as "no dead bindings".

These warnings are not the security control. The security control is the issuer-qualified
`(srcIss, subject)` match that `resolveGlobalRoleBindings` performs, and the `(srcIss, group)` match
that `resolveGroupRoleBindings` performs, both inside `processUserAccountACL`.

## The Cerbos Decision Path (migration)

Alongside the legacy ACL pipeline, this package carries the Cerbos decision path from the
authorization migration (see
[docs/authorization/cerbos-authorization-design.md](../../docs/authorization/cerbos-authorization-design.md)
and [pkg/authz/cerbos](../authz/cerbos/README.md)). The `Allow*` facade is **dual-path**: behind the
unchanged signatures each scope check either walks the local ACL (the legacy path, retained verbatim
for the shadow comparison and to serve kinds not yet cut over by the strangle-by-kind switch —
removed only at legacy-path retirement) or asks the PDP a coarse question (`Resource{Kind}` for
global, `+OrganizationID` for organization — the project attribute deliberately absent — and both
IDs for project scope, resource ID always the coarse `*`).

- **Dispatch is a structural fail-safe, not a configuration one.** The Cerbos path serves only when
  a decision engine was seeded into the request context (`NewEngineContext`, done by the openapi
  middleware when its authorizer implements `DecisionEngineProvider`) AND that engine's mode for the
  endpoint (`Options.AuthorizationEngine`, the identity server's `--authorization-engine` flag,
  default `legacy`) is `cerbos` — either globally, or for that endpoint alone via the
  strangle-by-kind cutover below. Contexts without an engine — every downstream service (they never
  construct an `RBAC`), `NewSuperContext`, and every ACL-only test context — always take the legacy
  path by construction. That absence-default is the migration's compatibility contract.
- **Shadow mode (`--authorization-engine=shadow`, `shadow.go`)** evaluates BOTH paths synchronously
  for every dispatched scope check and **serves the legacy verdict unconditionally**: nothing the
  shadow evaluation does — a policy deny, a PDP outage, a timeout, even a panic — can alter the
  served verdict (the comparison is recover-wrapped; a shadow failure is a log line, never a request
  failure). Disagreement is logged in two DISTINCT classes, and the split is load-bearing for the
  cutover gate:
  - `cerbos shadow divergence` — the PDP produced a **verdict** and it differs from
    legacy's. Comparison is on allow/deny alone, never on error message strings
    (cerbos-path denials carry a generic message by design). Fields: subject, actor type,
    endpoint, operation, organization/project IDs, both verdicts, the Cerbos sentinel
    class, and the policy-store hash correlate (`policy_hash`).
  - `cerbos shadow evaluation failure` — **no verdict** was obtained (`ErrDecisionUnavailable`,
    `ErrResolutionFailed`, or a recovered panic). This is infra signal, never policy-parity signal:
    **the cutover gate reads "zero divergence" as zero VERDICT divergences, with evaluation failures
    triaged separately**, so a PDP restart during the shadow phase cannot masquerade as policy
    divergence.

  The **policy correlate** is the **policy-store hash** (`policy_hash`): the fingerprint the hasher
  reports (`pkg/authz/cerbos.PolicyStoreHasher`, read-through of the controller-owned policies
  ConfigMap), so a divergence pins the exact store revision it was observed against. It is claimed
  only when a verdict was obtained, and is empty — never invented — when no hasher is configured or
  the hash is not yet available (the same fail-safe contract the coarse cache keys on). This
  replaces the earlier empty PDP echo: the PDP only echoes the *requested* policy version/scope,
  which identity's version-less coarse checks leave unset, so that echo carried no signal.

  Exclusions: `AllowProjectScopeCreate`/`AllowRole` are never shadowed (see below). **Impersonated
  requests are compared too**: the legacy intersection verdict against the AND-ed dual-check verdict
  — both single booleans, so the comparator needed no structural change (an impersonated shadow
  evaluation costs two PDP calls). Costs: shadow is an opt-in validation phase, not steady state —
  every dispatched check pays bindings resolution plus a PDP round trip **on top of** the legacy
  walk, and during a PDP outage each check additionally waits up to `--cerbos-check-timeout` before
  failing the shadow evaluation (the served verdict is unaffected either way).
- **Deny-shape parity.** Cerbos-path denials surface as the same `HTTPForbidden` form the legacy
  walk produces — call sites branch on `err == nil` and the error mapper on the HTTP status — with
  the fail-closed sentinel (`ErrPolicyDenied`, `ErrDecisionUnavailable`, `ErrResolutionFailed`)
  still visible via `errors.Is` for the shadow comparator and the decision observability. A PDP
  outage is therefore a deny that callers cannot tell from a policy deny — deliberately — while
  operators can, via the decision records' `reason` field and the decision counter's `class`
  attribute (see [Decision observability](#decision-observability)).
- **Impersonated requests dispatch like any other**: in cerbos mode they are served by the dual
  check — two AND-ed single-principal evaluations, the impersonated principal and the acting
  service, over the identical resource and action — replacing the legacy confused-deputy ACL
  intersection. The equivalence rests on system-account ACLs being Global-only: the legacy
  intersection then distributes over the (monotone) ACL walk into
  `principal-verdict AND service-verdict`, with the service side inheriting global→org→project
  flow-down structurally (a global binding activates on any resource — asserted by the parity
  matrix, not assumed). Detection is the exact legacy predicate (a principal in context, the
  impersonation marker, and a non-empty actor); an invalid impersonated principal TYPE — System,
  unknown or empty — fails closed with `ErrImpersonationNotSupported`, mirroring the legacy
  `ErrInvalidPrincipalType` hard error rather than falling back to the legacy path.
- **`AllowProjectScopeCreate` and `AllowRole` stay legacy-only, nested checks included**: Create's
  live project-existence orchestration moves to Cerbos as a deferred follow-up, and `AllowRole`'s
  grantability walk stays thin-Go by design. The grantability cross-parity test proved that safe:
  `TestGrantabilityCrossParity` (integration) shows the generated Cerbos policy grants every role —
  the built-in nine and the out-of-repo open-vocabulary shapes — exactly its declared scopes, so the
  thin-Go grant-guard and Cerbos enforcement provably agree and `AllowRole` need not dispatch to the
  PDP.
- **Costs, accepted until later tasks**: the middleware still resolves the legacy ACL for every
  request even in cerbos mode (the double-resolution goes away with the cutover and legacy-path
  retirement), and per-item filter loops over `Allow*` become N single-check PDP calls (the
  localhost sidecar answers sub-millisecond; the coarse-decision cache — below — now memoizes
  repeated identical checks).

- `ResolveBindings(ctx, info)` converts the authenticated subject into the `(role, scope)`
  binding tuples the Cerbos request builder renders. Every branch deliberately mirrors a
  specific legacy ACL-accumulation path — including the odd ones: the silent skip of
  unprovisioned organizations for users (but a hard error for service accounts), the
  service-account org-mismatch fallthrough ported as-is, the hard error for a group
  referencing a missing role next to the silent skip of a project referencing a missing
  group. Bindings resolve across **all** of the subject's organizations (the legacy `Allow*`
  functions read the plural `acl.Organizations` built across all orgs), and the resolver
  never reads `Role.Spec.Scopes` — the generated policies decide what each binding grants.
  Decision parity with the legacy pipeline is the M1 cutover contract; behavioural fixes
  (e.g. the fallthrough's information-leak TODO) are deliberately deferred to post-cutover.
  Global role bindings are honoured here too: a matched subject or group binding **replaces**
  membership resolution entirely, exactly as `accumulateMatchedBindings` does, and platform
  administrators reach it through the same `effectiveGlobalRoleBindings` translation `New`
  applies for the legacy path rather than through a check of their own (so the comparison is
  case-sensitive on both paths). **A wildcard subject binding is read-clamped**, not refused: it
  emits `cerbos.RoleBinding{GlobalRead: true}`, which activates the role's `global-read` bucket —
  the generator's read projection of the same global block the legacy clamp
  (`accumulateGlobalReadPermissions`) reads. The clamp therefore holds for every role shape, and a
  role that gains a write scope after the chart's render guard has run keeps its writes withheld.
  A missing role stays a hard consistency error, as on the legacy path.
- `Check(ctx, resource, action)` / `CheckMany(ctx, checks)` are the decision API: resolve bindings,
  build ONE batched `CheckResources` request, map per-resource `IsAllowed`. **Fail-closed**: every
  failure is a deny, with a distinct static error per failure class — `ErrPolicyDenied` (explicit
  policy deny), `ErrDecisionUnavailable` (no PDP client injected via `WithCerbos`, transport
  failure, malformed response), `ErrResolutionFailed` (missing authorization info, resolver or
  request-construction failure). Every served evaluation is audited and counted at the `CheckMany`
  choke point (see [Decision observability](#decision-observability)).
- **Impersonated requests are the dual check** (`decideImpersonated` in `check.go`): the
  impersonated side resolves from an `Info` synthesized from the propagated principal — mirroring
  the legacy claims rebuild exactly, defensive singular-organization fallback included — and the
  service side from the real context info. BOTH sides always evaluate (no short-circuit): two
  sequential PDP calls, each under the client's per-call timeout, each recording its own latency
  histogram sample; the per-entry verdict is their AND. A resolver or transport failure on either
  side maps to the ordinary fail-closed classes. `ErrImpersonationNotSupported` is **retained with a
  narrowed meaning**: only the type gate — an impersonated principal type that cannot be
  impersonated (System, unknown, empty) — refuses pre-PDP; it is deliberately not `ResolveBindings`'
  default-to-User arm, which would answer for the wrong principal class. **Verdict-level parity with
  the legacy intersection is the contract; two mechanism asymmetries are documented, not
  replicated** (both encoded in the parity matrix like the `UserProjectWrongOrg` precedent): an
  impersonated user scoped to a non-member organization legacy-errors (`ErrNotInOrganization` from
  the request-scoped resolution) where the dual check policy-denies via the request-scope-free
  resolver, and a System-type impersonation legacy-errors (`ErrInvalidPrincipalType`) where the dual
  check refuses with `ErrImpersonationNotSupported` — the same deny verdicts, different error
  shapes. **Coarse-cache-key obligation (delivered)**: the coarse-decision cache (below) keys an
  impersonated entry on the `(impersonated-sub, actor)` pair, the impersonation flag (the
  `direct|`/`impersonated|` discriminator), and the actor's type and org set — every
  verdict-determining input of the dual check — per the design's caching clause, so an impersonated
  verdict can never be served to a direct call, nor to a different impersonated principal. The dual
  check's concrete deliverable for that clause is carrying the pair in every impersonated decision
  record (see below).

### Decision observability

Every PDP-SERVED Cerbos-path decision is audited and counted at the `CheckMany` choke point
(`decision_log.go`): `Check` wraps `CheckMany`, cerbos-mode `allowCoarse` wraps `Check`, and the
remote `/authorization/check` handler lands on `CheckMany` too (delivered — see below) — so remote
decisions inherit these records with no further work. Hooking the choke point rather than decorating
the PDP client is deliberate: the pre-PDP fail-closed denials (no client configured, resolution
failures, refused impersonated principal types) are decisions and must be observed. **One path does
not reach here: a coarse-cache HIT short-circuits before `CheckMany`, so it emits no audit record
and no `decisions_total` increment (it is counted on the separate coarse-cache hit/miss counter
instead — see [the cache](#the-coarse-decision-cache)).** An impersonated dual-check decision is
still ONE record and ONE counter increment per entry — never one per side — with the AND-ed outcome.
Two owner-flagged deviations from the migration plan's file table: **`decision_log` lives in
`pkg/rbac`, not `pkg/authz/cerbos`** (the plan row predates the decision layer being placed here —
the choke point and every record input live in this package, and the PDP client knows nothing about
subjects and stays log-free), and **the policy-store hash correlate (`policy_hash`) is emitted
through the same seam the shadow comparator uses** (sourced from `PolicyStoreHasher`, empty when no
hasher is configured, e.g. downstream or tests).

**The decision log.** One record per `(resource, action)` entry of the batch — the flat, greppable
shape; a batch-wide failure denies every entry, so every entry gets a record with the shared reason
class. The message constant is `authorization decision` (load-bearing: dashboards grep it, unit
tests duplicate it so a rename breaks them). Records emit through the request-scoped logr logger
(`log.FromContext`) into the shared zap JSON stream (`SetupLogging`); the core OTel middleware seeds
that logger with the request's traceID/spanID, so records are trace-correlated automatically — that
is the design's "correlation id", with no explicit field. Levels mirror the core logging
middleware's convention (4xx unconditional, `V(1)` otherwise): **denies at Info unconditionally,
allows at `V(1)`** — this satisfies the design's "every decision" with allows visible at raised
verbosity. Fields (closed set, credential-free — only `Sub` and `Acctype` are read from the
authorization info, NEVER tokens/passports/claims): `subject`, `actor_type`, `endpoint`,
`resource_id` (empty for coarse checks), `operation`, `organization_id`, `project_id`, `decision`
(`allow|deny`), `reason` (`policy|unavailable|resolution|impersonation`, derived from the sentinel
taxonomy via `errors.Is` — `policy` covers both verdicts, including a dual-check deny from either
side; `impersonation` is **narrowed** to the type-gate refusal only; the rest are the fail-closed
classes), `policy_hash` (the policy-store hash correlate pinning the store revision, only claimed
when a verdict was obtained and empty when no hasher is configured), and `latency` (the whole
decision: resolution + PDP + mapping). Impersonated decisions carry exactly two more fields —
`impersonated_subject` and `impersonated_type`, read from the propagated principal — the design's
`(impersonated-sub, actor)` pair, while `subject` stays the acting service (the legacy cache-key
convention).

**Metrics.**

| Instrument | Type | Attributes / boundaries |
| --- | --- | --- |
| `unikorn_identity_authz_decisions_total` | `Int64Counter` | `decision=allow\|deny`, `class=policy\|unavailable\|resolution\|impersonation` — the vocabulary is CLOSED (renames are breaking; `impersonation` survives with its narrowed type-gate-refusal meaning); subject/endpoint attributes would be an open-vocabulary cardinality explosion |
| `unikorn_identity_authz_pdp_latency` | `Float64Histogram` (the repo's first) | unit `s`; explicit sub-second buckets `0.0005 … 2` sized for localhost gRPC, top buckets making `--cerbos-check-timeout` expiries visible |

The counter increments at the same per-entry classification point as the log — once per
decision, never once per dual-check side. The histogram is recorded tightly around the PDP
`CheckResources` round trip only (no resolution, no mapping), success and failure alike —
an impersonated decision contributes two samples, one per side. Instruments export **only when the server runs with
`--otlp-endpoint`** (metrics are pushed over OTLP; no `/metrics` endpoint exists) — without
it the recordings are silently dropped.

**Shadow evaluations are excluded.** They ride the same `CheckMany` funnel via a marked shallow
engine copy (`shadowCompare`), and the marker suppresses their decision records and counter
increments: shadow's signal is the shadow comparator's own divergence/failure records, which the
cutover gate consumes. Only the PDP latency histogram is shared — transport health is
path-independent.

**Shadow sink fix (delivered with the decision observability).** The shadow records (and the
deprecated-`userIDs` group warning) previously emitted through bare `slog` — Go's default TEXT
handler on stderr, outside the zap JSON stream and without trace correlation. Both now emit through
`log.FromContext` into the same sink as the decision records (logr has no warn level; shadow records
emit at Info so they stay unconditionally visible). Message constants and field sets are unchanged.

`make test-cerbos-decisions` (Docker-dependent, so not part of `test-unit`) runs the decision-parity
integration test: from one fixture dataset it computes every verdict through both the legacy
pipeline (`GetACL` + `Allow*`) and the Cerbos path (generated policies served by the pinned image),
and requires verdict equality across a matrix of all four actor classes, all three scope levels, and
the negative cases. A divergence there is an authorization bug in the migration, never something to
special-case. The same run exercises the shadow comparator end to end: against the parity store the
matrix must log zero divergences, and against a deliberately-divergent store (one extra generated
allow the legacy fixture lacks) exactly that one divergence must be detected — with the legacy
verdict still served on the divergent cell. The matrix also carries open-vocabulary cells
(placeholder `example:*`/`sample:*` open-vocabulary roles) — the Go-side proof that
parity is not an artifact of this repo's built-in `identity:*` vocabulary — and impersonated cells:
a registered system account impersonating the fixture user and service account, the byte-untouched
legacy `intersectACL` oracle against the dual check, covering allowed-by-both (including the
project-scope cell witnessing the service side's global→project flow-down), denied-by-service-only
(the narrowing proof), denied-by-principal-only, the wrong-org mechanism asymmetries, and
System-impersonation error parity.

### The remote decision endpoint

`POST /api/v1/authorization/check` (`pkg/handler`, `x-hidden`/`x-no-authorization` in the spec) is
how a downstream service **without** an in-process Cerbos sidecar obtains a decision: it POSTs a
batch of `(resource, action)` checks over mTLS and identity resolves bindings, consults the PDP, and
returns per-check `allowed` booleans in request order. The handler is deliberately thin — it maps
the wire body to `[]CheckRequest` (absence semantics preserved: an omitted
`organizationId`/`projectId` stays absent, never an empty string, so an org check cannot gain a
project attribute) and calls `CheckMany`. Everything else is inherited: the dual check, the decision
records and metrics all apply with no extra plumbing, off the same context the middleware builds for
any mTLS caller.

- **Cerbos-authoritative from day one, no legacy twin.** This endpoint IS the Cerbos path regardless
  of `--authorization-engine` (that flag only selects what serves identity's own `Allow*` facade).
  It has no legacy `Allow*` equivalent to shadow-compare against, which is exactly why the kind-CI
  divergence gate dropped its dependency on this endpoint (nothing to feed it).
- **mTLS-only.** The `oauth2` security scheme multiplexes bearer and mTLS onto the one route, so the
  handler's single security obligation is to reject non-system-account (bearer) callers (it checks
  `authorization.Info.SystemAccount`, set by the middleware from the verified peer CN); a bearer
  caller gets a 401. Hardening the header-strip deploy invariant and moving to signed-principal
  propagation are named follow-ups, not delivered here.
- **Fail-closed crosses the wire.** A per-check policy deny is `allowed: false` at HTTP 200; a
  batch-level failure
  (`ErrDecisionUnavailable`/`ErrResolutionFailed`/`ErrImpersonationNotSupported`) is a non-200 the
  calling `remote` authorizer treats as a deny for every check (`pkg/middleware/openapi/remote`
  `CheckMany`). Remote decisions are indistinguishable from local in the decision records (the
  closed `class` vocabulary has no remote/local split); if operators ever need that split it is a
  future attribute, documented as breaking to rename.

`make test-cerbos-remote` (Docker-dependent, not part of `test-unit`) is the deliverable's
proof: it drives the real router + middleware validator + handler + a real Cerbos-backed RBAC
through the generated typed client, asserting an allowed and a denied check for a system
caller, the dual-check verdict for an impersonated call, bearer rejection, and PDP-down
fail-closed.

### Downstream remote-authorization adoption

This work delivers the identity-side half of routing a **downstream** service's `Allow*` decisions
through identity's central PDP instead of a locally-resolved ACL walk: the seam and its guardrail
essentials specified in
[docs/authorization/downstream-remote-authorization-design.md](../../docs/authorization/downstream-remote-authorization-design.md).
It reuses the `/authorization/check` endpoint above as the wire call and adds a second, independent
dispatch fork alongside the local Cerbos path documented above.

- **One seam, two implementations.** `CoarseEngine` (`coarse_engine.go`) is
  `AllowCoarse`/`AllowCoarseMany` — the same coarse, batch-native shape the local `*RBAC` already
  serves internally (`AllowCoarseMany` wraps `CheckMany`; `AllowCoarse` is the N=1 case over
  `allowCoarse`, decision cache included). `RemoteEngine` (`pkg/middleware/openapi/remote`) is a
  second implementation, adapting the identical interface onto the wire call (`CheckMany` over
  `POST /authorization/check`): its `AllowCoarseMany` is one `CheckMany` round trip for N resources,
  re-wrapping any `CheckMany` failure as `ErrDecisionUnavailable` (`%w`-preserved, so `errors.Is`
  against this package's sentinels answers identically whichever engine served the decision); its
  `AllowCoarse` funnels through `AllowCoarseMany` for the N=1 case, so it carries no telemetry of
  its own (below) — one call in, one observation, never two.
- **`RemoteMode` and dispatch (`remote_engine.go`, `handler.go`).** A remote engine and its
  mode — `RemoteOff`/`RemoteShadow`/`RemoteEnforce` (`ParseRemoteMode`) — are seeded and read
  as one atomic context value (`NewRemoteEngineContext`/`remoteEngineFromContext`), under a
  key independent of the existing local `EngineMode`/`engineKey` seam above: that one selects
  WHICH local engine serves a decision (legacy walk vs. Cerbos); this one selects WHETHER a
  remote engine is consulted at all. `dispatchCoarse`, the single dispatch point behind all
  three `Allow*` scope forks, consults it FIRST, ahead of today's local dispatch:
  - `RemoteEnforce` serves the remote engine's `AllowCoarse` **authoritatively, fail-closed**
    — the `legacy` closure is never even invoked. Deliberately so: a downstream consumer
    wiring a remote engine has no local ACL/CRD access to run the legacy walk, so enforce
    cannot fall back to it on a remote deny or a decision-endpoint outage.
  - `RemoteShadow` evaluates `legacy()` (needed both to serve its verdict and to compare it)
    and hands the pair to `remoteShadowed` (below).
  - No remote engine in context, or one explicitly seeded `RemoteOff` — the zero value, and what an
    unseeded context reports — falls through **unchanged** to today's dispatch: the local Cerbos
    engine when the kind was cut over, else the legacy walk, optionally *locally* shadow-compared
    (above). The two shadow mechanisms stay independent and are never conflated (next).
- **The remote shadow comparator (`remote_shadow.go`) is a downstream analog of the local
  Cerbos shadow comparator above, built for a consumer-side soak gate rather than identity's
  own.** `remoteShadowed` always returns the legacy verdict UNCHANGED — a policy deny, a
  decision-endpoint outage, or a recovered panic on the remote side can never alter the
  served verdict, the same zero-behaviour-change contract the local comparator gives its own
  path. Disagreement is logged into its own two-class taxonomy, mirroring the local split
  exactly:
  - `remote shadow divergence` — a verdict was obtained and it differs from legacy's,
    compared on allow/deny only, never error strings.
  - `remote shadow evaluation failure` — no verdict was obtained (unavailability, an
    unclassified error, or a recovered panic) — infra signal, never divergence signal.

  Both messages are new and distinct from `shadow.go`'s `cerbos shadow …` pair, so the two
  comparators' signals never blur under the same grep. Unlike the local comparator, a remote
  divergence carries no `policy_hash` correlate: the remote `CoarseEngine` has no local
  policy-store hasher to pin a revision against — the generated policy lives at identity, not
  the consumer.
- **How a consumer opts in.** A downstream service builds its `remote` authorizer with the
  `WithRemoteEngineMode` option (left unset, the mode defaults to the zero value
  `RemoteOff` — today's legacy walk, untouched). That satisfies `RemoteDecisionEngineProvider`
  (`pkg/middleware/openapi/decision_engine.go`), the sibling of the local engine's
  `DecisionEngineProvider` (above); `Validator.seedDecisionEngines` (`openapi.go`) — the same
  production choke point that seeds the local engine — seeds the pair into every handler
  context via `NewRemoteEngineContext`. No `Allow*` call site changes.
- **Guardrail essentials, delivered.** The remote call carries its own hard per-call deadline
  (`WithCheckTimeout`, default 250ms) applied via `context.WithTimeout`, independent of whatever
  deadline the caller's own context carries, so a slow or wedged identity cannot block a downstream
  request indefinitely — an expired deadline surfaces through the same fail-closed path as any other
  transport failure. Every `AllowCoarse`/`AllowCoarseMany` round trip also gets caller-side
  telemetry, distinct from identity's own server-side decision instruments: a decision log
  (`remote authorization decision` — denies/unavailable at Info, allows at `V(1)`, deliberately a
  different message from the server-side `authorization decision`) and two metrics,
  `unikorn_identity_authz_remote_decision_total` (`outcome=allow|deny|unavailable`) and
  `unikorn_identity_authz_remote_decision_latency` (network-hop-shaped buckets from 5ms to 5s — an
  order of magnitude above the localhost-sidecar `pdp_latency` above). This is the consumer's own
  view of the round trip, one observation per call regardless of batch size, never a duplicate of
  identity's server-side records.
- **Mechanism now, adoption deferred.** No consumer in this repo builds a `remote` authorizer with
  `WithRemoteEngineMode` set — identity's own `Allow*` behaviour is unaffected by construction,
  since identity's own server always constructs the local authorizer, never the remote one.
  Provisioning and wiring `uni-region`/`uni-compute` (the shadow-then-enforce rollout) is deferred
  downstream work; the circuit-breaker profile is a separate follow-up. Neither is delivered by this
  seam — it ships the mechanism only.

### The kind-CI divergence gate

Kind CI runs the identity server in shadow mode (`hack/ci/test-values.yaml` sets
`identity.authorizationEngine: shadow`), so every fixture and API-suite request doubles as a
live legacy-vs-Cerbos comparison. After the API suite, `hack/ci/divergence-gate` reads the
server logs and **fails on any `cerbos shadow divergence` line**, while `cerbos shadow
evaluation failure` lines are tolerated but printed (infrastructure signal, per the split
above — the gate greps the two exact message constants separately, and asserts the server
container never restarted, since a restart truncates the logs and would make a pass vacuous).

What zero divergence there proves — and does not:

- **Proves:** legacy/Cerbos verdict parity for the identity-served kinds the suite exercises, under
  non-impersonated traffic. The comparator covers impersonated requests, but the kind fixtures and
  API suite send no `X-Impersonate` traffic, so the gate's EVIDENCE remains non-impersonated until
  the fixtures exercise impersonation (a recorded follow-up); impersonated parity is proven by the
  docker matrix's impersonated cells.
- **Does not prove:** open-vocabulary parity (no `example:*`/`sample:*` traffic flows through
  identity's own endpoints) — that is the docker matrix's job above, plus the generator's
  compile suite. The CI values file does inject the transcribed open-vocabulary roles, so the
  kind stack proves those shapes survive generation, the compile gate and publication.

Two supporting CI units guard the gate's integrity (both documented in
[hack/ci](../../hack/ci/README.md)):

- `hack/ci/wait-policies` runs between install and fixtures: until the policy controller's
  first publish reaches the PDP, Cerbos denies everything and every shadowed request would log
  a false divergence, poisoning the gate. Cerbos 0.53.0 only logs its policy count at startup
  (`"Found N executable policies"`) — a live reload after the kubelet back-fills the ConfigMap
  volume is silent at info level — so if the sidecar started against the empty store the unit
  restarts the deployment to make the load observable.
- `hack/ci/decision-flip` runs strictly AFTER the gate: it applies a Role CR granting the user
  persona `identity:roles` read, rebinds the fixture group via kubectl (deliberately bypassing
  the grantability API), and asserts the endpoint flips 403→200 and that shadow divergence
  ceases. The two engines flip at different times (legacy on ~1m ACL-cache expiry, Cerbos on
  ~1m ConfigMap propagation), so a transient divergence window is expected and correct there —
  which is exactly why it must never run before the gate.

### The strangle-by-kind cutover

`--authorization-engine` is a single GLOBAL switch: it makes one engine serve every `Allow*`
decision. The cutover adds a **per-kind override** on top so Cerbos can be made authoritative one
endpoint at a time, without flipping the whole service. `--cerbos-authoritative-kinds`
(`Options.CerbosAuthoritativeKinds`, the chart's `identity.cerbosAuthoritativeKinds`) is the
**cutover set**: the endpoint kinds (e.g. `identity:groups`) for which Cerbos is authoritative
*regardless of the global baseline*.

- **`modeForKind` is the switch** (`engine.go`). It specialises `mode()` per kind: a kind in
  the cutover set resolves to `cerbos` even when the global mode is `legacy` or `shadow`; every
  other kind follows the global mode. Both dispatch (`engineForDispatch`) and the shadow gate
  (`engineForShadow`) consult `modeForKind(endpoint)` rather than `mode()`, so the engine
  decision is taken per endpoint. Matching is **exact-string** on the endpoint — one endpoint
  is strangled at a time (no wildcards in M1). A value that does not exactly match an endpoint
  is a silent no-op leaving the kind on the baseline (fail-open in the safe direction — legacy
  still enforces — but with no per-request signal); entries are whitespace-trimmed, and the
  effective set is logged once at startup (`cerbos authoritative (cutover) kinds configured`) so
  an operator can confirm the flip matches intent.
- **A cut-over kind is Cerbos-authoritative.** It takes the existing cerbos branch
  (`allowCoarse` → `Check`), so the PDP verdict is the SERVED verdict. There is **no legacy
  fallback** and it is **not shadow-compared** (its `modeForKind` is cerbos, so `engineForShadow`
  returns nil for it — a cut-over kind is authoritative-served, never both). Crucially it is
  **fail-closed**: the kind hard-depends on the PDP, so a Cerbos outage is a deny for that kind
  (`ErrDecisionUnavailable`), never a quiet fall back to the legacy ACL walk. That fail-closed
  hard-dependency is the load-bearing safety property of an authoritative cutover.
- **Empty by default = zero behaviour change.** With no kind cut over, `modeForKind == mode()` for
  every kind, so dispatch is byte-identical to the pre-cutover global behaviour. Downstream services
  and every ACL-only test never set the option, so they are unaffected by construction (the same
  absence-default the whole migration rests on).
- **Config-only rollback.** Removing a kind from the set reverts it to the global mode — no code
  change. This is the escape hatch if a cut-over kind misbehaves in production.
- **Mechanism now, flip deferred.** This is the cutover MECHANISM only. WHICH kinds are cut over,
  and WHEN, is an operations config change, gated on the shadow soak (the divergence gate above)
  showing zero verdict divergence for that kind — not decided in this code, which ships with an
  empty default.
- **Legacy code stays until retirement.** The cutover does not remove the legacy ACL walk (nor
  `AllowProjectScopeCreate`/`AllowRole`, which never dispatch to Cerbos): it is retained to serve
  every not-yet-cut-over kind and the shadow comparison. Removing it is the later legacy-path
  retirement.

### The coarse-decision cache

Cerbos-mode `Allow*` dispatch memoizes coarse verdicts so repeated identical checks (the per-item
filter loops over `Allow*`) do not re-hit the PDP. The cache lives at ONE choke point —
`allowCoarse` in `engine.go`, reached only through `engineForDispatch` (cerbos mode) — so the shadow
path (`shadowCompare`) and the remote decision endpoint (the `CheckMany` handler) never touch it:
shadow divergence coverage and remote decisions are uncached by construction.

- **Key dimensions** (`decisionCacheKey`, the analog of the middleware's `aclCacheKey`): the calling
  subject, the `direct|`/`impersonated|` discriminator, the coarse scope
  (`kind|organizationID|projectID`, the no-flow-up shape preserved — org/project empty when absent),
  the action, and the **policy-store hash**. An impersonated key additionally carries the
  impersonated actor, its principal **type**, and its **sorted organization set** — the
  verdict-determining inputs the dual check resolves the actor's bindings from (`impersonatedInfo` →
  `ResolveBindings`) — so two distinct impersonated principals that merely share an actor string
  cannot collide on one cached verdict. (This is stricter than today's `aclCacheKey`, which omits
  type/orgs; aligning the ACL cache is a tracked follow-up.) The resource ID is deliberately absent
  (coarse-only). The impersonation predicate is the SAME `impersonationFromContext` the decision
  path uses, so the key can never disagree with how `decide` treats the request (a marker without an
  actor is direct on both sides).
- **Policy-hash invalidation is the correctness core.** The hash comes from the controller-owned
  policies ConfigMap (see [`pkg/authz/cerbos`](../authz/cerbos/README.md#the-policy-store-hasher)).
  A republish changes the store's content-addressed key set, so the hash changes, so every entry
  keyed on the previous store becomes unreachable — a revoking republish can NEVER be masked by a
  stale cached allow. Residual staleness (while the PDP itself reloads the new store, or in the
  same-hash edge case) is bounded by `--decision-cache-timeout`.
- **Only DEFINITE verdicts are cached** — an allow (`err == nil`) or a policy deny
  (`ErrPolicyDenied`). Transient failures (`ErrDecisionUnavailable`, `ErrResolutionFailed`)
  are NEVER cached: a PDP outage must not poison a later retry. A cached deny is
  reconstructed to the exact `ErrPolicyDenied` HTTPForbidden shape a fresh deny carries, so
  a hit is indistinguishable from a miss to callers.
- **Fail-safe / inert by default.** The cache is only active when a policy-store hasher is
  configured (`WithPolicyStoreHash`, wired only in the identity server). Without one — every
  downstream construction and every test — `decisionCacheKey` reports bypass and every
  decision consults the PDP. An unavailable hash (no successful ConfigMap read yet) or an
  unreadable subject also bypasses. The impersonation type gate runs BEFORE any cache lookup,
  so a cached allow (keyed on the actor, not the principal type) can never be served to a
  principal type that cannot be impersonated.
- **Cache hits skip the decision log and `decisions_total`** (which document PDP-served decisions —
  a hit is not a new PDP decision) but are counted in a dedicated
  `unikorn_identity_authz_coarse_cache_total{outcome=hit|miss}` counter, so the cache's
  effectiveness (hit ratio) stays observable without inflating the PDP-served stream. Misses funnel
  through `CheckMany` and are logged and counted there exactly as before, and additionally recorded
  as `outcome=miss` on the coarse-cache counter. The verbose audit log stays miss-only by design
  (the authoritative decision is logged on the miss that populated the entry). Flags:
  `--decision-cache-size` (default `1<<16`) and `--decision-cache-timeout` (default `1m`).

## The decision stash

`decision_stash.go` is a request-scoped accumulator of `Allow*` outcomes, seeded by
[`pkg/middleware/audit`](../middleware/audit/README.md#decisions-and-the-sensitive-read-marker)
before it calls the handler chain and read back once the handler returns, so the audit record can
carry the resources a request actually referenced and the authorization verdict on each — closing
the front-door-audit gap where the record previously carried neither. It is engine-independent: it
observes whatever verdict the `Allow*` facade already produced, whether served by the legacy ACL
walk, Cerbos, or a remote engine, and changes no authorization decision itself.
`pkg/middleware/audit` also reads this accumulator to type the record's resource itself — the
authoritative `ResourceKind`, not a URL guess — not only to populate the `decisions` list.

- **Purely additive.** `NewDecisionAccumulatorContext` seeds an accumulator into a context;
  `appendDecision` — called from the two hook points below — is a no-op unless one is present. Every
  existing `Allow*` caller and every pre-existing test (none of which seed an accumulator) is
  therefore unaffected by construction, mirroring the migration's own absence-default discipline
  (`EngineFromContext`/`remoteEngineFromContext` above).
- **Hooked at exactly two choke points**, mirroring how `decision_log.go` hooks `CheckMany` rather
  than decorating every call site: `dispatchCoarse` is the single dispatch point behind
  `AllowGlobalScope`, `AllowOrganizationScope` and `AllowProjectScope` — and therefore their `…ID`/
  `…Reader` delegates too — so one append there covers all three scope-check families without
  duplicating the call at every wrapper. `AllowProjectScopeCreate` is hooked separately since it
  deliberately never calls `dispatchCoarse` (its live project-existence orchestration is entangled
  with legacy ACL structure — see its own `NOTE`). Both are thin wrappers around an `…Impl` function
  carrying the original, unchanged logic verbatim: a plain local variable captures the result, not a
  named return plus `defer` (the repository's `nonamedreturns` lint rule forbids the latter).
  **`AllowRole` is deliberately not hooked**: it is a role-*grantability* meta-check over a whole
  role's scope set (many endpoint/operation pairs, evaluated via the legacy walk directly — see its
  own docs above), not a single check against one referenced resource, so it does not fit this
  accumulator's per-resource shape.
- **The accumulated `Decision`** carries the resource kind (the RBAC endpoint, e.g.
  `identity:groups`), the resource ID (empty for every coarse check — global/organization/project
  scope checks never carry a specific instance), the action (`openapi.AclOperation` stringified),
  and the tri-state outcome described next.
- **The outcome vocabulary reuses `decision_log.go`'s reason strings (`policy`, `impersonation`,
  `resolution`, `unavailable`) and adds a tri-state `allow`/`deny`/`unavailable` decision — but
  `decisionOutcome` is a DELIBERATELY DIFFERENT classifier from `decisionClass`, not a call to it.**
  `decisionClass` classifies `CheckMany`'s PDP-served errors only, where an error matching none of
  the sentinels means the PDP/transport failed — correct for that narrower caller. The `Allow*`
  facade's return spans a wider surface: today's default legacy ACL walk, and whatever
  shadow/remote-shadow mode always *serves* (both unconditionally return the legacy verdict),
  produce a plain `errors.HTTPForbidden` denial with **no wrapped sentinel at all** (the legacy
  `*Legacy` functions never call `.WithError`). Reusing `decisionClass` verbatim would misclassify
  that extremely common case — the system's own default operating mode — as `unavailable` instead
  of `deny`. `decisionOutcome` therefore treats an unrecognized non-nil error as an explicit denial
  (`deny`/`policy`): only the specific fail-closed sentinels (`ErrResolutionFailed`,
  `ErrDecisionUnavailable`, `ErrImpersonationNotSupported`) classify as `unavailable` — no verdict
  was reached, so the request was failed closed rather than actually denied by a policy. `nil`
  classifies `allow`/`policy`, and an explicit `ErrPolicyDenied` classifies `deny`/`policy`, matching
  `decisionClass` for the cases the two classifiers do agree on.

## Invariants

- Effective authority is computed from stored identity state, not invented ad hoc in handlers.
- Protected roles are not part of normal user-facing role administration.
- Role grantability is bounded by the caller's own effective permissions.
- ACL intersection for impersonated system-account calls is deliberate least-privilege behaviour.
- Service accounts are organization-bound and their scoped access must remain consistent with that
  binding.
- UNI `Group` membership routes actors to organization- and project-scoped roles only.
  `accumulateGlobalPermissions` accepts a role ID list, never a `Group`, so UNI group membership
  alone can never reach global authority. IdP-asserted groups do reach it: a global group role
  binding grants unclamped global authority to a `groupsClaim` group by deployment configuration,
  with no check that the subject is a UNI user. See [Group bindings](#group-bindings).
- The ACL output is both an enforcement artifact and a visibility artifact, so incorrect ACL
  construction affects both authorization and UX.
- Global role binding matching is always issuer-qualified at runtime. Subject and wildcard-subject
  bindings match on `(srcIss, subject)` (`resolveGlobalRoleBindings`), group bindings on
  `(srcIss, group)` (`resolveGroupRoleBindings`). `Options.Validate` is startup-only and advisory,
  and replaces neither. Bare legacy admin entries match only the UNI sentinel, plus the legacy
  auth0-exchange flag issuer through the startup mirror in `pkg/server`, never a CRD-declared issuer.
- A wildcard-subject binding is always clamped to `read` at authorization time, on both engines: the
  legacy path through `accumulateGlobalReadPermissions`, the Cerbos path through the role's
  `global-read` bucket. The clamp bounds verbs, not response sensitivity, so any role it references
  needs a read-surface audit first. A group binding carries no equivalent clamp — see
  [Group bindings](#group-bindings).
- The chart additionally refuses to render a wildcard binding on a role declaring any non-`read`
  global operation. This does not make the runtime clamp redundant: roles can gain write scopes
  after the render. For group bindings the chart rejects only roles that write the credential and
  trust scopes (`identity:users`, `identity:groups`, `identity:roles`, `identity:serviceaccounts`,
  `identity:oauth2providers`). Other writes render. No runtime clamp backs that guard.
- Subject, wildcard-subject, and group bindings all resolve against the authenticating issuer, never
  a client-supplied one. UNI evaluates impersonated principals against the UNI sentinel with no
  groups, so neither an external-issuer subject binding nor any group binding applies on a delegated
  service hop. Both fail closed.
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
  Grantability against this lattice is enforced on the role *delta* for group updates, not on
  a group's full `RoleIDs` on every write: `pkg/handler/groups` grant-checks a role being
  added and leaves an already-present role unchecked, so a group carrying a role from outside
  this lattice (a third-party service's `Role` CR) stays editable. Removals are not gated —
  dropping a role confers nothing. Create has no prior state, so every role in the request
  counts as an addition.
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
- [`pkg/authz/cerbos`](../authz/cerbos/README.md), which provides the PDP client, policy
  generator and request builder behind the Cerbos decision path
- [`docs/authorization/downstream-remote-authorization-design.md`](../../docs/authorization/downstream-remote-authorization-design.md),
  which specifies the downstream remote-authorization seam documented above
- [`formal/`](../../formal/README.md), the machine-checked Lean model of this package's enforcement
  core and the source of the conformance vectors in `testdata/`
