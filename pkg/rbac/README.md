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

`TestBuiltinRoleGrantability` proves the Go lattice is internally consistent, but `AllowRole`
also has to agree with Cerbos, which does the actual enforcement — the grant-guard trusts
`Role.Spec.Scopes` while Cerbos serves the generated policy. That cross-check is A16's
`TestGrantabilityCrossParity` (integration, `make test-cerbos-decisions`): for every role — the
built-in nine plus the out-of-repo open-vocabulary shapes — it holds a principal bound to
exactly that role and asserts, in both directions, that the generated Cerbos policy grants it
exactly the scopes `AllowRole` trusts it to (with the downward flow). An over-grant would be an
escalation slipping past the grant-guard; an under-grant a role that under-functions. The test
is what lets `AllowRole` stay thin-Go: it guarantees its model and Cerbos enforcement cannot
diverge for any role.

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

## The Cerbos Decision Path (migration)

Alongside the legacy ACL pipeline, this package carries the Cerbos decision path from the
authorization migration (see
[docs/cerbos-authorization-migration-design.md](../../docs/cerbos-authorization-migration-design.md)
and [pkg/authz/cerbos](../authz/cerbos/README.md)). Since A6 the `Allow*` facade is
**dual-path**: behind the unchanged signatures each scope check either walks the local ACL
(the legacy path, retained verbatim for A7's shadow comparison and removed only at the A12
cutover) or asks the PDP a coarse question (`Resource{Kind}` for global, `+OrganizationID`
for organization — the project attribute deliberately absent — and both IDs for project
scope, resource ID always the coarse `*`).

- **Dispatch is a structural fail-safe, not a configuration one.** The Cerbos path serves
  only when a decision engine was seeded into the request context (`NewEngineContext`,
  done by the openapi middleware when its authorizer implements `DecisionEngineProvider`)
  AND that engine's mode (`Options.AuthorizationEngine`, the identity server's
  `--authorization-engine` flag, default `legacy`) is `cerbos`. Contexts without an engine
  — every downstream service (they never construct an `RBAC`), `NewSuperContext`, and
  every ACL-only test context — always take the legacy path by construction. That
  absence-default is the migration's compatibility contract.
- **Shadow mode (`--authorization-engine=shadow`, task A7, `shadow.go`)** evaluates BOTH
  paths synchronously for every dispatched scope check and **serves the legacy verdict
  unconditionally**: nothing the shadow evaluation does — a policy deny, a PDP outage, a
  timeout, even a panic — can alter the served verdict (the comparison is
  recover-wrapped; a shadow failure is a log line, never a request failure). Disagreement
  is logged in two DISTINCT classes, and the split is load-bearing for A12's cutover gate:
  - `cerbos shadow divergence` — the PDP produced a **verdict** and it differs from
    legacy's. Comparison is on allow/deny alone, never on error message strings
    (cerbos-path denials carry a generic message by design). Fields: subject, actor type,
    endpoint, operation, organization/project IDs, both verdicts, the Cerbos sentinel
    class, and the policy correlate.
  - `cerbos shadow evaluation failure` — **no verdict** was obtained
    (`ErrDecisionUnavailable`, `ErrResolutionFailed`, or a recovered panic). This is infra
    signal, never policy-parity signal: **A12's gate reads "zero divergence" as zero
    VERDICT divergences, with evaluation failures triaged separately**, so a PDP restart
    during the shadow phase cannot masquerade as policy divergence.

  The **policy correlate** is currently the in-band per-result policy version/scope the
  SDK response carries (plus the record's timestamp) — a deliberate deviation from the
  plan's "policy hash". Note the PDP echoes the *requested* version/scope, which identity's
  version-less coarse checks leave empty. A15 has since built the policy-store hash signal
  (the hasher, for cache invalidation), but this correlate does NOT yet consume it: wiring
  that hash into `shadowPolicyCorrelate` (the seam in `shadow.go`), so a divergence pins the
  exact store revision it was observed against, is a deferred follow-up.

  Exclusions: `AllowProjectScopeCreate`/`AllowRole` are never shadowed (see below).
  **Impersonated requests are compared too since A14**: the legacy intersection verdict
  against the AND-ed dual-check verdict — both single booleans, so the comparator needed
  no structural change (an impersonated shadow evaluation costs two PDP calls). Costs:
  shadow is an opt-in validation phase, not steady state — every dispatched check pays
  bindings resolution plus a PDP round trip **on top of** the legacy walk, and during a
  PDP outage each check additionally waits up to `--cerbos-check-timeout` before failing
  the shadow evaluation (the served verdict is unaffected either way).
- **Deny-shape parity.** Cerbos-path denials surface as the same `HTTPForbidden` form the
  legacy walk produces — call sites branch on `err == nil` and the error mapper on the
  HTTP status — with the fail-closed sentinel (`ErrPolicyDenied`,
  `ErrDecisionUnavailable`, `ErrResolutionFailed`) still visible via `errors.Is` for A7's
  comparator and A10's observability. A PDP outage is therefore a deny that callers
  cannot tell from a policy deny — deliberately — while operators can, via the decision
  records' `reason` field and the decision counter's `class` attribute (see
  [Decision observability](#decision-observability-a10)).
- **Impersonated requests dispatch like any other since A14**: in cerbos mode they are
  served by the dual check — two AND-ed single-principal evaluations, the impersonated
  principal and the acting service, over the identical resource and action — replacing
  the legacy confused-deputy ACL intersection. The equivalence rests on system-account
  ACLs being Global-only: the legacy intersection then distributes over the (monotone)
  ACL walk into `principal-verdict AND service-verdict`, with the service side inheriting
  global→org→project flow-down structurally (a global binding activates on any resource —
  asserted by the parity matrix, not assumed). Detection is the exact legacy predicate (a
  principal in context, the impersonation marker, and a non-empty actor); an invalid
  impersonated principal TYPE — System, unknown or empty — fails closed with
  `ErrImpersonationNotSupported`, mirroring the legacy `ErrInvalidPrincipalType` hard
  error rather than falling back to the legacy path.
- **`AllowProjectScopeCreate` and `AllowRole` stay legacy-only, nested checks included**:
  Create's live project-existence orchestration moves to Cerbos with A19, and `AllowRole`'s
  grantability walk stays thin-Go by design. A16 proved that safe: `TestGrantabilityCrossParity`
  (integration) shows the generated Cerbos policy grants every role — the built-in nine and the
  out-of-repo open-vocabulary shapes — exactly its declared scopes, so the thin-Go grant-guard
  and Cerbos enforcement provably agree and `AllowRole` need not dispatch to the PDP.
- **Costs, accepted until later tasks**: the middleware still resolves the legacy ACL for
  every request even in cerbos mode (the double-resolution goes with A12/A17), and
  per-item filter loops over `Allow*` become N single-check PDP calls (the localhost
  sidecar answers sub-millisecond; the A15 coarse-decision cache — below — now memoizes
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
- `Check(ctx, resource, action)` / `CheckMany(ctx, checks)` are the decision API: resolve
  bindings, build ONE batched `CheckResources` request, map per-resource `IsAllowed`.
  **Fail-closed**: every failure is a deny, with a distinct static error per failure class —
  `ErrPolicyDenied` (explicit policy deny), `ErrDecisionUnavailable` (no PDP client injected
  via `WithCerbos`, transport failure, malformed response), `ErrResolutionFailed` (missing
  authorization info, resolver or request-construction failure). Every served evaluation is
  audited and counted at the `CheckMany` choke point (see
  [Decision observability](#decision-observability-a10)).
- **Impersonated requests are the A14 dual check** (`decideImpersonated` in `check.go`): the
  impersonated side resolves from an `Info` synthesized from the propagated principal —
  mirroring the legacy claims rebuild exactly, defensive singular-organization fallback
  included — and the service side from the real context info. BOTH sides always evaluate
  (no short-circuit): two sequential PDP calls, each under the client's per-call timeout,
  each recording its own latency histogram sample; the per-entry verdict is their AND. A
  resolver or transport failure on either side maps to the ordinary fail-closed classes.
  `ErrImpersonationNotSupported` is **retained with a narrowed meaning**: only the type
  gate — an impersonated principal type that cannot be impersonated (System, unknown,
  empty) — refuses pre-PDP; it is deliberately not `ResolveBindings`' default-to-User arm,
  which would answer for the wrong principal class. **Verdict-level parity with the legacy
  intersection is the contract; two mechanism asymmetries are documented, not replicated**
  (both encoded in the parity matrix like the `UserProjectWrongOrg` precedent): an
  impersonated user scoped to a non-member organization legacy-errors
  (`ErrNotInOrganization` from the request-scoped resolution) where the dual check
  policy-denies via the request-scope-free resolver, and a System-type impersonation
  legacy-errors (`ErrInvalidPrincipalType`) where the dual check refuses with
  `ErrImpersonationNotSupported` — the same deny verdicts, different error shapes.
  **A15 cache-key obligation (delivered)**: the A15 coarse-decision cache (below) keys an
  impersonated entry on the `(impersonated-sub, actor)` pair, the impersonation flag (the
  `direct|`/`impersonated|` discriminator), and the actor's type and org set — every
  verdict-determining input of the dual check — per the design's caching clause, so an
  impersonated verdict can never be served to a direct call, nor to a different impersonated
  principal. A14's concrete deliverable for that clause is carrying the pair in every
  impersonated decision record (see below).

### Decision observability (A10)

Every PDP-SERVED Cerbos-path decision is audited and counted at the `CheckMany` choke point
(`decision_log.go`): `Check` wraps `CheckMany`, cerbos-mode `allowCoarse` wraps `Check`, and
A8's remote `/authorization/check` handler lands on `CheckMany` too (delivered — see below)
— so remote decisions inherit these records with no further work. Hooking the choke point rather than decorating
the PDP client is deliberate: the pre-PDP fail-closed denials (no client configured,
resolution failures, refused impersonated principal types) are decisions and must be
observed. **One path does not reach here: an A15 coarse-cache HIT short-circuits before
`CheckMany`, so it emits no audit record and no `decisions_total` increment (it is counted
on the separate coarse-cache hit/miss counter instead — see [the cache](#the-coarse-decision-cache-a15)).** An impersonated dual-check decision is still ONE record and ONE counter
increment per entry — never one per side — with the AND-ed outcome. Two
owner-flagged deviations from the migration plan's file table: **`decision_log` lives in
`pkg/rbac`, not `pkg/authz/cerbos`** (the plan row predates A5 placing the decision layer
here — the choke point and every record input live in this package, and the PDP client knows
nothing about subjects and stays log-free), and **the "policy version/hash" field is emitted
through the same seam the shadow comparator uses** (empty against today's PDP; A15 has built
the policy-store hash signal but wiring it into this correlate is a deferred follow-up).

**The decision log.** One record per `(resource, action)` entry of the batch — the flat,
greppable shape; a batch-wide failure denies every entry, so every entry gets a record with
the shared reason class. The message constant is `authorization decision` (load-bearing:
dashboards grep it, unit tests duplicate it so a rename breaks them). Records emit through
the request-scoped logr logger (`log.FromContext`) into the shared zap JSON stream
(`SetupLogging`); the core OTel middleware seeds that logger with the request's
traceID/spanID, so records are trace-correlated automatically — that is the design's
"correlation id", with no explicit field. Levels mirror the core logging middleware's
convention (4xx unconditional, `V(1)` otherwise): **denies at Info unconditionally, allows
at `V(1)`** — this satisfies the design's "every decision" with allows visible at raised
verbosity. Fields (closed set, credential-free — only `Sub` and `Acctype` are read from the
authorization info, NEVER tokens/passports/claims): `subject`, `actor_type`, `endpoint`,
`resource_id` (empty for coarse checks), `operation`, `organization_id`, `project_id`,
`decision` (`allow|deny`), `reason` (`policy|unavailable|resolution|impersonation`, derived
from the sentinel taxonomy via `errors.Is` — `policy` covers both verdicts, including a
dual-check deny from either side; `impersonation` is **narrowed since A14** to the type-gate
refusal only; the rest are the fail-closed classes), `policy_version`/`policy_scope` (the
A15-seam correlate, only claimed when a verdict was obtained), and `latency` (the whole
decision: resolution + PDP + mapping). Impersonated decisions carry exactly two more
fields — `impersonated_subject` and `impersonated_type`, read from the propagated
principal — the design's `(impersonated-sub, actor)` pair, while `subject` stays the
acting service (the legacy cache-key convention).

**Metrics.**

| Instrument | Type | Attributes / boundaries |
| --- | --- | --- |
| `unikorn_identity_authz_decisions_total` | `Int64Counter` | `decision=allow\|deny`, `class=policy\|unavailable\|resolution\|impersonation` — the vocabulary is CLOSED (renames are breaking; `impersonation` survives A14 with its narrowed type-gate-refusal meaning); subject/endpoint attributes would be an open-vocabulary cardinality explosion |
| `unikorn_identity_authz_pdp_latency` | `Float64Histogram` (the repo's first) | unit `s`; explicit sub-second buckets `0.0005 … 2` sized for localhost gRPC, top buckets making `--cerbos-check-timeout` expiries visible |

The counter increments at the same per-entry classification point as the log — once per
decision, never once per dual-check side. The histogram is recorded tightly around the PDP
`CheckResources` round trip only (no resolution, no mapping), success and failure alike —
an impersonated decision contributes two samples, one per side. Instruments export **only when the server runs with
`--otlp-endpoint`** (metrics are pushed over OTLP; no `/metrics` endpoint exists) — without
it the recordings are silently dropped.

**Shadow evaluations are excluded.** They ride the same `CheckMany` funnel via a marked
shallow engine copy (`shadowCompare`), and the marker suppresses their decision records and
counter increments: shadow's signal is A7's own divergence/failure records, which A12's gate
consumes. Only the PDP latency histogram is shared — transport health is path-independent.

**Shadow sink fix (with A10).** The A7 shadow records (and the deprecated-`userIDs` group
warning) previously emitted through bare `slog` — Go's default TEXT handler on stderr,
outside the zap JSON stream and without trace correlation. Both now emit through
`log.FromContext` into the same sink as the decision records (logr has no warn level; shadow
records emit at Info so they stay unconditionally visible). Message constants and field sets
are unchanged.

`make test-cerbos-decisions` (Docker-dependent, so not part of `test-unit`) runs the
decision-parity integration test: from one fixture dataset it computes every verdict through
both the legacy pipeline (`GetACL` + `Allow*`) and the Cerbos path (generated policies served
by the pinned image), and requires verdict equality across a matrix of all four actor classes,
all three scope levels, and the negative cases. A divergence there is an authorization bug in
the migration, never something to special-case. The same run exercises the shadow comparator
end to end: against the parity store the matrix must log zero divergences, and against a
deliberately-divergent store (one extra generated allow the legacy fixture lacks) exactly that
one divergence must be detected — with the legacy verdict still served on the divergent cell.
The matrix also carries open-vocabulary cells (`radar:*`/`envir:*` roles transcribed from the
real deployment repo) — the Go-side proof that parity is not an artifact of this repo's
built-in `identity:*` vocabulary — and, since A14, impersonated cells: a registered system
account impersonating the fixture user and service account, the byte-untouched legacy
`intersectACL` oracle against the dual check, covering allowed-by-both (including the
project-scope cell witnessing the service side's global→project flow-down),
denied-by-service-only (the narrowing proof), denied-by-principal-only, the wrong-org
mechanism asymmetries, and System-impersonation error parity.

### The remote decision endpoint (A8)

`POST /api/v1/authorization/check` (`pkg/handler`, `x-hidden`/`x-no-authorization` in the
spec) is how a downstream service **without** an in-process Cerbos sidecar obtains a decision:
it POSTs a batch of `(resource, action)` checks over mTLS and identity resolves bindings,
consults the PDP, and returns per-check `allowed` booleans in request order. The handler is
deliberately thin — it maps the wire body to `[]CheckRequest` (absence semantics preserved:
an omitted `organizationId`/`projectId` stays absent, never an empty string, so an org check
cannot gain a project attribute) and calls `CheckMany`. Everything else is inherited: the A14
dual check, the A10 decision records and metrics all apply with no extra plumbing, off the
same context the middleware builds for any mTLS caller.

- **Cerbos-authoritative from day one, no legacy twin.** This endpoint IS the Cerbos path
  regardless of `--authorization-engine` (that flag only selects what serves identity's own
  `Allow*` facade). It has no legacy `Allow*` equivalent to shadow-compare against, which is
  exactly why A11 dropped its dependency on A8 (nothing to feed the divergence gate).
- **mTLS-only.** The `oauth2` security scheme multiplexes bearer and mTLS onto the one route,
  so the handler's single security obligation is to reject non-system-account (bearer) callers
  (it checks `authorization.Info.SystemAccount`, set by the middleware from the verified peer
  CN); a bearer caller gets a 401. Hardening the header-strip deploy invariant and moving to
  signed-principal propagation (design §3.7 b/c) are named follow-ups, not delivered here.
- **Fail-closed crosses the wire.** A per-check policy deny is `allowed: false` at HTTP 200; a
  batch-level failure (`ErrDecisionUnavailable`/`ErrResolutionFailed`/`ErrImpersonationNotSupported`)
  is a non-200 the calling `remote` authorizer treats as a deny for every check
  (`pkg/middleware/openapi/remote` `CheckMany`). Remote decisions are indistinguishable from
  local in the decision records (the closed `class` vocabulary has no remote/local split); if
  operators ever need that split it is an A15+ attribute, documented as breaking to rename.

`make test-cerbos-remote` (Docker-dependent, not part of `test-unit`) is the deliverable's
proof: it drives the real router + middleware validator + handler + a real Cerbos-backed RBAC
through the generated typed client, asserting an allowed and a denied check for a system
caller, the dual-check verdict for an impersonated call, bearer rejection, and PDP-down
fail-closed.

### The kind-CI divergence gate (A11)

Kind CI runs the identity server in shadow mode (`hack/ci/test-values.yaml` sets
`identity.authorizationEngine: shadow`), so every fixture and API-suite request doubles as a
live legacy-vs-Cerbos comparison. After the API suite, `hack/ci/divergence-gate` reads the
server logs and **fails on any `cerbos shadow divergence` line**, while `cerbos shadow
evaluation failure` lines are tolerated but printed (infrastructure signal, per the split
above — the gate greps the two exact message constants separately, and asserts the server
container never restarted, since a restart truncates the logs and would make a pass vacuous).

What zero divergence there proves — and does not:

- **Proves:** legacy/Cerbos verdict parity for the identity-served kinds the suite exercises,
  under non-impersonated traffic. The comparator covers impersonated requests since A14,
  but the kind fixtures and API suite send no `X-Impersonate` traffic, so the gate's
  EVIDENCE remains non-impersonated until the fixtures exercise impersonation (a recorded
  follow-up); impersonated parity is proven by the docker matrix's impersonated cells.
- **Does not prove:** open-vocabulary parity (no `radar:*`/`envir:*` traffic flows through
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

### The coarse-decision cache (A15)

Cerbos-mode `Allow*` dispatch memoizes coarse verdicts so repeated identical checks (the
per-item filter loops over `Allow*`) do not re-hit the PDP. The cache lives at ONE choke
point — `allowCoarse` in `engine.go`, reached only through `engineForDispatch` (cerbos mode)
— so the shadow path (`shadowCompare`) and the remote decision endpoint (A8's `CheckMany`
handler) never touch it: shadow divergence coverage and remote decisions are uncached by
construction.

- **Key dimensions** (`decisionCacheKey`, the analog of the middleware's `aclCacheKey`):
  the calling subject, the `direct|`/`impersonated|` discriminator, the coarse scope
  (`kind|organizationID|projectID`, the no-flow-up shape preserved — org/project empty when
  absent), the action, and the **policy-store hash**. An impersonated key additionally
  carries the impersonated actor, its principal **type**, and its **sorted organization
  set** — the verdict-determining inputs the A14 dual check resolves the actor's bindings
  from (`impersonatedInfo` → `ResolveBindings`) — so two distinct impersonated principals
  that merely share an actor string cannot collide on one cached verdict. (This is stricter
  than today's `aclCacheKey`, which omits type/orgs; aligning the ACL cache is a tracked
  follow-up.) The resource ID is deliberately absent (coarse-only). The impersonation
  predicate is the SAME `impersonationFromContext` the decision path uses, so the key can
  never disagree with how `decide` treats the request (a marker without an actor is direct
  on both sides).
- **Policy-hash invalidation is the correctness core.** The hash comes from the
  controller-owned policies ConfigMap (see
  [`pkg/authz/cerbos`](../authz/cerbos/README.md#the-policy-store-hasher-a15)). A republish
  changes the store's content-addressed key set, so the hash changes, so every entry keyed
  on the previous store becomes unreachable — a revoking republish can NEVER be masked by a
  stale cached allow. Residual staleness (while the PDP itself reloads the new store, or in
  the same-hash edge case) is bounded by `--decision-cache-timeout`.
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
- **Cache hits skip the A10 decision log and `decisions_total`** (which document PDP-served
  decisions — a hit is not a new PDP decision) but are counted in a dedicated
  `unikorn_identity_authz_coarse_cache_total{outcome=hit|miss}` counter, so the cache's
  effectiveness (hit ratio) stays observable without inflating the PDP-served stream.
  Misses funnel through `CheckMany` and are logged and counted there exactly as before, and
  additionally recorded as `outcome=miss` on the coarse-cache counter. The verbose audit
  log stays miss-only by design (the authoritative decision is logged on the miss that
  populated the entry). Flags: `--decision-cache-size` (default `1<<16`) and
  `--decision-cache-timeout` (default `1m`).

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
- [`pkg/authz/cerbos`](../authz/cerbos/README.md), which provides the PDP client, policy
  generator and request builder behind the Cerbos decision path
