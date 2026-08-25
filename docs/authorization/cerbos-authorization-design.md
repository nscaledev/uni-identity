# Cerbos authorization: replacing the homegrown decision engine

- **Date:** 2026-07-09
- **Status:** Proof of concept, implemented and shadow-validated, not yet merged. Validated against Cerbos 0.53.0 and
  `cerbos-sdk-go` 0.4.0, including the policy composition, which requires a grantor-root
  pattern and surfaced an org-veto subtlety. See
  [Policy model and scope hierarchy](#33-policy-model-and-scope-hierarchy).
- **Scope:** Identity's authorization decision path. Cerbos runs centrally at identity for
  now. Distribution is designed as a per-enclave authorization unit in
  `distributed-pdp-design.md`, which supersedes the per-service sidecar shape this
  document describes. Authentication is in scope only as the seam that feeds a normalized
  principal into it. This document describes the whole program. A file it names can arrive in a
  later change of the same series.

The change is behaviour-preserving and reversible. It reproduces today's RBAC first and
validates it in shadow mode, so it can be adopted incrementally or backed out. One design
item is still open: which side supplies each attribute under impersonation. That is a
tenant-authored-rules concern and does not gate the compatible cutover. See
[Open decisions](#open-decisions).

## Problem

Authorization today is a homegrown, **pure-RBAC** engine. `RBAC.GetACL(ctx, org)`
(`pkg/rbac/rbac.go`) reads `Role`, `Group`, `Project`, `User`, `OrganizationUser`
CRDs and returns a principal's materialized `openapi.Acl` (endpoint-scopes × CRUD,
at `global`/`organization`/`project`); every service enforces *locally* against
that ACL through `github.com/unikorn-cloud/identity/pkg/rbac` (`Allow*()`).

Two structural limits:

1. **It cannot express ABAC.** The ACL is computed without the specific resource,
   so decisions can't depend on resource attributes (classification, owner, team)
   or request context (MFA/step-up, source IP, time), all near-term requirements.
2. **AuthN dispatch is hardcoded**: no registry, no single normalized-principal
   contract isolating authZ from authN.

**Goal: prove out replacing the homegrown authorization engine with Cerbos** (not
layering on top of it), so decision logic lives in a versioned, testable policy
engine (ABAC, policy-as-config, auditability); and introduce a **pluggable
authentication layer** so new credential types slot in without touching
authorization. Two clean seams, rolled out along two axes.

### Requirements gathered

| Dimension | Decision |
|---|---|
| Motivation | **All of, equal weight**: ABAC (resource/context-aware policies today's role engine can't express), policy-as-config, decoupled authN/authZ, auditability & reuse. The aim is to *remove homegrown access-decision evaluation* (the grant-guard + enumeration stay Go, §3.2); this PoC proves the ground for it. |
| ABAC | **Near-term & concrete**: step-up/MFA, source-IP/network trust, resource classification, owner/team. Requires per-request, per-resource decisions. |
| Future authN | **All of**: per-org OIDC providers, SAML, API-keys/PATs, workload identity. *Accommodate* all four; *implement* the OIDC generalization now, stub the rest ([D6](#open-decisions)). |
| Rollout | Two axes. **Deployment: central (A) now, distributed (B) reshaped as a per-enclave authorization unit** (`distributed-pdp-design.md`). **Capability: M1 compatible cutover → M2 bundled rules** (platform ABAC + tenant-authored, one engine). |

### Prior art

- The build-vs-buy **spike** validated Cerbos
  semantics (0 mistakes / 1k scenarios) and gives the reusable **Style-B mapping**:
  a single Cerbos role `principal` + **derived roles** matching flattened
  `role#org#project` **bindings** against the resource's `organization`/`project`.
  The generator produces exactly this shape from `Role` CRDs (below). Caveats it left:
  no `cerbos-sdk-go`, no native scopes, no list/batch or audit path. This note fills those.
- `docs/passport-exchange-providers.md` designs the OIDC token-exchange
  generalization; this note **subsumes and extends** it as the first verifier
  behind the authN seam.

## Constraints (platform specification)

Guardrails from the platform spec. Where a constraint is a self-imposed default
rather than a hard rule, that's called out (the team owns the spec).

- **§10.1 Single Enforcement Point**: *"all access decisions are made against
  the ACL returned by the identity service. There is no local policy evaluation in
  individual services."* → **Central Cerbos at identity satisfies this**: services
  consume decisions *from identity* (which owns Cerbos), and they never evaluate
  locally. Per-service sidecars *would* be local evaluation and need a
  specification §10.1 amendment. The per-enclave unit that replaced them
  (`distributed-pdp-design.md`) keeps consumers evaluating nothing locally, and needs
  only the narrow amendment that design states ([D5](#open-decisions)).
- **§4.3 `identity/pkg/rbac` is the consumption contract.** We keep it as the one
  library services call; its *external* API stays behaviour-compatible through M1
  (minimal downstream churn), while its *implementation* swaps from a local ACL
  check to a Cerbos decision. "As a unit" / full backward-compat are not treated as
  immutable. They're preserved by choice.
- **Group-only assignment**, **global→org→project flow-down**, **Helm CN→role
  for system accounts**, **label-based scoping**, **input-path (taint) re-check**,
  and **no cache coarser than the full authorization scope** remain invariants.
  Flow-down + grantability now live in *generated Cerbos policy* (§3.3) rather than
  Go, the genuine reimplementation risk, guarded by Cerbos's test suite + shadow
  parity.
- **Impersonation can only narrow, never expand** (§10.1 *No Privilege
  Escalation*). Mechanism: the decision point issues **two Cerbos checks** over the
  identical resource/action, one with the impersonated principal's bindings, one
  with the acting service's, and allows **iff both allow**. (A single *merged*
  principal would be a union/escalation. It must be two checks.) The service-side
  check must inherit the same global→org→project flow-down today's *asymmetric*
  `intersectACL` (`rbac.go`) relies on, or M1 shadow will diverge on system-account
  impersonation. The two-principal split lives in **identity**: remote services
  forward only one principal + a boolean `X-Impersonate` today. ABAC raises "whose
  attributes apply", [D7](#open-decisions).
- **Identity is the sole issuer of *platform* tokens and the trust root.** External
  IdPs issue upstream tokens; identity validates and **exchanges (RFC 8693) into a
  passport**, a short-lived JWS **signed ES512** (JWKS-verifiable) that carries
  the principal (its resolved **role bindings** + attributes) to the decision
  boundary. The passport is the operative service-to-service token. No downstream
  service trusts an external token directly; external claims (`orgIds`) are advisory
 , effective authority comes from identity's own state, by actor type (§3.2).

The spec is silent on external policy engines/sidecars/authz SLOs, deploying
Cerbos beside identity is architecturally normal, given the invariants above.

---

## Roadmap: two evolution axes

**Axis 1: Deployment topology:**

| | Where | Spec | Status |
|---|---|---|---|
| **A: Central** | One Cerbos owned by identity; services consume decisions via `pkg/rbac`. | §10.1 as written. | **now** |
| **B: Distributed** | Reshaped: a per-enclave identity authorization unit evaluating replicated state, not a sidecar per service (`distributed-pdp-design.md`). | needs a narrow specification §10.1 amendment ("single *policy authority*"). | **proposed**, reshaping the deferred sidecar shape ([D5](#open-decisions)). |

**Axis 2: Policy capability:**

| Milestone | What | When |
|---|---|---|
| **M1: Compatible cutover** | Cerbos reproduces today's RBAC exactly; shadow-validated; strangle by kind. Behaviour-preserving. | near-term |
| **M2: Rules capability (ABAC + tenant-authored, one engine)** | One shared catalog of condition predicates (MFA, source-IP, classification, ownership, …). **Both** platform (at **root**) **and tenants** (at **org/project**) author with it, same building blocks, same guardrails; tenants can only restrict. Built once. | near-term (tenant surface gateable) |

Near-term work = **deployment-A + M1 then M2**. B is a later rollout that the M1
interfaces are shaped not to preclude (§6).

---

## 1. Architecture and components

Two seams, each isolating one concern:

- **Seam 1: the normalized `Principal` contract** (authN ↔ everything else).
  Any credential, once verified, becomes one canonical principal. Largely exists
  today (the **passport** normalizes UNI/Auth0; `Userinfo` in-process); the new work
  is the **verifier registry** feeding it (§2) + extending its claims for ABAC.
- **Seam 2: the identity decision boundary** (authZ ↔ every service). Services
  never evaluate policy; they consume decisions via `pkg/rbac`. **Cerbos is the
  decision engine, central at identity.**

```
                              IDENTITY SERVICE
  ┌──────────────────────────────────────────────────────────────────┐
  │  authN layer (pkg/authn) — verifier registry                        │
  │    UNI · OIDC-provider(s) · SAML · API-key · workload · mTLS         │
  │                 ▼ Seam 1: NormalizedPrincipal                       │
  │         token issuance (passport, ES512, RFC 8693)                  │
  │                                                                     │
  │  pkg/rbac (the §4.3 contract, engine swapped underneath):           │
  │    Allow*()/Check()  ── decisions ──▶  Cerbos (sidecar, gRPC)       │
  │    GetACL()          ── thin Go expansion, /acl enumeration only     │
  │                                            ▲ hot-reload              │
  │  policy controller: watch Role CRDs ──▶ generated policies ─────────┘
  │                                         (ConfigMap/disk store)       │
  │   internal POST /authorization/check (mTLS, x-hidden) ◀── Seam 2 wire │
  └──────────────────────────────────────────────────────────────────┘
        ▲ decisions (batched per request; coarse cached)
   ┌────┴───────────────────────────────────┐
   │  Region / Compute / Kubernetes svc       │  consume via pkg/rbac only;
   │  handlers call rbac.Allow*() / Check()   │  never talk to Cerbos directly
   └──────────────────────────────────────────┘
```

**Packages that change or appear:**

| Package | Change | Responsibility |
|---|---|---|
| `pkg/authn` *(new; separate workstream)* | extract + generalize | `CredentialVerifier` registry; dispatch by credential type; build `NormalizedPrincipal`. Existing UNI/Auth0/mTLS verification moves behind it. Delivered separately as its own workstream (see §2). |
| `pkg/authz/cerbos` *(new)* | new | `cerbos-sdk-go` gRPC client to the local sidecar; build principal (role **bindings** + attrs) / resource / action; single + **batch** decisions; **fail-closed** (decision logging + metrics live in `pkg/rbac`, at the `CheckMany` choke point). |
| `pkg/authz/cerbos` **controller** *(new)* | new | **Reconciling controller**: watch `Role` CRDs (GitOps *and* manually applied) → generate Cerbos derived-roles + resource policies + scope hierarchy → write to a **ConfigMap/disk store the sidecar hot-reloads**. No DB, no Admin API in M1. |
| `pkg/rbac` *(changed; §4.3 API preserved)* | engine swap | `Allow*()`/`Check()` keep their signatures but now **delegate to Cerbos** (via identity's decision path) instead of checking a local ACL. `GetACL` **kept as a thin Go expansion** for the `/acl` enumeration + grantability only (not for decisions). |
| `pkg/middleware/openapi` (`local`+`remote`) | additive | `local` calls the in-process Cerbos client; `remote` calls identity's `/authorization/check`. Batches a request's checks. |
| identity server | new endpoint | Internal `POST /authorization/check` (mTLS, `x-hidden`), the Seam-2 wire API. |
| `charts/identity` | add | Cerbos **sidecar** + the generated-policy ConfigMap/volume + config. Single central PDP (localhost). |
| `pkg/authz/cerbos/generate/testdata/store/` *(generated golden store + hand-authored compile tests)* | new | Cerbos derived-roles + per-resource policies the generator emits from `Role` CRDs, checked in as golden fixtures and compiled by `make validate-policies`. The **runtime** store is not committed here, the reconciliation controller regenerates it from live `Role` CRDs into the ConfigMap the sidecar mounts. (Platform ABAC / guardrail policies: deferred to M2.) |

**Confirmed constraints (Cerbos 0.53.0):** there is **no in-process Go embedding**: the Go SDK is a remote client, so identity talks to Cerbos as a **sidecar over
gRPC** (the WASM "embedded PDP" is JavaScript-only + needs Hub). Everything below
respects that.

---

## 2. The authentication layer (seam 1)

The authN verifier registry is a separate workstream, designed here and shipped
independently of the Cerbos work.

Replace the hardcoded dispatch with a **verifier registry**. Each method
implements one interface and normalizes to one principal shape. That shape is
**not greenfield**: the **passport** already normalizes UNI/Auth0 and `Userinfo`
carries it in-process; we *formalize and extend* those (add `Source`,
infra-populated `Attrs`), and the genuinely new piece is the **registry**.

```go
// pkg/authn — illustrative, not final.
type Credential struct { Scheme string; Raw []byte; Peek map[string]string }

type CredentialVerifier interface {
    CanVerify(c Credential) bool
    Verify(ctx context.Context, c Credential) (*NormalizedPrincipal, error)
}

type NormalizedPrincipal struct {
    Subject  string; Type AccountType; Source string
    OrgIDs   []string        // advisory from IdP; authoritative set from userdb
    Verified bool
    Attrs    map[string]any  // MFA, amr, sourceIP, auth_time, ...
}
```

Dispatch *becomes* credential-type-based (`iss` peek for OIDC, scheme for API keys,
cert for mTLS), **replacing** today's *two* hardcoded sites: the JOSE-shape
router (`JWE→UNI` / `JWS→a single flag-configured Auth0 validator`) in
`passport.go` (`dispatchUserinfo`), and the separate mTLS branch in
`middleware/openapi`. (There is no `iss`-peek today. That's the target, not the
current mechanism.) Every verifier normalizes to `NormalizedPrincipal`, which is
what identity mints the passport from and, after identity resolves memberships to
**role bindings**: what authZ consumes. Identity stays the sole platform-token
issuer; org membership is resolved from `userdb` for users (a service account
carries a single owning org; a system account none, §3.2).

| Method | Verifier sketch | Normalizes to |
|---|---|---|
| Per-org OIDC | **Reuse** the generic `pkg/oauth2/oidc` verifier (today wired only to login) on the passport path; replace the bespoke `pkg/oauth2/auth0` exchange validator; `iss`-dispatch against `OAuth2Provider` CRDs (new `tokenExchange` block). *(Reuse, not rewrite.)* | `Type=user`, `Source=<provider>` |
| Enterprise SAML | assertion-consumer flow; validate signed assertion. | `Type=user` |
| API keys / PATs | hashed-key lookup → owner; exchange to short-lived token. | `Type=user\|service` |
| Workload identity | verify SPIFFE SVID / cloud-IAM JWT. | `Type=service\|system` |

**[D6: confirmed]** Build the registry + normalized principal now, migrate
UNI/OIDC/mTLS behind it, implement the OIDC generalization; **stub**
SAML/API-keys/workload until prioritized.

---

## 3. Authorization: Cerbos integration and policy model (seam 2)

### 3.1 Deployment (central, M1)

- **One Cerbos sidecar** in the identity `Deployment` (localhost gRPC), **v0.53.0**,
  via `cerbos-sdk-go` (v0.4.0) wrapped in `pkg/authz/cerbos`.
- **Policy delivery:** the controller writes generated policies to a **ConfigMap /
  mounted volume the sidecar hot-reloads** (`watchForChanges`). **No mutable DB, no
  Admin API, no Hub in M1**, those are only needed for runtime *tenant* authoring
  (M2). Distribution needs none of them either, because each enclave generates its store
  locally from replicated state (`distributed-pdp-design.md`). This keeps M1's
  footprint to "identity + a sidecar + a controller."
  - *Reload gap (verified during implementation, design-impacting):* plain
    `watchForChanges` does **not** see content-only ConfigMap updates, the
    kubelet swaps a hidden `..data` symlink (`atomic_writer.go`) and Cerbos's
    dirwatch drops hidden-name events and only reloads the exact visible paths in an
    event batch (cerbos@v0.53.0 `internal/storage/disk/dirwatch.go`), so a same-key
    content update never reloads. *Resolution:* the controller publishes every file
    under a **content-hash-suffixed key** (`<base>-<sha256[:8]>.yaml`): changed
    content swaps keys, which surfaces as visible delete+create events the watcher
    does reload (deletes processed first, no duplicate-definition window);
    unchanged files keep identical keys. See `pkg/authz/cerbos/README.md`.
- **Policy-delivery trust:** the ConfigMap/volume the sidecar reads *is* the
  effective authorization policy, least privilege applies. Only the controller's
  ServiceAccount may write it; identity/sidecar mount it read-only. The controller
  MUST `cerbos compile` (test-suite pass) each generated bundle and **refuse to
  publish on failure**, keep last-good and alarm, never fail-open on a broken or
  well-formed-but-hostile bundle. *(The controller ships this: exec'd pinned-binary
  gate, refusal keeps last-good + warning event + classified error log; published
  keys embed content hashes and publishes are logged. Richer provenance/audit
  records ride with the decision-observability work.)*
- **Deployment hardening (from the deployment review), deferred decisions:**
  - *Policies-ConfigMap ownership.* ✅ **RESOLVED: controller-owned outright; the
    chart no longer templates the ConfigMap.** The sidecar mounts it as an
    `optional` volume (deny-by-default until first publish; the kubelet back-fills
    the volume once it appears), and a wiped/pruned ConfigMap is self-healing. The next reconcile re-gates and recreates it from the Roles. `helm uninstall`
    orphans it (labels, no ownerReferences/GC).
  - *CPU sizing:* the sidecar sits on the synchronous auth hot path; size its
    resources with load data during the decision-layer and strangle-by-kind cutover.
  - *Native sidecar* (initContainer + `restartPolicy: Always`) fixes termination
    ordering but requires k8s ≥ 1.29, a strangle-by-kind cutover question.
  - *Image digest pinning* is a platform-wide supply-chain convention question,
    not a one-image fix.
- **Enforcement path:** services call `pkg/rbac`; for other services `remote` calls
  identity's `/authorization/check`; identity dials the local Cerbos. A request's
  checks are **batched** (≈one call per request, like today's one ACL fetch);
  coarse (context-free) decisions are cacheable per authorization scope, ABAC
  decisions are per-request.

### 3.2 Cerbos is the authorization engine

**The decision logic moves to Cerbos; role *definitions* are generated into Cerbos
policy from `Role` CRDs; identity keeps only membership resolution + two read-only
helpers.**

- **Role definitions → generated Cerbos policy.** A reconciling **controller**
  watches `Role` CRDs (from *any* source, identity chart, deploy
  `additionalRoles`, `ai-services.yaml`, or manually applied) and generates: one
  **derived role per role** whose condition matches the principal's scoped
  **bindings** (`"administrator#" + R.attr.organization in P.attr.bindings`), plus
  **resource policies** granting that derived role the role's actions at the
  **grantor (root) scope** (M1); tenant/platform overlays layer on at org/project
  scopes in M2 (§3.3). This is the spike's Style-B, *generated*, so new
  services/roles (any out-of-repo service, future) need **zero hand-authoring**, and
  manually-applied `Role` CRs are picked up at runtime like today's informer.
- **Identity resolves memberships → bindings (data), Cerbos maps bindings →
  permissions (policy).** Actor-aware: a **user** derives bindings from groups
  across their orgs; a **service account** from groups in its single owning org
  (`oid`); a **system account** from the Helm CN→role map. Identity passes
  `principal.roles: ["principal"]` + `principal.attr.bindings` + ABAC attrs;
  Cerbos decides.
- **Enforcement moves to Cerbos.** `pkg/rbac.Allow*()`/`Check()` stay the facade
  (§4.3, minimal churn) but can delegate to Cerbos. The local ACL walk, the Go
  scope-flow-down, and the role→permission expansion *for decisions* are retained
  during migration (shadow → per-kind strangle → cutover, §4.2) and removed
  only once every kind is cut over.
- **Two thin Go helpers stay** (read-only, not the decision engine):
  - **`/acl` enumeration**: the coarse "what can I do" list the UI/sidebar needs.
    A point-check engine can't enumerate cheaply, and PlanResources is per-kind
    (a sidebar spanning ~40 features → ~40 calls + fuzzy `KIND_CONDITIONAL`
    results). The thin Go expansion produces the whole coarse matrix in one shot. It is the right tool for enumeration ([D2](#open-decisions)).
  - **Grantability** (`AllowRole`), "you may only grant roles whose permissions
    you hold" compares the *target* role's `Role` CRD scopes against the **caller's
    materialized ACL** (the retained `GetACL` Go expansion, via `FromContext`), not CRD-vs-CRD. So `GetACL` is **security-load-bearing** (it gates role grants).
    Preserve `allowGrantProjectScope`'s "any accessible project" assumption and its
    guard invariants (`handler.go`) when those scopes are generated into Cerbos.

  Enforcement (Cerbos) and grantability (Go `GetACL`) are therefore **two expanders
  over the same `Role` CRDs**. They must be proven equivalent, an M1 cross-parity
  task asserts the Go expansion and the generated Cerbos policy agree (or
  grantability moves to a Cerbos check). Do **not** assume "no drift".

*Honest framing:* what moves to Cerbos is the **access-decision engine** (what
grants/denies a request). What remains in Go, and stays **security-load-bearing**, is membership resolution, the `/acl` enumeration, and the grantability guard
(`GetACL`). So this removes *homegrown access-decision evaluation*, not every line
of authz-adjacent Go.

### 3.3 Policy model and scope hierarchy

- **Resource kinds** = platform resources; **actions** = the endpoint-scope verbs
  (`region:networks:v2:create`, …). Actions are **native Cerbos actions**, and rules are keyed by `actions:` (wildcards supported). This matters because **a CEL
  `condition` cannot reference the current action** (verified), so per-action
  logic is partitioned across action-keyed rules, which the generator emits.
- **Tenant *identity* is data, not scopes**, resources carry
  `attr.organization`/`attr.project`; derived-role conditions match the principal's
  bindings. We do **not** encode tenant IDs as Cerbos scopes.
- **Native scoped policies for the tier/overlay hierarchy**
  (`root → org → project`). In **M1** the generator emits the **root (`""`)
  grantor policies** (the RBAC ceiling); the **org/project CONSENT overlay scopes
  arrive with M2**. Wherever scopes exist, the chain must have **no gaps** and a
  root policy must exist (composition spike).
- **Restrict-never-escalate for tenant overlays**: two mechanisms, **verified on
  0.53.0 incl. the composition (the composition spike):**
  - `scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS`, a
    scope may **DENY unilaterally** (an explicit DENY anywhere in the chain wins),
    but an ALLOW is definitive only if **≥1 ancestor also allows *and* no scope
    denies**, intermediate **silence is permissive** (project allows, org silent,
    root allows → ALLOW). A grant **no** ancestor permits is denied (can't exceed
    the ceiling). *(This corrects an earlier reading of "every ancestor must
    allow.")*
  - `rolePolicy`, a per-role exhaustive allow-list, strict subset of the
    resource-policy baseline. Complementary per-role narrowing.
- **Composition VERIFIED by the composition spike, with a mandatory
  *grantor-root* pattern.** Generated per-role `derivedRoles` (binding-match) *do*
  compose across a native `root→org→project` scope chain:
  `effectiveDerivedRoles` resolves at every scope and a wrong-org binding is denied
  everywhere (tenant isolation holds). **But a consent-mode policy cannot
  *originate* a grant**, an all-consent chain denies everything (even a plain
  root allow returns DENY). So the **top of the chain must be a grantor**
  (`OVERRIDE_PARENT`, or grants via a role policy) that sets the ceiling;
  descendants consent-*narrow*. The generator MUST emit an OVERRIDE grantor at the
  top and CONSENT below, **never all-consent**.
- **Org-level restriction is a design decision, not syntax (composition-spike
  finding).** Because consent is satisfied by *any one* ancestor, a **permissive
  root undermines an org-level veto**, a *silent* org does not withhold consent
  once root has granted. A real org-level limit must be an **explicit DENY**
  at/above the org (or the org must be the grantor of org-and-below, or use
  per-scope role policies). Narrowing is expressed as explicit denies/conditions,
  **never by omission**.
- **Two structural constraints (from the composition spike).** `scopePermissions` is
  a property of the *scope string* (shared across resources), consent and
  override chains **cannot share a scope** (separate stores); and **every scoped
  resource needs a root (`""`) policy** (the generator emits one per resource).
- **Performance note (verified):** membership tests should use a **map** (`in` on a
  map key is O(1)) not a list (O(n)); Cerbos runs Go CEL, prefer maps on the hot
  path and benchmark.

### 3.4 The `pkg/rbac` enforcement API

```go
// pkg/rbac — the enforcement facade; the engine now delegates to Cerbos.
func (r *RBAC) Check(ctx context.Context, resource Resource, action openapi.AclOperation) error
func (r *RBAC) CheckMany(ctx context.Context, checks []CheckRequest) ([]bool, error)

type Resource struct { Kind, ID, OrganizationID, ProjectID string } // scope is explicit; ABAC attrs deferred to M2
type CheckRequest struct { Resource Resource; Action openapi.AclOperation } // per-resource action
```

- `Allow*(endpoint, op, scope)` → a **coarse** Cerbos decision (no resource
  instance; cacheable per scope). `Check(resource, action)` → a **per-resource**
  decision (ABAC attributes deferred to M2); coincides with the spec's input-path
  taint re-check. Both route to Cerbos (via identity in `remote`); **no service
  evaluates policy locally**.
- **`GetACL()` is retained only for the `/acl` enumeration** (thin Go, §3.2), not
  for enforcement.

### 3.5 The bundled rules capability (M2)

M2 builds **one** rule-authoring engine for both platform and tenant authors: the same mechanism at a different scope. Rests on four pieces laid down in M1:

- the **scope hierarchy** (root/org/project);
- **platform guardrail gates**: the **root is the OVERRIDE grantor** (sets the
  ceiling); org/project overlays use `REQUIRE_PARENTAL_CONSENT` and narrow via
  **explicit denies/conditions** (a *silent* scope does not restrict, a composition-spike finding), so an org-level limit is an explicit deny at/above the
  org;
- a **bounded building-block vocabulary**: kinds, actions, attributes, and a
  fixed catalog of **condition predicates** (require-MFA, source-IP-in-CIDR,
  classification, owner/team, time-window, …) **shared by platform and tenant
  authors alike**, no raw CEL exposed, every attribute infra-populated from a
  trusted source (§3.6);
- the **non-escalation model** (authored rules only *restrict*, never exceed the
  grant ceiling or the platform baseline).

**MFA/IP/classification/ownership are not platform-only.** A **tenant** can require
MFA or a source-IP range for *their* resources, drawing from the same catalog at
their org/project scope (adding restrictions only). Platform ABAC is simply that
same engine authored at **root** scope: so it builds **no throwaway machinery**,
and tenant authoring is the identical mechanism at a narrower scope. (Provenance
holds either way: the tenant writes the *predicate*; infra supplies the MFA/IP
*fact*, §3.6.)

**Two write cadences.** Base policy (role rules + platform ABAC + scope hierarchy)
is **deploy-time**, generated + hot-reloaded. Tenant overlays are **runtime**,
authored via API. Runtime authoring needs a mutable store (Cerbos DB/`sqlite` store
+ Admin API) *or* Hub, so the **DB/Admin-API surface only appears at M2**, not
M1. The M2 authoring pipeline: **(1)** bounded authoring API → **(2)** compile to
scoped Cerbos policies → **(3)** write to the mutable store → **(4)**
author-time validation (non-escalation, trusted attrs) → **(5)**
versioning/rollback.

**Open M2 questions (captured):** tenant author scope (org vs project admins);
restrict-only vs bounded self-grants; authoring surface shape; whether the
tenant-facing surface ships in M2 or is gated.

### 3.6 Attribute provenance: tenants author predicates, infrastructure populates facts

Handing ABAC to tenants is safe only because authoring a rule and supplying the
facts it runs against are **separate powers**. An author writes the **predicate**
(*which* attribute, *what* value); the runtime **fact** is populated by trusted
infra. *Example:* a tenant writes "allow only if `sourceIp ∈ 10.1.0.0/16`", but
the actual `sourceIp` comes from **our infra**, so a caller can't claim to be
inside the range.

| Attribute class | Examples | Populated by (never the caller) |
|---|---|---|
| Network / connection | source IP, mTLS peer, time | ingress / PEP, from the real connection |
| Auth context | MFA/`amr`, `auth_time`, verified subject | the verified passport |
| Resource | classification, owner, team, env | the owning service's store (taint re-check) |
| Principal | bindings, org/project | identity's membership resolution, in the passport |

The building-block vocabulary is exactly the set of trustworthily-populatable
attributes; the PEP assembles `principal.attr`/`resource.attr` from these only
(the spec's header-stripping + taint invariants, applied to ABAC). Ties to
[D7](#open-decisions) under impersonation: each fact is still infra-populated for
the relevant principal, never caller-injected.

**Source-IP provenance (proxied topology).** identity/ingress sees the *proxy* IP,
so the client IP MUST be recovered from a **configured trusted-proxy CIDR allow-list
with a fixed hop count** (right-most-untrusted `X-Forwarded-For`); a client-settable
`X-Forwarded-For` is discarded. A source-IP predicate is only as trustworthy as this
config, name the authoritative component and pin it before the M2 source-IP
predicate ships.

**Auth-context facts are IdP-trust-bounded.** `amr`/`auth_time` originate in the
upstream IdP's token, so they're trustworthy only to the extent that IdP is trusted.
For a tenant-controlled per-org OIDC provider (D6), treat IdP-asserted MFA as
*advisory* (as we already treat `orgIds`); a step-up predicate that must be strong
should rely on step-up identity establishes at its own boundary.

### 3.7 Trust boundary of the decision endpoint

`/authorization/check` (and the principal-propagation path generally) is the trust
seam: it carries the principal's **bindings** and the **impersonation flag**, which
Cerbos then trusts verbatim. Today the fast path base64-decodes `X-Principal` and
reads `X-Impersonate: true` with **no signature check** (`pkg/middleware/openapi`
`extractPrincipal`), and identity's ingress strips **no** headers, so the entire
safety argument currently rests on an *uncodified* assumption that mTLS terminates
only at identity. That is an unbounded privilege-escalation surface if any hop
terminates mTLS or ingress config drifts. **M1 MUST harden it:**

- **Header-stripping becomes a hard, tested deploy invariant.** Enumerate the exact
  stripped set (`X-Principal`, `X-Impersonate`, `Ssl-Client-Cert`, …) with a
  chart-level assertion/test; a forged header over a non-mTLS/untrusted hop MUST be
  rejected (negative test).
- **Prefer signed-principal propagation** (the existing `VerifyAndDecode`/JWS path)
  over bare base64-JSON, so trust does not rest on ingress alone.
- **`/authorization/check` re-derives the acting service identity from the verified
  mTLS peer CN** and never trusts a self-declared subject or impersonation flag.

---

## 4. Data flow and migration

### 4.1 Request flow (downstream service, ABAC-gated resource)

1. Middleware verifies the credential → `NormalizedPrincipal` (or exchanges the
   bearer at identity → passport with resolved bindings).
2. Handler calls `rbac.Allow*()` for the coarse endpoint/scope gate → a Cerbos
   decision (cacheable; batched with other checks this request).
3. Handler fetches the target resource, derives org/project from labels (taint),
   and for ABAC-gated kinds calls `rbac.Check(resource, action)`.
4. `remote` POSTs the subject credential (the acting service's mTLS client cert,
   ingress-verified; no bearer forwarded, the endpoint is system-account-only) +
   the `X-Principal`/`X-Impersonate` principal headers + the batch of
   `(resource, action)` checks to identity `POST /api/v1/authorization/check`;
   **identity resolves the bindings** from the acting service's CN (and, when
   impersonating, the propagated principal) and its own k8s membership state, the
   wire does NOT carry bindings, and passports do not either, then Cerbos →
   per-check decision; identity logs it. (As implemented: `pkg/handler`
   `PostApiV1AuthorizationCheck` + `pkg/middleware/openapi/remote` `CheckMany`.)
5. Handler proceeds or returns 403 **before** any side effect.

**List endpoints:** pre-authorize scope, push org/project filters to storage, fetch
the page, `CheckMany()` the batch, return only allowed records (200 + server-side
filtering).

### 4.2 Migration: shadow first, strangle by kind

1. **Shadow (M1).** Stand up Cerbos + the controller-generated policies. On each
   decision evaluate **both** the legacy `Allow*` path and Cerbos, **serve legacy**,
   and log divergence. Cerbos must reproduce today's decisions before any ABAC.
2. **Strangle by kind.** Once divergence is zero for a kind, flip that
   `(kind, action)` set to authoritative Cerbos and enable its ABAC (M2). One kind
   at a time; per-kind revert flag.
3. **Cutover & cleanup.** Remove the legacy decision paths; keep the thin
   `GetACL`/grantability helpers.
4. **Rollback.** Per-kind flag to legacy; the shadow comparator stays until proven.

---

## 5. Error handling, operations and testing

- **Fail-closed.** Cerbos unavailable/timeout/malformed → deny (never fail open).
- **Latency.** Localhost gRPC is sub-ms; set a `Check()` timeout, surface in
  metrics. Batch a request's checks (≈one call/request).
- **Availability / blast radius.** Central Cerbos + fail-closed means an
  identity/Cerbos outage fails *every* in-flight ABAC-gated request platform-wide,
  and each downstream ABAC check adds a cross-service
  `service → identity → Cerbos` hop (the sub-ms figure is identity↔Cerbos
  only). Coarse-decision caching bounds the blast radius to ABAC-gated paths (coarse
  RBAC still serves from cache during a blip, as today's ACL does). This interim
  central SPOF is an **accepted M1 risk**. The per-enclave authorization unit
  (`distributed-pdp-design.md`) is the structural fix.
- **Caching.** Coarse (context-free) decisions may be cached; ABAC decisions are
  per-request (uncacheable). Every coarse-decision cache key MUST include: principal
  subject, the **impersonation flag + acting-service actor** (the full
  `(impersonated-sub, actor)` pair, preserving today's `direct|`/`impersonated|`
  discriminator in `openapi.go`, without which a mis-keyed hit is a wrongful
  *ALLOW*), the org/project scope, **and the published policy hash**. Because the
  controller hot-reloads policy, the cache MUST be busted/re-keyed on policy-hash
  change (bounding the stale-allow window). Never cache coarser than the full
  authorization scope (§10.1).
- **Decision logs.** Every decision: correlation id, subject, actor/source, action,
  resource, org/project, decision, reason, **policy version/hash**, latency.
  **Never** log tokens/passports. Emitted to a shared audit sink.
- **Testing:** **Cerbos policy test suite** (`_test.yaml` fixtures; `cerbos compile`
  fails the build on exit 3/4; JUnit output) as the consistency gate, directly
  targeting the role-consistency/grantability bug class. Go unit tests for
  `pkg/authz/cerbos` (incl. fail-closed, batch). (`pkg/authn` unit tests belong to
  Plan B.) Kind integration tests extend the RBAC matrix
  (`test/api/suites/rbac_matrix_test.go`) with ABAC dimensions; BDD, typed client,
  response-body asserts incl. filtered lists; Cerbos added to `hack/ci`.
  **Shadow-divergence CI gate** before any kind flips.

---

## 6. Distributed deployment: the proposed reshape

**`distributed-pdp-design.md` proposes reshaping B. That design is not yet approved.**
Under it B is no longer deferred, and no longer a Cerbos sidecar per service. It becomes a
per-enclave identity authorization unit that evaluates centrally-authored policy against
enclave-local replicated state. Read that design for the topology, the trust argument and the rollout.
M1 still carries the properties that make distribution an operations and governance
rollout rather than a redesign:

- **`pkg/rbac` is the stable contract**: distribution changes only its implementation. A
  consumer re-points its check endpoint at its own enclave.
- **Policies are generated and owned at identity**: each enclave runs the same controller
  against replicated `Role` CRDs and generates the store locally. Generation is
  compilation, not authoring, so policy is still written once, centrally.
- **Decision logs target a shared sink per enclave**, with the global rollup owned
  by the aggregation plane.

What remains is the narrow specification §10.1
amendment, which replaces the implicit "single instance" with "single *policy authority*"
([D5](#open-decisions)).

---

## Open decisions

- **D1: Authz engine. ✅ RESOLVED.** Cerbos *is* the authorization
  engine; role definitions are generated into Cerbos policy from `Role` CRDs by a
  reconciling controller; homegrown decision logic removed. See
  [§3.2](#32-cerbos-is-the-authorization-engine). *(Composition **verified**
  by the composition spike, with a mandatory grantor-root pattern and an org-veto
  subtlety; see §3.3.)*
- **D2: `/acl` endpoint. ✅ Settled, thin Go expansion.** Kept as a
  coarse-RBAC enumeration for the UI/sidebar (spans many features in one call);
  PlanResources is per-kind and not a fit. Not used for decisions.
- **D3: Enforcement path. ✅ Settled.** `Allow*()`/`Check()` keep their
  signatures but delegate to Cerbos; batched per request; coarse cacheable. No local
  eval.
- **D4, Policy delivery. ✅ Settled for M1 → ConfigMap/disk hot-reload from
  the controller** (no DB/Admin-API/Hub). Runtime mutable store (DB/Admin-API)
  appears only for M2 tenant authoring. Distribution needs neither, because each enclave
  generates its store locally (`distributed-pdp-design.md`).
- **D5, Platform specification amendment. ⏳ Open.** `distributed-pdp-design.md`
  proposes the answer: distribution as a per-enclave authorization unit that generates
  policy locally, so no per-service distribution mechanism is needed. That design is not
  yet approved. Either way a narrow specification §10.1 amendment is required, which is an
  external dependency on `nscaledev/uni-specifications`. Not needed for the central
  compatible cutover.
- **D6: AuthN rollout. ✅ Confirmed.** Registry + OIDC generalization now; stub
  SAML/API-keys/workload.
- **D7: Attributes under impersonation. ⏳ Open (M2).** Which side supplies each
  attribute (request context = acting service; identity attrs = impersonated
  principal). Does not gate M1; impersonation itself is handled as intersection of
  decisions (Constraints).
- **M2 bundling. ✅ Settled.** Platform ABAC + tenant rules are one engine, see
  [§3.5](#35-the-bundled-rules-capability-m2).

## Non-goals (near-term)

- **Per-service sidecars, Hub, mutable DB store**: not part of the near-term work. The
  sidecar shape is superseded by the per-enclave unit in
  `distributed-pdp-design.md`, which needs neither Hub nor a mutable store. The
  mutable store belongs to M2 tenant authoring.
- **Full SAML / API-key / workload-identity implementations**: seam + stubs only.
- **Moving role *definitions* out of `Role` CRDs**. They stay the source of
  truth; the controller *generates* Cerbos policy from them.

---

## Future extensions (out of scope now; designed-for)

### Direct role / rule assignment to an individual identity

Today roles reach a principal only via `Group.RoleIDs`. Attaching roles/rules
**directly** later is cheap: identity's membership resolution is already
multi-source (groups for users/SAs, Helm CN→role for system accounts), so direct
assignment is another branch; and the controller/Cerbos are unaffected (they see
`Role` CRDs and resolved bindings). Steps: a `RoleBinding` CR
`(subject, roleID, scope)`; union it in binding resolution; extend grantability;
amend specification §4.3. **Direct *rules* on an identity** map onto Cerbos **principal
policies**, a native per-principal feature, riding the M2 machinery.
Trade-off: direct assignment trades the single auditable "who has what" place for
flexibility.
