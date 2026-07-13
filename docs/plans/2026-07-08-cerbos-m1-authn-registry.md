# Cerbos Authorization Migration — M1 Implementation Plan

> **Scope:** the near-term (M1) work from the approved design
> (`docs/cerbos-authorization-migration-design.md` — **D1b, central**). Two
> independent subsystems → **Plan A (Cerbos M1)** and **Plan B (authN registry)**;
> each produces working, testable software on its own and can be executed in
> parallel. Tasks are right-sized units, each ending in an **independently
> testable deliverable**. Bite-sized TDD steps (write-failing-test → run → implement
> → run → commit) are expanded per task at execution time, grounded in the real
> file being touched — see [Execution](#execution).

**Global constraints** (from `CLAUDE.md`, apply to every task):
- Pre-push must pass: `make touch && make license && make validate && make lint && make generate && [[ -z $(git status --porcelain) ]] && make test-unit`.
- Tests follow `test/api` BDD (`Describe > Context > Describe > It`), typed client, response-body assertions, `test/api.Endpoints`, `DeferCleanup`. Integration `//go:build integration`; e2e `//go:build e2e`.
- Cerbos pinned **v0.53.0**; `github.com/cerbos/cerbos-sdk-go` **v0.4.0** (remote gRPC client — no in-process embedding).
- Do **not** move role definitions out of `Role` CRDs; do **not** add a DB/Admin-API/Hub (those are M2/B). Central single Cerbos only.

**Out of scope (M1):** M2 tenant-authored rules + ABAC condition catalog; deployment-B sidecars, §10.1 amendment, Hub/fleet distribution; SAML / API-key / workload verifiers (stubs only).

---

## Plan A — Cerbos M1 (compatible cutover, central)

**Goal:** Cerbos is the authorization engine, deployed as a central sidecar at
identity, **reproducing today's RBAC decisions exactly** (shadow-validated, then
strangled by kind). Role definitions are **generated** into Cerbos policy from
`Role` CRDs by a reconciling controller; `pkg/rbac.Allow*()/Check()` delegate to
Cerbos; `GetACL`/`/acl` stays as a thin Go enumeration.

The full decision pipeline is live end-to-end: `Role` CR → generated policy (A2) →
compile-gated publish to a controller-owned ConfigMap (A3) → PDP sidecar (A1) →
request builder (A4) + `Check`/`CheckMany` (A5) behind the dual-path `Allow*` facade
(A6), shadowed against legacy (A7) with decision logging + metrics (A10),
impersonation dual-check (A14), a kind CI shadow-divergence gate + docker parity
matrix (A11), and a remote decision endpoint for downstream services (A8). The
shadow signal is scope-complete (impersonation included), and the thin-Go
grant-guard (`AllowRole`) is cross-checked against Cerbos for every role,
built-in and open-vocabulary (A16).

### File structure

| File | Create/Modify | Responsibility |
|---|---|---|
| `pkg/authz/cerbos/client.go` | Create | `cerbos-sdk-go` gRPC client to the localhost sidecar; `CheckResources`; timeouts; **fail-closed**. |
| `pkg/authz/cerbos/request.go` | Create | Build the Cerbos principal (`roles:["principal"]` + `attr.bindings` + attrs) / resource / action from identity's resolved principal. |
| `pkg/authz/cerbos/decision_log.go` | Create | Structured decision log (correlation id, subject, action, resource, decision, reason, policy hash, latency); never logs tokens. |
| `pkg/authz/cerbos/generate/generate.go` | Create | **Pure fn**: `Role` CRD scopes → Cerbos derived-roles + resource policies + `root→org→project` scope chain. |
| `pkg/authz/cerbos/controller/controller.go` | Create | Reconciling controller: watch `Role` CRDs → run generator → write policies to the ConfigMap/volume the sidecar hot-reloads. |
| `policies/` | Create | Hand-authored base (scope-hierarchy skeleton, platform guardrail placeholder), generated-output layout, and the Cerbos **policy test suite** (`*_test.yaml`). |
| `pkg/rbac/rbac.go`, `handler.go` | Modify | `Allow*()` → coarse Cerbos decision (cached); `Check()`/`CheckMany()` added; `GetACL` retained thin (for `/acl` + grantability); role-expansion-for-decisions removed at cutover. |
| `pkg/rbac/shadow.go` | Create | Dual-run comparator: legacy `Allow*` + Cerbos, serve legacy, log divergence. |
| `pkg/middleware/openapi/{local,remote}/authorizer.go` | Modify | `local` → in-process Cerbos client; `remote` → identity `/authorization/check`; **batch** a request's checks. |
| `pkg/openapi/server.spec.yaml` + `pkg/handler/handler.go` | Modify | Internal `POST /authorization/check` (`x-hidden`, mTLS). |
| `charts/identity/templates/*`, `values.yaml` | Modify | Cerbos sidecar container; generated-policy volume/ConfigMap; controller; config/flags (shadow, per-kind cutover). |
| `hack/ci/*` | Modify | Install Cerbos (idempotent/composable); mount policies. |
| `test/api/suites/rbac_matrix_test.go` (+ new) | Modify/Create | Parity matrix (Cerbos == legacy); shadow-divergence gate; per-kind cutover + rollback. |

### Tasks — the tracker (definitions, status, and commits in one table)

**15 of 17 tasks landed on `cerbos-integration`; 2 remaining (A12, A17) + 3 follow-ups (A18 hardening slice in the working tree — pending commit; A19; A23).** _(updated 2026-07-13)_

Ordered A1–A23; each task ends in an independently testable deliverable. Bite-sized
TDD steps are expanded per task at execution time — see [Execution](#execution).
Status: ✅ committed = landed in this repo at the anchor commit; ✅ done = complete
out-of-repo; 🔲 todo = open (blocker/dependency in the same column).

| Task | Status      | Commit / blocker | Definition — Deliverable · Test · Depends |
|---|-------------|---|---|
| **A1 — Cerbos sidecar + client + config** | ✅ committed | `873bb2ad` | Add the Cerbos sidecar to `charts/identity` (localhost gRPC, v0.53.0); scaffold `pkg/authz/cerbos/client.go` (connect, health, timeout, **fail-closed on unavailable**); wire config/flags.<br>**Deliverable:** identity boots with the sidecar; a trivial `CheckResources` round-trips.<br>**Test:** integration test hits the sidecar with a hand-written allow/deny policy.<br>**Depends:** — |
| **A2 — Policy generator (pure fn)** | ✅ committed | `9f0afcf2` | `generate.go`: `Role` CRD scopes → derived-roles (one per role, binding-match condition) + resource policies (derived-role → actions). Per **A13**: emit an **OVERRIDE grantor** top scope (the RBAC ceiling) with a **root (`""`) policy per resource** (binding-match `derivedRoles` drop in unchanged); CONSENT org/project overlay scopes are M2; no scope-chain gaps.<br>**Deliverable:** generator emits valid Cerbos YAML for the built-in roles (`values.yaml`) **and representative out-of-repo open-vocabulary roles** (`radar:*`, `envir:*` from `~/go/src/k8s-deploy-unikorn` — the generator exists for exactly those); `cerbos compile` + its test suite pass on the output.<br>**Test:** golden-file unit tests per role (incl. open-vocab) + `cerbos compile` in CI.<br>**Depends:** A1, A13 (spike proves the mechanism first). |
| **A3 — Reconciling controller** | ✅ committed | `e96c62e1` | Watch `Role` CRDs → run A2 → write to the sidecar's policy volume/ConfigMap → hot-reload. Handles GitOps *and* manually-applied `Role` CRs, and must settle policies-ConfigMap ownership/upgrade semantics (Helm templates it empty today; upgrade/rollback/prune must not wipe controller-written policies — design §3.1).<br>**Deliverable:** applying/editing a `Role` CR updates Cerbos policy at runtime.<br>**Test:** integration — create a custom `Role`, assert a decision that depends on it flips.<br>**Depends:** A2. |
| **A4 — Cerbos request builder** | ✅ committed | `a4aaa41e` | `request.go`: identity's resolved principal (bindings + actor type + attrs) + resource (kind/id/org/project) + action → `CheckResources` request.<br>**Deliverable:** builder produces correct requests for user / service-account / system-account principals.<br>**Test:** table unit tests.<br>**Depends:** A1. |
| **A5 — `pkg/rbac.Check()`/`CheckMany()` delegating to Cerbos** | ✅ committed | `f2576298` | Decision API calling the client (local) / `/authorization/check` (remote), fail-closed, batched.<br>**Deliverable:** `Check()` returns correct allow/deny via Cerbos for representative cases.<br>**Test:** unit + integration.<br>**Depends:** A1, A4. |
| **A6 — `Allow*()` dual-path (facade preserved; legacy RETAINED)** | ✅ committed | `7c6e1c60` | Behind the unchanged `Allow*()` signatures, ADD a coarse Cerbos decision path while **retaining** the legacy local-ACL evaluation; a mode flag selects which the comparator (A7) serves. Legacy is removed only at A12 cutover — NOT here (A7 needs it live to compare against).<br>**Deliverable:** both engines live behind the facade; `Allow*` call sites compile unchanged.<br>**Test:** existing RBAC unit tests pass against the legacy path; new tests cover the Cerbos path.<br>**Depends:** A5. |
| **A7 — Shadow-mode comparator** | ✅ committed | `d5083837` | `shadow.go`: run legacy `Allow*` + Cerbos, **serve legacy**, log divergence (inputs, both verdicts, policy hash). Config-gated.<br>**Deliverable:** divergences are detected and logged; zero behaviour change.<br>**Test:** inject a deliberately-divergent policy → assert divergence logged; parity policy → none.<br>**Depends:** A6. |
| **A8 — Internal `/authorization/check` + `remote` path** | ✅ committed | `a22d33f5` | OpenAPI spec entry (`x-hidden` + `x-no-authorization` + `oauth2Authentication` security triple; `pkg/openapi/server.spec.yaml`, info bumped 1.13.0→1.14.0) + handler (`pkg/handler` `PostApiV1AuthorizationCheck`, thin: `SystemAccount` gate then `CheckMany`; Cerbos-authoritative, no legacy twin, fail-closed over the wire) + `remote` authorizer decision call (`pkg/middleware/openapi/remote` `CheckMany`, mirrors `GetACL`; local DTO, no `pkg/rbac` import; fail-closed sentinel mapping). Shipped with three review fixes: a `maxItems: 50` batch cap (matching the sidecar's per-request limit), corrected system-account framing (mTLS peer CN or cert-bound service token — plus a System-bearer-accepted test), and a `projectId`-without-`organizationId` → 400 handler guard.<br>**Deliverable:** a downstream service obtains a decision from identity.<br>**Test:** `make test-cerbos-remote` — real router + validator + handler + real Cerbos-backed RBAC via the generated typed client (allowed/denied, impersonated dual-check, bearer-reject, PDP-down). §3.7(c) reject-non-mTLS delivered in the handler; §3.7(a)/(b) hardening and downstream `Allow*`-routing are the follow-ups below.<br>**Depends:** A5. |
| **A9 — Retain thin-Go `/acl`** | ✅ committed | `fa8ee63e` | Ensure `GetApiV1Acl` / `…/organizations/{id}/acl` (`handler.go:309/319`) still compute the coarse ACL, now decoupled from enforcement.<br>**Deliverable:** `/acl` returns the same shape/content as today.<br>**Test:** regression test comparing `/acl` output pre/post.<br>**Depends:** A6 (decoupling). |
| **A10 — Decision logging + fail-closed + metrics** | ✅ committed | `0b930975` | `decision_log.go` to the shared audit sink; explicit `Check()` timeout → deny; metrics (latency, deny-on-error).<br>**Deliverable:** decisions logged (no tokens); Cerbos-down ⇒ deny.<br>**Test:** unit (fail-closed) + assert log fields.<br>**Depends:** A5. |
| **A11 — `hack/ci` + kind integration parity** | ✅ committed | `6fa4300e` | Add Cerbos to the CI stack; RBAC **parity matrix** (Cerbos == legacy) + **shadow-divergence CI gate**. Parity fixtures MUST cover the **open-vocabulary** shapes (`radar:*`/`envir:*` from `k8s-deploy-unikorn`), not only this repo's built-ins — that's what the generator exists for.<br>**Deliverable:** integration suite green; parity proven across built-in AND open-vocabulary roles.<br>**Test:** `test/api/suites/rbac_matrix_test.go` extended.<br>**Depends:** A2, A3, A7 (A8 dropped: its endpoint is a Cerbos-only path with no legacy twin, so it feeds the shadow gate nothing). |
| **A12 — Strangle-by-kind cutover + rollback** | 🔲 todo     | critical path — needs real shadow soak | Per-`(kind)` flag to flip Cerbos authoritative (retire the legacy path for that kind) + revert.<br>**Deliverable:** a kind flips to Cerbos-authoritative and reverts via config, gated on zero divergence.<br>**Test:** integration toggling a kind.<br>**Depends:** A7, A11. |
| **A13 — D1b composition spike** (`cerbos-experiment/spike-a13`) | ✅ done      | `spike-a13` (separate repo) | Verdict: the composition works on 0.53.0 — binding-match `derivedRoles` compose across a native `root→org→project` scope chain, `effectiveDerivedRoles` resolves at every scope, tenant isolation holds. **Requirements it established for A2:** (a) the chain top must be an **OVERRIDE grantor** — a consent-mode policy can't originate a grant, so an all-consent chain denies everything; (b) every scoped resource needs a **root (`""`) policy**; (c) `scopePermissions` is per-scope-string (consent/override can't share a scope → separate stores); (d) narrowing is via **explicit deny, not silence** — a silent org doesn't restrict, so an org-level veto needs an explicit deny at/above the org (consent = "≥1 ancestor allows & no scope denies"). |
| **A14 — Impersonation-intersection under Cerbos** | ✅ committed | `21285364` | Two AND-ed checks (impersonated principal ∧ acting service, identical resource/action), the service-side inheriting global→org→project flow-down; preserve the `direct\|`/`impersonated\|` cache-key discriminator.<br>**Deliverable:** impersonated decisions match today's `intersectACL`; shadow parity holds for system-account impersonation.<br>**Test:** unit + shadow.<br>**Depends:** A5, A6. |
| **A15 — Coarse-decision cache + policy-hash invalidation** | ✅ committed | `18e2e5c3` | Cache coarse cerbos-mode decisions at the `pkg/rbac` `allowCoarse` choke point, keyed by (subject, impersonation-flag+actor, scope, **policy hash**); the hash read-throughs the controller-owned policies ConfigMap key set (`pkg/authz/cerbos/policyhash.go`), so a controller republish changes the hash and busts every entry — no stale-allow past republish. Allow AND policy-deny are cached, transient failures never; the cache is inert without a hasher (safe default for downstream/tests); the impersonated key includes the actor's type + org set (every verdict-determining input, so distinct impersonated principals can't collide); hits skip the A10 audit log + `decisions_total` but are counted on a `coarse_cache_total{outcome=hit\|miss}` counter for hit-ratio observability; the impersonation type gate runs before any lookup.<br>**Deliverable:** correct keying; no stale-allow past republish.<br>**Test:** `decisionCacheKey` unit test (analogous to `pkg/middleware/openapi/cachekey_test.go`) + cache-behaviour tests + policy-store hasher tests, all in `test-unit`.<br>**Depends:** A3, A6. |
| **A16 — Grantability cross-parity** | ✅ committed | `b2e8a6fb` | Keep grantability (`AllowRole`) reading the caller's materialized ACL (Go `GetACL`); add a test asserting the Go expansion and the generated Cerbos policy AGREE for every role (built-in + open-vocab).<br>**Deliverable:** enforcement (Cerbos) and grant-guard (Go) provably agree — `TestGrantabilityCrossParity` (`pkg/rbac`, `//go:build integration`) holds one isolated principal per role and asserts both directions across the full endpoint×operation vocabulary at every scope; test-only, `AllowRole` stays thin-Go. Rides `make test-cerbos-decisions` and its PR CI, no new wiring.<br>**Test:** `make test-cerbos-decisions`.<br>**Depends:** A2, A6. |
| **A17 — Post-cutover legacy removal + doc updates** | 🔲 todo     | after A12 | After A12: delete the dead legacy decision path; update the affected `pkg/**/README.md` (`pkg/rbac`, `pkg/middleware/openapi`, `pkg/oauth2`, `pkg/authn`, `pkg/authz/cerbos`) per CLAUDE.md.<br>**Deliverable:** no dead legacy code; package docs current.<br>**Depends:** A12. |
| **A18 — `/authorization/check` principal-propagation hardening (§3.7 a/b)** | ✅ slice (WT) | working tree — pending commit; (a) chart-assert + (b)→A23 deferred | A8 delivered §3.7(c) (handler rejects non-`SystemAccount` callers, re-deriving the acting identity from the verified peer CN). **This hardening slice landed in the working tree** and hardens + *proves* the current trust-the-channel model: (1) forged-header **negative tests** — a spoofed `X-Principal`/`X-Impersonate` over a non-mTLS/bearer/no-cert hop is rejected, does NOT grant `SystemAccount`, cannot reach Cerbos, and cannot override the acting identity derived from the verified peer (`pkg/handler` `TestAuthorizationCheckIgnoresForgedPrincipalHeaders`; `pkg/middleware/openapi` `TestServiceToServiceForgedPrincipalWithoutMTLSIsNotHonored` + `TestForgedPrincipalHeaderWithoutVerifiedPeerRejected`; `make test-unit`); (2) a **genuine mTLS-handshake** assertion for the endpoint in **kind CI** (`test/api/suites/authorization_check_mtls_test.go`, rides `make test-api-ci`; valid trusted client cert → decision returned, no/untrusted cert → rejected). **Deferred:** (a) the **static chart-level** ingress header-stripping deploy assertion (the deploy invariant is now proven end-to-end in kind CI and the code path is negative-tested; only the Helm-template assertion is outstanding); (b) **signed-principal propagation as the default** → split to **A23** (trust-the-channel kept by owner decision). Note recorded in code (`extractPrincipal`) + `pkg/middleware/openapi/README.md`.<br>**Depends:** A8. |
| **A19 — Downstream `Allow*`-routing through the remote decision call** | 🔲 todo     | follow-up of A8 | A8 delivered the remote decision **call** (`remote.Authorizer.CheckMany` over `/authorization/check`), but NOT downstream `Allow*` **routing** through it: that needs a remote transport **above** `rbac.decide()` (a downstream RBAC cannot read identity's authorization resources — the Group/Role/Project/Organization CRDs binding resolution walks — so `ResolveBindings` fail-closed-denies everything) plus a remote `DecisionEngineProvider` — the `DecisionEngine()` seam sits **below** binding resolution and cannot express it (see `pkg/rbac/check.go`, `pkg/middleware/openapi/decision_engine.go`). A19 also owns the **`AllowProjectScopeCreate` dual-path migration** (split out of A9): Create is a downstream-only export, reachable only once A19's remote `DecisionEngineProvider` seeds an engine into downstream contexts, and its existence-check orchestration maps onto coarse Cerbos checks (global-trust / org-derived-verify / project-specific-exists).<br>**Deliverable:** a downstream service's `Allow*()` call transparently obtains its decision from identity via the remote path.<br>**Depends:** A8. |
| **A20 — Wire the policy-store hash into the decision correlate** (deferred out of A15) | ✅ committed | `6656b97e` | A15 built the policy-store hash signal (`pkg/authz/cerbos.PolicyStoreHasher`) but deferred consuming it in the observability correlate. A20 replaces the empty PDP version/scope echo with the store hash, emitted as a single `policy_hash` field in the shadow-divergence records (`shadow.go`) and the A10 decision records (`decision_log.go`), sourced from a new fail-safe `RBAC.policyStoreHash` helper (empty when no hasher is configured or the hash is unavailable) and gated on an obtained verdict (a failure record pins no revision). The now-vestigial PDP-response-for-correlate threading is removed (`capturingPDP`, `shadowPolicyCorrelate`, `resultPolicyCorrelate`, the response returns from `decide`/`evaluate`/`decideImpersonated`, and the `recordDecisions` response param); public `Check`/`CheckMany`/`Allow*` signatures and the decision counter (still `decision × class`, never the high-cardinality hash) are unchanged. The three "A15 seam" comments are resolved.<br>**Deliverable:** shadow-divergence and decision records carry the policy-store hash.<br>**Depends:** A15. |
| **A21 — Align `aclCacheKey` with the decision cache's keying** (deferred out of A15) | ✅ committed | `2fc05b38` | A15 hardened the coarse-decision cache key to include the impersonated principal's type + sorted org set (the verdict-determining inputs the A14 dual check resolves from). The middleware's ACL cache key (`aclCacheKey`, `pkg/middleware/openapi`) has the same latent gap — it keys an impersonated ACL on `(sub, actor, scope)` only, so two impersonated principals sharing an actor string but differing in type/org set can collide (pre-existing, TTL-bounded). A21 brings `aclCacheKey` to parity (add type + sorted org set to the impersonated key) with a `cachekey_test` case.<br>**Deliverable:** the ACL cache cannot serve one impersonated principal's ACL to another; parity with the decision key.<br>**Depends:** A6. |
| **A22 — Guard the policy store against the ConfigMap size ceiling** | ✅ committed | `1bca0c44` | The controller (A3) writes the entire generated Cerbos store into ONE ConfigMap, capped at ~1 MiB by the API server (the etcd request-size limit). Today an over-cap store fails `publish` as a generic `"publishing policy store"` reconcile error and silently freezes at last-good — new `Role` changes stop taking effect with no dedicated signal. A22 adds a pre-publish size check (~1 MiB) that refuses with a dedicated `PolicyStoreTooLarge` Warning event (mirroring the compile-gate refusal path in `controller.go`), turning a silent freeze into a legible one, and documents the ceiling as a caveat in `pkg/authz/cerbos`. Sharding the store across multiple ConfigMaps or a non-ConfigMap Cerbos store (blob/git/DB) is out of scope — M2.<br>**Deliverable:** an over-cap store is refused legibly with last-good retained; the ceiling is documented.<br>**Depends:** A3. |
| **A23 — Signed-principal propagation (deferred)** | 🔲 todo | deferred (cross-service; trust-the-channel kept) | The **A18(b)** split-out. Make **signature-verified** `X-Principal` propagation (`EncodeAndSign`/`VerifyAndDecode`, uni-core) the **default** for service-to-service calls, so trust does not rest on ingress header-stripping alone, instead of the current unsigned base64-JSON `X-Principal` (`principal.Injector`). Deferred by owner decision: the signing/verification primitives live in **uni-core** (flipping the default is cross-repo/flag-day and breaking) and per-request public-key verification has a real perf cost. The mechanism already exists — `extractPrincipal`'s `VerifyAndDecode` fallback handles signed principals today for `principal.ControllerInjector` — but it is NOT the default. Trust-the-channel (unsigned `X-Principal` over mTLS + ingress stripping) is KEPT and A18-proven.<br>**Deliverable:** signed propagation is the default; trust no longer rests on ingress config alone.<br>**Depends:** A8, A18. |

---

## Plan B — AuthN verifier registry

**Goal:** replace hardcoded credential dispatch with a `CredentialVerifier`
registry producing a `NormalizedPrincipal`; migrate existing methods behind it;
implement the OIDC-provider generalization; stub the rest. *(Independent of Plan A.)*

**Current state (verified against `pkg/oauth2`).** The passport **exchange** endpoint,
the shared `dispatchUserinfo` seam, and passport-layer normalization
(`PassportClaims.Source`) already exist — but there is **no registry, no
`NormalizedPrincipal`**, dispatch is still hardcoded (JOSE-shape in `passport.go` +
a separate mTLS branch in `middleware/openapi`), and there is a single
flag-configured Auth0 exchange validator. So **B1–B3 are refactors that wrap
existing logic** (`GetUserinfo`, the cert-CN path, `Userinfo`/`PassportClaims`)
behind the new contract; **B4 is the only net-new authN work** (CRD-driven
multi-provider `iss`-dispatch) and the critical path. Nothing here is already done.

### File structure

| File | Create/Modify | Responsibility |
|---|---|---|
| `pkg/authn/principal.go` | Create | `NormalizedPrincipal` (formalize/extend `Userinfo`/passport claims: `Source`, `Attrs`). |
| `pkg/authn/verifier.go`, `registry.go` | Create | `CredentialVerifier` interface + registry + dispatch (`iss` peek / scheme / cert). |
| `pkg/oauth2/*`, `pkg/oauth2/auth0/*` | Modify | UNI-token and OIDC verifiers moved behind the registry; `auth0` → provider-agnostic. |
| `pkg/apis/unikorn/v1alpha1/types.go` (`OAuth2ProviderSpec`, ~L110) | Modify | Add a new `tokenExchange` block to `OAuth2ProviderSpec` (per `docs/passport-exchange-providers.md`). |
| `pkg/middleware/openapi/openapi.go` | Modify | Dispatch through the registry (replace the hardcoded JWE/JWS/mTLS ladder). |
| `pkg/authn/verifiers/{saml,apikey,workload}.go` | Create | Interface stubs returning explicit "not implemented". |

### Tasks

**Not started (0 of 6).**

Same tracker format as Plan A; all 🔲 todo (nothing landed). **Depends** is in the definition; the Commit / blocker column carries the near-term gate.

| Task | Status | Commit / blocker | Definition — Deliverable · Test · Depends |
|---|---|---|---|
| **B1 — `CredentialVerifier` + `NormalizedPrincipal` + registry** | 🔲 todo | no deps — ready | Interface, the normalized shape (extending existing `Userinfo`/passport claims), and the dispatch registry.<br>**Deliverable:** registry routes a credential to the right verifier by cheap hints.<br>**Test:** unit tests for dispatch.<br>**Depends:** — |
| **B2 — Migrate UNI-token verifier** | 🔲 todo | after B1 | Move `GetUserinfoFromBearer`'s UNI-JWE path behind a `CredentialVerifier`.<br>**Deliverable:** UNI tokens verify identically via the registry.<br>**Test:** parity unit tests.<br>**Depends:** B1. |
| **B3 — Migrate mTLS / system-account verifier** | 🔲 todo | after B1 | Cert-CN → system principal, behind the registry.<br>**Deliverable:** mTLS auth via the registry.<br>**Test:** unit.<br>**Depends:** B1. |
| **B4 — Generalize OIDC/Auth0 verifier (the net-new authN work)** | 🔲 todo | after B1 · net-new critical path | **Reuse the existing generic `pkg/oauth2/oidc` verifier** (currently login-only) on the passport path — do **not** rewrite OIDC verification; replace the bespoke `pkg/oauth2/auth0` exchange validator; `iss`-dispatch against `OAuth2Provider.tokenExchange` CRDs (new block → CRD schema change + `make generate`); per-provider JWKS (retain the throttle); **deprecate the `--auth0-exchange-*` flags and migrate the `identity.auth0Exchange` chart values**. Implements `docs/passport-exchange-providers.md`.<br>**Deliverable:** an OIDC token from a CRD-configured provider exchanges into a passport; Auth0-specific flags/values gone.<br>**Test:** unit + integration with a test provider.<br>**Depends:** B1. |
| **B5 — Wire the registry into middleware** | 🔲 todo | after B2, B3, B4 | Replace the hardcoded dispatch (incl. the inline mTLS system-account branch) in `pkg/middleware/openapi`.<br>**Deliverable:** all existing auth paths run through the registry, behaviour-equivalent.<br>**Test:** existing auth-middleware tests pass where control flow is unchanged; where the seam changes flow, update the test and justify the change.<br>**Depends:** B2, B3, B4. |
| **B6 — Stub SAML / API-key / workload verifiers** | 🔲 todo | after B1 | Interface implementations returning explicit not-implemented + design notes.<br>**Deliverable:** the seam is complete; adding a real method is a new `CredentialVerifier`.<br>**Test:** unit (registration + not-implemented).<br>**Depends:** B1. |

---

## Execution

Recommended: **subagent-driven-development** — a fresh subagent per task, which
reads the real file it's touching, writes the bite-sized TDD steps for that task,
implements, and returns for a review gate before the next. Alternatively, inline
execution per `executing-plans`. Plans A and B can run in parallel.

Next slice (see **Status** above for what has landed): **A12** (the kind cutover)
is the critical path now that **A16** grantability cross-parity has landed. **A12 must not
cut over until real shadow soak shows zero divergence** — the A11 kind gate proves
this for identity-served kinds under non-impersonated-plus-impersonated traffic;
open-vocabulary parity is proven by the docker decision matrix plus the A2 compile
suite, since no `radar:*`/`envir:*` traffic flows through identity's own endpoints.
**A18** landed its hardening slice (forged-header negative tests + a genuine kind-CI mTLS
assertion) in the working tree; its residual — a static chart-level ingress-stripping assertion (a)
and signed-principal propagation as the default (b, split to **A23**) — plus **A19** (downstream
`Allow*`-routing) and all of **Plan B** remain open and can run in parallel. Cutover for *remote*
kinds additionally waits on A19 (downstream adoption of the A8 endpoint).
