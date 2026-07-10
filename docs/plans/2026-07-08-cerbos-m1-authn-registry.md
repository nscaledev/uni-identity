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

### Tasks (ordered; each ends in a testable deliverable)

- [ ] **A1 — Cerbos sidecar + client + config.** Add the Cerbos sidecar to `charts/identity` (localhost gRPC, v0.53.0); scaffold `pkg/authz/cerbos/client.go` (connect, health, timeout, **fail-closed on unavailable**); wire config/flags. *Deliverable:* identity boots with the sidecar; a trivial `CheckResources` round-trips. *Test:* integration test hits the sidecar with a hand-written allow/deny policy. *Depends:* —
- [ ] **A2 — Policy generator (pure fn).** `generate.go`: `Role` CRD scopes → derived-roles (one per role, binding-match condition) + resource policies (derived-role → actions). Per **A13**: emit an **OVERRIDE grantor** top scope (the RBAC ceiling) with a **root (`""`) policy per resource** (binding-match `derivedRoles` drop in unchanged); CONSENT org/project overlay scopes are M2; no scope-chain gaps. *Deliverable:* generator emits valid Cerbos YAML for the built-in roles (`values.yaml`) **and representative out-of-repo open-vocabulary roles** (`radar:*`, `envir:*` from `~/go/src/k8s-deploy-unikorn` — the generator exists for exactly those); `cerbos compile` + its test suite pass on the output. *Test:* golden-file unit tests per role (incl. open-vocab) + `cerbos compile` in CI. *Depends:* A1, A13 (spike proves the mechanism first).
- [ ] **A3 — Reconciling controller.** Watch `Role` CRDs → run A2 → write to the sidecar's policy volume/ConfigMap → hot-reload. Handles GitOps *and* manually-applied `Role` CRs, and must settle policies-ConfigMap ownership/upgrade semantics (Helm templates it empty today; upgrade/rollback/prune must not wipe controller-written policies — design §3.1). *Deliverable:* applying/editing a `Role` CR updates Cerbos policy at runtime. *Test:* integration — create a custom `Role`, assert a decision that depends on it flips. *Depends:* A2.
- [ ] **A4 — Cerbos request builder.** `request.go`: identity's resolved principal (bindings + actor type + attrs) + resource (kind/id/org/project) + action → `CheckResources` request. *Deliverable:* builder produces correct requests for user / service-account / system-account principals. *Test:* table unit tests. *Depends:* A1.
- [ ] **A5 — `pkg/rbac.Check()`/`CheckMany()` delegating to Cerbos.** Decision API calling the client (local) / `/authorization/check` (remote), fail-closed, batched. *Deliverable:* `Check()` returns correct allow/deny via Cerbos for representative cases. *Test:* unit + integration. *Depends:* A1, A4.
- [ ] **A6 — `Allow*()` dual-path (facade preserved; legacy RETAINED).** Behind the unchanged `Allow*()` signatures, ADD a coarse Cerbos decision path while **retaining** the legacy local-ACL evaluation; a mode flag selects which the comparator (A7) serves. Legacy is removed only at A12 cutover — NOT here (A7 needs it live to compare against). *Deliverable:* both engines live behind the facade; `Allow*` call sites compile unchanged. *Test:* existing RBAC unit tests pass against the legacy path; new tests cover the Cerbos path. *Depends:* A5.
- [ ] **A7 — Shadow-mode comparator.** `shadow.go`: run legacy `Allow*` + Cerbos, **serve legacy**, log divergence (inputs, both verdicts, policy hash). Config-gated. *Deliverable:* divergences are detected and logged; zero behaviour change. *Test:* inject a deliberately-divergent policy → assert divergence logged; parity policy → none. *Depends:* A6.
- [ ] **A8 — Internal `/authorization/check` + `remote` path.** OpenAPI spec entry (`x-hidden`, mTLS) + handler + `remote` authorizer decision call. Gates A12-for-remote-kinds (downstream adoption). *Deliverable:* a downstream service obtains a decision from identity. *Test:* integration via the typed client over mTLS. *Depends:* A5.
- [ ] **A9 — Retain thin-Go `/acl`.** Ensure `GetApiV1Acl` / `…/organizations/{id}/acl` (`handler.go:309/319`) still compute the coarse ACL, now decoupled from enforcement. *Deliverable:* `/acl` returns the same shape/content as today. *Test:* regression test comparing `/acl` output pre/post. *Depends:* A6 (decoupling).
- [ ] **A10 — Decision logging + fail-closed + metrics.** `decision_log.go` to the shared audit sink; explicit `Check()` timeout → deny; metrics (latency, deny-on-error). *Deliverable:* decisions logged (no tokens); Cerbos-down ⇒ deny. *Test:* unit (fail-closed) + assert log fields. *Depends:* A5.
- [ ] **A11 — `hack/ci` + kind integration parity.** Add Cerbos to the CI stack; RBAC **parity matrix** (Cerbos == legacy) + **shadow-divergence CI gate**. Parity fixtures MUST cover the **open-vocabulary** shapes (`radar:*`/`envir:*` from `k8s-deploy-unikorn`), not only this repo's built-ins — that's what the generator exists for. *Deliverable:* integration suite green; parity proven across built-in AND open-vocabulary roles. *Test:* `test/api/suites/rbac_matrix_test.go` extended. *Depends:* A2, A3, A7 (A8 dropped: its endpoint is a Cerbos-only path with no legacy twin, so it feeds the shadow gate nothing).
- [ ] **A12 — Strangle-by-kind cutover + rollback.** Per-`(kind)` flag to flip Cerbos authoritative (retire the legacy path for that kind) + revert. *Deliverable:* a kind flips to Cerbos-authoritative and reverts via config, gated on zero divergence. *Test:* integration toggling a kind. *Depends:* A7, A11.
- [x] **A13 — D1b composition spike. ✅ DONE** (`cerbos-experiment/spike-a13`). Verdict: the composition works on 0.53.0 — binding-match `derivedRoles` compose across a native `root→org→project` scope chain, `effectiveDerivedRoles` resolves at every scope, tenant isolation holds. **Requirements it established for A2:** (a) the chain top must be an **OVERRIDE grantor** — a consent-mode policy can't originate a grant, so an all-consent chain denies everything; (b) every scoped resource needs a **root (`""`) policy**; (c) `scopePermissions` is per-scope-string (consent/override can't share a scope → separate stores); (d) narrowing is via **explicit deny, not silence** — a silent org doesn't restrict, so an org-level veto needs an explicit deny at/above the org (consent = "≥1 ancestor allows & no scope denies").
- [ ] **A14 — Impersonation-intersection under Cerbos.** Two AND-ed checks (impersonated principal ∧ acting service, identical resource/action), the service-side inheriting global→org→project flow-down; preserve the `direct|`/`impersonated|` cache-key discriminator. *Deliverable:* impersonated decisions match today's `intersectACL`; shadow parity holds for system-account impersonation. *Test:* unit + shadow. *Depends:* A5, A6.
- [ ] **A15 — Coarse-decision cache + policy-hash invalidation.** Cache coarse decisions keyed by (subject, impersonation-flag+actor, scope, **policy hash**); bust on controller republish; cache-key test analogous to `pkg/middleware/openapi/cachekey_test.go`. *Deliverable:* correct keying; no stale-allow past republish. *Depends:* A3, A6.
- [ ] **A16 — Grantability cross-parity.** Keep grantability (`AllowRole`) reading the caller's materialized ACL (Go `GetACL`); add a test asserting the Go expansion and the generated Cerbos policy AGREE for every role (built-in + open-vocab). *Deliverable:* enforcement (Cerbos) and grant-guard (Go) provably agree. *Depends:* A2, A6.
- [ ] **A17 — Post-cutover legacy removal + doc updates.** After A12: delete the dead legacy decision path; update the affected `pkg/**/README.md` (`pkg/rbac`, `pkg/middleware/openapi`, `pkg/oauth2`, `pkg/authn`, `pkg/authz/cerbos`) per CLAUDE.md. *Deliverable:* no dead legacy code; package docs current. *Depends:* A12.

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

- [ ] **B1 — `CredentialVerifier` + `NormalizedPrincipal` + registry.** Interface, the normalized shape (extending existing `Userinfo`/passport claims), and the dispatch registry. *Deliverable:* registry routes a credential to the right verifier by cheap hints. *Test:* unit tests for dispatch. *Depends:* —
- [ ] **B2 — Migrate UNI-token verifier.** Move `GetUserinfoFromBearer`'s UNI-JWE path behind a `CredentialVerifier`. *Deliverable:* UNI tokens verify identically via the registry. *Test:* parity unit tests. *Depends:* B1.
- [ ] **B3 — Migrate mTLS / system-account verifier.** Cert-CN → system principal, behind the registry. *Deliverable:* mTLS auth via the registry. *Test:* unit. *Depends:* B1.
- [ ] **B4 — Generalize OIDC/Auth0 verifier (the net-new authN work).** **Reuse the existing generic `pkg/oauth2/oidc` verifier** (currently login-only) on the passport path — do **not** rewrite OIDC verification; replace the bespoke `pkg/oauth2/auth0` exchange validator; `iss`-dispatch against `OAuth2Provider.tokenExchange` CRDs (new block → CRD schema change + `make generate`); per-provider JWKS (retain the throttle); **deprecate the `--auth0-exchange-*` flags and migrate the `identity.auth0Exchange` chart values**. Implements `docs/passport-exchange-providers.md`. *Deliverable:* an OIDC token from a CRD-configured provider exchanges into a passport; Auth0-specific flags/values gone. *Test:* unit + integration with a test provider. *Depends:* B1.
- [ ] **B5 — Wire the registry into middleware.** Replace the hardcoded dispatch (incl. the inline mTLS system-account branch) in `pkg/middleware/openapi`. *Deliverable:* all existing auth paths run through the registry, behaviour-equivalent. *Test:* existing auth-middleware tests pass where control flow is unchanged; where the seam changes flow, update the test and justify the change. *Depends:* B2, B3, B4.
- [ ] **B6 — Stub SAML / API-key / workload verifiers.** Interface implementations returning explicit not-implemented + design notes. *Deliverable:* the seam is complete; adding a real method is a new `CredentialVerifier`. *Test:* unit (registration + not-implemented). *Depends:* B1.

---

## Execution

Recommended: **subagent-driven-development** — a fresh subagent per task, which
reads the real file it's touching, writes the bite-sized TDD steps for that task,
implements, and returns for a review gate before the next. Alternatively, inline
execution per `executing-plans`. Plans A and B can run in parallel.

Suggested first slices: **A13 is done** (✅ composition proven — `cerbos-experiment/spike-a13`)
→ **A1–A3** (get generated policies live under shadow, honoring A13's grantor-root
pattern) and **B1** (the registry contract). Nothing cuts over authoritative until
**A7/A11** prove zero divergence. (The A11 kind gate covers identity-served kinds;
open-vocabulary parity is proven by the docker decision matrix plus the A2 compile
suite, since no `radar:*`/`envir:*` traffic flows through identity's own endpoints.)
