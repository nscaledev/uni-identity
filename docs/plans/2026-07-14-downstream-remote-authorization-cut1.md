# Downstream Remote Authorization — Cut #1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route `uni-region` and `uni-compute` authorization decisions through identity's central Cerbos PDP via `POST /authorization/check`, shadow-first, with guardrail essentials — keeping the `rbac.Allow*` facade and changing ~one line per consumer.

**Architecture:** Add a `rbac.CoarseEngine` seam in identity: the local `*RBAC` and a new remote adapter (over the existing `authorizer.CheckMany`) both satisfy it. A remote engine is seeded into the request context by a `RemoteDecisionEngineProvider` at the single middleware seed point, carrying a mode (`off|shadow|enforce`). The three `Allow*` dispatch forks consult the remote engine first; `enforce` makes it authoritative (fail-closed), `shadow` serves the legacy walk and logs divergence. Consumers flip a config value; their handlers are untouched.

**Tech Stack:** Go 1.25, `github.com/unikorn-cloud/identity/pkg/rbac`, `.../pkg/middleware/openapi[/remote]`, cerbos-sdk-go, Ginkgo/Gomega (integration), kind CI. Design spec: `docs/downstream-remote-authorization-design.md`.

## Progress (updated 2026-07-15)

Identity-side seam (Tasks 1–9b), **Task 10** (uni-region wiring + Fix A), **Task 11** (uni-region shadow e2e), **and Task 12a** (uni-compute wiring + Fix A) **done and committed** — the Task 11/12 e2e *runs* are CI-deferred (Colima LB wall). **Task 12b** (the compute/kubernetes e2e harness) is folded into the unified downstream-e2e follow-up (Out of scope).

| Task | Status | Commit / notes |
|------|--------|----------------|
| 1 — parity + impersonation spike | ✅ done | findings → design §7 (`ffa4e926`); bearer landmine fixed `c18eeefe` |
| 2 — CoarseEngine seam | ✅ done | `7e20e487` |
| 3 — remote adapter | ✅ done | `9f28b357` |
| 4 — per-call timeout | ✅ done | `0b3d4255` |
| 5 — remote-engine context + mode | ✅ done | `63170d89` |
| 6 — dispatch arm (enforce) | ✅ done | `0b4d67aa` |
| 7 — remoteShadowed comparator | ✅ done | `d01119fe` |
| 8 — seed remote engine | ✅ done | `a4ad0233` |
| 9 — caller-side telemetry | ✅ done | `88ba7d6b` |
| 9b — impersonation trigger ("Fix B") | ✅ done | `94d2eb1e` (corrected to the `authorization.Info` model) |
| 10 — uni-region wiring + role provisioning | ✅ done | uni-region `3f92ade` (wiring + flags + chart) + `region-service` superset / Fix A (`3e6254d3`, identity) |
| 11 — uni-region cross-service e2e + divergence gate | ✅ committed; kind run pends CI | uni-region `bf3b3a5`; reviewed + compile-verified; local kind run blocked by Colima LB routing → empirical 0-divergence pends CI/Linux |
| 12a — uni-compute wiring + Fix A (shadow) | ✅ done | uni-compute `9d742b5` (cerbos-integration) + `compute-service` `compute:*` superset / Fix A (identity `1e75c435`) |
| 12b — uni-compute e2e/CI harness | ⬜ deferred | greenfield (no `hack/ci/`, 2-level install, can't run locally); folded into the unified downstream-e2e follow-up — see Out of scope |

> **Model correction (2026-07-15, design §4.3):** the original "always impersonate" model was superseded by trusted-subsystem / caller-alone. **Fix B** = the Task 9b trigger (done). **Fix A** = the `region-service` `region:*` superset (part of Task 10, committed `3e6254d3`).

---

## Global Constraints

- **GOWORK=off** for every `go` command (a local `go.work` links sibling checkouts; CI resolves via `go.mod`).
- **Commits are the user's.** Per this project's workflow ([[feedback-no-commits-without-review]]), each task's final step **stages** the change (`git add`) and hands off for review — **do NOT `git commit`**. The user commits after review. Do NOT touch `CLAUDE.md`.
- **Fail-closed** everywhere: any transport/timeout/PDP/resolver failure is a deny, distinguishable via `errors.Is(err, rbac.ErrDecisionUnavailable)` vs a policy deny (`rbac.ErrPolicyDenied`).
- **Per-call timeout** target 100–300ms; default **250ms**.
- **§4.3:** authorization stays behind `pkg/rbac` (the facade). Never call `CheckMany` raw from consumer handlers.
- **§4.6 / §4.6.1:** the remote check runs in impersonation mode (decide against the user); identity applies `intersection(user ACL, calling-service ACL)`. Consumer system-account CN→role must be provisioned in identity Helm values.
- **No secrets/tokens in logs.** Decision logs carry: correlation id, actor/subject, resource, operation, org/project, decision, source, latency.
- **Pre-commit checklist must pass before hand-off** (run from the repo being changed): `make touch && make license && make validate && make lint && make generate && [[ -z $(git status --porcelain) ]] && make test-unit`.
- **Test conventions:** package unit tests follow the package's existing Go style; `test/` integration suites use the BDD + typed-client rules in `CLAUDE.md`; integration files carry `//go:build integration`, e2e `//go:build e2e`.

---

## File Structure

**uni-identity (the seam — Tasks 1–8):**
- `pkg/rbac/coarse_engine.go` *(new)* — the `CoarseEngine` interface + local `*RBAC` methods `AllowCoarse`/`AllowCoarseMany`.
- `pkg/rbac/remote_engine.go` *(new)* — `RemoteMode`, `NewRemoteEngineContext`, `remoteEngineFromContext`, `dispatchCoarse` helper, `remoteShadowed` comparator.
- `pkg/rbac/handler.go` *(modify)* — the 3 dispatch forks call `dispatchCoarse`.
- `pkg/rbac/remote_engine_test.go`, `pkg/rbac/coarse_engine_test.go` *(new)* — unit tests.
- `pkg/middleware/openapi/remote/engine.go` *(new)* — `RemoteEngine` adapter implementing `rbac.CoarseEngine` over `Authorizer.CheckMany`; `Authorizer.RemoteDecisionEngine()`.
- `pkg/middleware/openapi/remote/decision.go` *(modify)* — per-call timeout around the check call.
- `pkg/middleware/openapi/remote/authorizer.go` *(modify)* — timeout option/field; construct with mode.
- `pkg/middleware/openapi/decision_engine.go` *(modify)* — add `RemoteDecisionEngineProvider` interface.
- `pkg/middleware/openapi/openapi.go` *(modify, ~518–529)* — seed the remote engine.
- `pkg/rbac/decision_log.go` / metrics *(modify)* — caller-side telemetry for remote decisions.

**uni-region / uni-compute (Tasks 9–12):**
- `pkg/server/server.go` *(modify)* — construct the remote authorizer with a mode from config.
- `pkg/server/options.go` (or equivalent) *(modify)* — the `--authorization-engine-mode` flag.
- `charts/*/values.yaml` + `templates/.../deployment.yaml` *(modify)* — render the mode; identity chart values map the consumer CN→role.
- `test/e2e/rbac_matrix_test.go` (+ `hack/ci/*`) *(modify/new)* — cross-service kind e2e + divergence gate.

---

## Task 1: Parity + impersonation-context spike (sets the divergence expectation and the impersonation wiring)

**Files:**
- Read: `pkg/handler/handler.go` (the `GetApiV1...Acl`/`GetACL` handler), `pkg/rbac` ACL assembly, `pkg/middleware/openapi/remote/authorizer.go:334-345` (`GetACL`), `pkg/principal/injector.go`, and a consumer's principal middleware setup (`uni-region/pkg/server/server.go` request wiring).
- Modify: `docs/downstream-remote-authorization-design.md` (§7 open items).

**Interfaces:** Produces a documented finding only; no code contract. Its two findings gate Tasks 10–12 (role provisioning; impersonation marking).

- [x] **Step 1: §4.6.1 parity.** Determine whether today's downstream `GetACL` already applies `intersection(user, calling-service)`, or returns the user's full ACL. Check the A14 dual-check impersonation handling and the ACL handler.
- [x] **Step 2: Impersonation context.** Determine how (or whether) the consumer request path marks the acting **user** as the impersonated principal for a `CheckMany` call — i.e. whether `principal.ImpersonateFromContext` is set in a consumer's user-request context so `principal.Injector` emits `X-Impersonate: true`. Without it, identity would decide against the *service's* identity (attribution-only, §4.6), not the user — a correctness bug.
- [x] **Step 3: Record both findings** in the design doc §7: "(a) GetACL returns {full user ACL | intersected} ⇒ shadow expected {non-zero, close via provisioning | zero}. (b) Consumer path {already marks | does NOT mark} the user as impersonated for CheckMany ⇒ Task 10/12 {no-op | must set `ImpersonateFromContext` at <location>}."
- [x] **Step 4: Stage for review.** `git add docs/downstream-remote-authorization-design.md` (no commit).

---

## Task 2: `CoarseEngine` interface + local `*RBAC` implementation

**Files:**
- Create: `pkg/rbac/coarse_engine.go`
- Create: `pkg/rbac/coarse_engine_test.go`

**Interfaces:**
- Consumes: `RBAC.allowCoarse(ctx, Resource, openapi.AclOperation) error` (engine.go:190, cached), `RBAC.CheckMany(ctx, []CheckRequest) ([]bool, error)` (check.go:154).
- Produces:
  ```go
  type CoarseEngine interface {
      // AllowCoarseMany is the batch primitive: one PDP round-trip for N
      // resources (list filtering).  Returns per-resource verdicts in order;
      // a non-nil error is fail-closed (treat every entry as denied).
      AllowCoarseMany(ctx context.Context, resources []Resource, action openapi.AclOperation) ([]bool, error)
      // AllowCoarse is the single-resource convenience the Allow* facade uses;
      // nil == allow, else an HTTPForbidden wrapping ErrPolicyDenied /
      // ErrDecisionUnavailable.
      AllowCoarse(ctx context.Context, resource Resource, action openapi.AclOperation) error
  }
  ```
  Local methods on `*RBAC`: `AllowCoarse` delegates to `allowCoarse` (preserving the cache + impersonation gate); `AllowCoarseMany` delegates to `CheckMany`.
  Also **exports** `CoarseForbidden(resource Resource, operation openapi.AclOperation, err error) error` — a rename of the existing unexported `coarseForbidden` (engine.go:244) — so the remote adapter (Task 3) reuses the identical `HTTPForbidden` error shape (single source of truth).

- [x] **Step 1: Write the failing test** — `coarse_engine_test.go` (package `rbac_test`, reuse the `newParityFixture`/`capturePDP` helpers from the existing dispatch tests):
```go
func TestRBACImplementsCoarseEngine(t *testing.T) {
    t.Parallel()
    var _ rbac.CoarseEngine = (*rbac.RBAC)(nil) // compile-time contract

    // AllowCoarse: single, cached path (allow).
    engine := newDispatchEngine(t, rbac.EngineCerbos, &capturePDP{allow: true})
    ctx := rbac.NewEngineContext(rbac.NewContext(aliceContext(t), globalACL("identity:groups", openapi.Read)), engine)
    require.NoError(t, engine.AllowCoarse(ctx, rbac.Resource{Kind: "identity:groups"}, openapi.Read))

    // AllowCoarseMany: batch, verdicts in order (allow, deny).
    pdp := &capturePDP{results: []bool{true, false}}
    engine2 := newDispatchEngine(t, rbac.EngineCerbos, pdp)
    ctx2 := rbac.NewEngineContext(rbac.NewContext(aliceContext(t), globalACLBoth("a:x", "a:y")), engine2)
    got, err := engine2.AllowCoarseMany(ctx2, []rbac.Resource{{Kind: "a:x"}, {Kind: "a:y"}}, openapi.Read)
    require.NoError(t, err)
    require.Equal(t, []bool{true, false}, got)
}
```
(If `capturePDP` lacks a `results []bool` field, extend it minimally as part of this task.)
- [x] **Step 2: Run — expect FAIL** (`AllowCoarse`/`AllowCoarseMany`/`CoarseEngine` undefined): `GOWORK=off go test ./pkg/rbac/ -run TestRBACImplementsCoarseEngine -v`
- [x] **Step 3: Implement** `pkg/rbac/coarse_engine.go`:
```go
package rbac

import (
    "context"
    "github.com/unikorn-cloud/identity/pkg/openapi"
)

type CoarseEngine interface {
    AllowCoarseMany(ctx context.Context, resources []Resource, action openapi.AclOperation) ([]bool, error)
    AllowCoarse(ctx context.Context, resource Resource, action openapi.AclOperation) error
}

// AllowCoarse serves one coarse decision through the coarse-decision cache.
func (r *RBAC) AllowCoarse(ctx context.Context, resource Resource, action openapi.AclOperation) error {
    return r.allowCoarse(ctx, resource, action)
}

// AllowCoarseMany serves a batch of coarse decisions in one PDP round-trip
// (uncached — mirrors CheckMany; used for list filtering).
func (r *RBAC) AllowCoarseMany(ctx context.Context, resources []Resource, action openapi.AclOperation) ([]bool, error) {
    checks := make([]CheckRequest, len(resources))
    for i, resource := range resources {
        checks[i] = CheckRequest{Resource: resource, Action: action}
    }
    return r.CheckMany(ctx, checks)
}
```
- [x] **Step 4: Run — expect PASS.** `GOWORK=off go test ./pkg/rbac/ -run TestRBACImplementsCoarseEngine -v`
- [x] **Step 5: Export `CoarseForbidden`.** Rename `coarseForbidden`→`CoarseForbidden` in `pkg/rbac/engine.go` (engine.go:244) and update its in-package call sites (`allowCoarse` etc.). Run `GOWORK=off go test ./pkg/rbac/...` — expect green.
- [x] **Step 6: Pre-commit checklist + stage.** `GOWORK=off make generate lint test-unit` (from uni-identity), then `git add pkg/rbac/coarse_engine.go pkg/rbac/coarse_engine_test.go pkg/rbac/engine.go` (+ any `capturePDP` extension). No commit.

---

## Task 3: Remote adapter (`RemoteEngine` over `CheckMany`)

**Files:**
- Create: `pkg/middleware/openapi/remote/engine.go`
- Create: `pkg/middleware/openapi/remote/engine_test.go`

**Interfaces:**
- Consumes: `rbac.CoarseEngine`, `rbac.Resource`, `rbac.ErrPolicyDenied`, `rbac.ErrDecisionUnavailable`; local `Authorizer.CheckMany(ctx, []CheckRequest) ([]bool, error)` (decision.go:68) with `authorizer.Resource`/`CheckRequest`.
- Produces: `type RemoteEngine struct{ authorizer *Authorizer }`; `func NewRemoteEngine(a *Authorizer) *RemoteEngine`; it satisfies `rbac.CoarseEngine`. `func (a *Authorizer) RemoteDecisionEngine() rbac.CoarseEngine` returning `NewRemoteEngine(a)`.

- [x] **Step 1: Write the failing test** — `engine_test.go`: with a fake `Authorizer.CheckMany` returning `[]bool{true}` → `AllowCoarse` returns nil; returning `[]bool{false}` → `errors.Is(err, rbac.ErrPolicyDenied)`; returning `(nil, ErrDecisionUnavailable)` → `errors.Is(err, rbac.ErrDecisionUnavailable)`; and `AllowCoarseMany([x,y])` returns the batch verdicts in order. Assert `var _ rbac.CoarseEngine = (*RemoteEngine)(nil)`.
- [x] **Step 2: Run — expect FAIL.** `GOWORK=off go test ./pkg/middleware/openapi/remote/ -run TestRemoteEngine -v`
- [x] **Step 3: Implement** `engine.go` — translate `rbac.Resource` → `authorizer.Resource`, call `CheckMany`, and map results with the SAME mapping the local `coarseForbidden` uses:
```go
func (e *RemoteEngine) AllowCoarseMany(ctx context.Context, resources []rbac.Resource, action openapi.AclOperation) ([]bool, error) {
    checks := make([]CheckRequest, len(resources))
    for i, r := range resources {
        checks[i] = CheckRequest{Resource: Resource(r), Action: action} // field-identical DTOs
    }
    return e.authorizer.CheckMany(ctx, checks)
}

func (e *RemoteEngine) AllowCoarse(ctx context.Context, resource rbac.Resource, action openapi.AclOperation) error {
    allowed, err := e.AllowCoarseMany(ctx, []rbac.Resource{resource}, action)
    if err != nil {
        return rbac.CoarseForbidden(resource, action, err) // preserves ErrDecisionUnavailable
    }
    if !allowed[0] {
        return rbac.CoarseForbidden(resource, action, fmt.Errorf("%w: operation '%s' on '%s'", rbac.ErrPolicyDenied, action, resource.Kind))
    }
    return nil
}
```
  NOTE: `rbac.CoarseForbidden` is exported in Task 2 — consume it here. If the `Resource(r)` conversion fails (field order differs between `rbac.Resource` and `authorizer.Resource`), map the four fields explicitly.
- [x] **Step 4: Run — expect PASS.** Same command.
- [x] **Step 5: Pre-commit + stage.** No commit.

---

## Task 4: Per-call timeout on the remote check (guardrail essential)

**Files:**
- Modify: `pkg/middleware/openapi/remote/authorizer.go` — add a `checkTimeout time.Duration` field to `Authorizer`; add a functional-option mechanism and make the constructor variadic; default the timeout.
- Modify: `pkg/middleware/openapi/remote/decision.go` — `CheckMany` wraps the call in `context.WithTimeout(ctx, a.checkTimeout)`.
- Create: `pkg/middleware/openapi/remote/decision_timeout_test.go`

**Scope note (grounded 2026-07-14):** The authorizer's two options structs — `identityclient.Options` (a type ALIAS for `coreclient.HTTPOptions`) and `coreclient.HTTPClientOptions` — both live in **uni-core**, and identity itself uses the *local* authorizer (it builds no remote authorizer), so there is **no uni-identity home to register a `--authorization-check-timeout` flag**. This task therefore delivers only the *mechanism* + a safe default. Registering the flag and passing `WithCheckTimeout(flagValue)` is a **consumer** concern (Tasks 10–12), where the remote authorizer is actually constructed. The 250ms default guarantees a hard deadline even before a consumer wires the flag.

**Interfaces:**
- Produces:
  ```go
  const defaultCheckTimeout = 250 * time.Millisecond
  type Option func(*Authorizer)
  func WithCheckTimeout(d time.Duration) Option // sets a.checkTimeout = d
  func NewAuthorizer(client client.Client, options *identityclient.Options, clientOptions *coreclient.HTTPClientOptions, opts ...Option) (*Authorizer, error)
  ```
  `NewAuthorizer` sets `a.checkTimeout = defaultCheckTimeout` BEFORE applying `opts` (so `WithCheckTimeout` overrides). Making it variadic is backward-compatible — every existing 3-arg caller (uni-region/compute/kubernetes/auth0 + in-repo tests) still compiles untouched. `CheckMany` applies the hard per-call deadline; a `context.DeadlineExceeded` surfaces through the existing transport-error mapping as `ErrDecisionUnavailable`.

- [x] **Step 1: Write the failing test** (`decision_timeout_test.go`) — stand up a fake identity HTTP server that sleeps ~500ms before responding; build the authorizer with `WithCheckTimeout(50 * time.Millisecond)` (reuse the existing `createRemoteAuthorizer`/`newCheckAuthorizer` test helpers, extended to pass the option); assert `CheckMany` returns in well under 500ms and `errors.Is(err, authorizer.ErrDecisionUnavailable)`.
- [x] **Step 2: Run — expect FAIL** (`GOWORK=off go test ./pkg/middleware/openapi/remote/ -run Timeout -v`): no timeout today, so the call blocks ~500ms.
- [x] **Step 3: Implement** — add the `Option` type, `WithCheckTimeout`, the `checkTimeout` field, the variadic constructor with the `defaultCheckTimeout` default; then in `CheckMany`, before building the client:
```go
if a.checkTimeout > 0 {
    var cancel context.CancelFunc
    ctx, cancel = context.WithTimeout(ctx, a.checkTimeout)
    defer cancel()
}
```
  Keep the existing transport-error → `ErrDecisionUnavailable` mapping (`decision.go` already maps a client error that way; `context.DeadlineExceeded` surfaces through it).
- [x] **Step 4: Run — expect PASS**; then `GOWORK=off go test ./pkg/middleware/openapi/remote/ ./pkg/rbac/` to confirm no regression (existing 3-arg `NewAuthorizer` callers still green).
- [x] **Step 5: Pre-commit + stage.** No commit.

---

## Task 5: Remote engine context + mode

**Files:**
- Create: `pkg/rbac/remote_engine.go` (the context/mode half), `pkg/rbac/remote_engine_test.go`

**Interfaces:**
- Produces:
  ```go
  type RemoteMode int
  const ( RemoteOff RemoteMode = iota; RemoteShadow; RemoteEnforce )
  func NewRemoteEngineContext(ctx context.Context, engine CoarseEngine, mode RemoteMode) context.Context
  func remoteEngineFromContext(ctx context.Context) (CoarseEngine, RemoteMode) // (nil, RemoteOff) if none
  func ParseRemoteMode(s string) (RemoteMode, error) // "off"|"shadow"|"enforce"
  ```
  Uses a new unexported context key (mirror `engineKey`, engine.go:88).

- [x] **Step 1: Write the failing test** — round-trip: a context seeded with `(fakeEngine, RemoteEnforce)` returns them; an unseeded context returns `(nil, RemoteOff)`; `ParseRemoteMode` maps the three strings and errors on junk.
- [x] **Step 2: Run — expect FAIL.**
- [x] **Step 3: Implement** the mode enum, context key, seed/read functions, and parser. Mirror `NewEngineContext`/`EngineFromContext` exactly (engine.go:88-106).
- [x] **Step 4: Run — expect PASS.**
- [x] **Step 5: Pre-commit + stage.** No commit.

---

## Task 6: Dispatch arm — `dispatchCoarse` + wire the 3 forks (enforce path)

**Files:**
- Modify: `pkg/rbac/handler.go` (the 3 forks at ~58-61, ~108-112, ~173-179), add `dispatchCoarse` to `remote_engine.go`.
- Create: `pkg/rbac/remote_dispatch_test.go`

**Interfaces:**
- Consumes: `remoteEngineFromContext`, `engineForDispatch` (engine.go:144), `shadowed` (shadow.go), the `allow*Legacy` functions, `remoteShadowed` (Task 7).
- Produces: `func dispatchCoarse(ctx, resource Resource, operation openapi.AclOperation, legacy func() error) error`.

- [x] **Step 1: Write the failing test** (mirror `engine_cutover_test.go`): remote engine seeded in `RemoteEnforce` with a deny-PDP over a GRANTING ACL ⇒ `AllowGlobalScope`/`AllowProjectScope` return `IsForbidden` + `errors.Is(ErrPolicyDenied)`, and the legacy walk is NOT consulted (assert via a legacy-walk spy or a granting ACL that would allow). Remote enforce + unavailable PDP ⇒ `errors.Is(ErrDecisionUnavailable)` (fail-closed, no legacy fallback). Remote `off` ⇒ identical to today (legacy/local path unchanged).
- [x] **Step 2: Run — expect FAIL.**
- [x] **Step 3: Implement** `dispatchCoarse`:
```go
func dispatchCoarse(ctx context.Context, resource Resource, operation openapi.AclOperation, legacy func() error) error {
    if engine, mode := remoteEngineFromContext(ctx); engine != nil {
        switch mode {
        case RemoteEnforce:
            return engine.AllowCoarse(ctx, resource, operation) // authoritative, fail-closed
        case RemoteShadow:
            return remoteShadowed(ctx, engine, resource, operation, legacy())
        }
    }
    if engine := engineForDispatch(ctx, resource.Kind); engine != nil {
        return engine.allowCoarse(ctx, resource, operation)
    }
    return shadowed(ctx, resource, operation, legacy())
}
```
  Rewrite the 3 forks to call it, e.g. `AllowProjectScope`:
```go
return dispatchCoarse(ctx, Resource{Kind: endpoint, OrganizationID: organizationID, ProjectID: projectID}, operation,
    func() error { return allowProjectScopeLegacy(ctx, endpoint, operation, organizationID, projectID) })
```
  (`remoteShadowed` may be a temporary stub returning `legacyErr` until Task 7 — keep this task's tests to `off`/`enforce`.)
- [x] **Step 4: Run — expect PASS; then `GOWORK=off go test ./pkg/rbac/...` to confirm all existing dispatch/cutover/shadow tests still pass** (local path unchanged).
- [x] **Step 5: Pre-commit + stage.** No commit.

---

## Task 7: `remoteShadowed` comparator (shadow path)

**Files:**
- Modify: `pkg/rbac/remote_shadow.go` — replace the Task-6 stub with the real `remoteShadowed`; add the message constants **here** (mirroring `shadow.go`, which keeps its own `shadowDivergenceMessage`/`shadowFailureMessage` self-contained). Do NOT modify `remote_engine.go` or `decision_log.go`.
- Create: `pkg/rbac/remote_shadow_test.go`

**Interfaces:**
- Keep the existing stub signature: `func remoteShadowed(ctx context.Context, engine CoarseEngine, resource Resource, operation openapi.AclOperation, legacyErr error) error`. It **serves `legacyErr`** (return value unchanged from the stub), and evaluates `engine.AllowCoarse(ctx, resource, operation)` alongside, logging:
  - `remoteShadowDivergenceMessage = "remote shadow divergence"` when a remote VERDICT was obtained and differs from legacy;
  - `remoteShadowFailureMessage = "remote shadow evaluation failure"` when NO remote verdict was obtained.
  Both constants are NEW and DISTINCT from the `cerbos shadow …` ones (a divergence gate greps them separately).
- **Reuse `shadow.go`'s helpers** — `shadowAttrs(ctx, resource, operation, legacyAllowed)` (endpoint/legacy_verdict/subject/etc., credential-free), `shadowVerdict`, `shadowClass` — and add the field `"remote_verdict"` (parallel to `cerbos_verdict`). **No `policy_hash`**: the remote `CoarseEngine` adapter has no local policy hasher (the policy lives at identity), so omit that field.
- **Verdict mapping:** `err == nil` ⇒ remote allow (a verdict); `errors.Is(err, ErrPolicyDenied)` ⇒ remote deny (a verdict); anything else (`ErrDecisionUnavailable`/unclassified) ⇒ NO verdict ⇒ the failure message (never divergence — the gate must not be poisoned by an outage). Compare the remote verdict against `legacyErr == nil`.
- **LOAD-BEARING safety (mirror `shadowCompare`):** wrap the evaluation in a `recover()` so a panicking remote engine (or a bug here) is a log line, NEVER a request failure — shadow mode must serve `legacyErr` regardless. This is the zero-behaviour-change contract for shadow.

- [x] **Step 1: Write the failing test** (`remote_shadow_test.go`, mirror the identity shadow tests + the `logCapture` helper): legacy-allow / remote-deny ⇒ served result is the **legacy allow**, and exactly one `remote shadow divergence` record with `legacy_verdict=allow`, `remote_verdict=deny`, `endpoint=<kind>`. Remote-unavailable ⇒ served legacy, one `remote shadow evaluation failure`, **zero** divergence records. (Use a fake `CoarseEngine` returning nil / `ErrPolicyDenied` / `ErrDecisionUnavailable`.)
- [x] **Step 2: Run — expect FAIL.**
- [x] **Step 3: Implement** `remoteShadowed` per the interfaces above.
- [x] **Step 4: Run — expect PASS; then `GOWORK=off go test ./pkg/rbac/...`** to confirm the whole suite (incl. the Task-6 dispatch tests, which currently exercise the stub) stays green.
- [x] **Step 5: Pre-commit + stage.** No commit.

---

## Task 8: Seed the remote engine at the middleware point

**Files:**
- Modify: `pkg/middleware/openapi/decision_engine.go` (add interface), `pkg/middleware/openapi/openapi.go` (~518-529 seed block), `pkg/middleware/openapi/remote/authorizer.go` (carry the mode; implement the provider).
- Create/modify: `pkg/middleware/openapi/openapi_test.go` (seed assertion).

**Interfaces:**
- Produces:
  ```go
  type RemoteDecisionEngineProvider interface { RemoteDecisionEngine() rbac.CoarseEngine; RemoteEngineMode() rbac.RemoteMode }
  ```
  implemented by `remote.Authorizer`; the mode comes from a new construction option `WithRemoteEngineMode(rbac.RemoteMode)` (a `remoteMode` field on the authorizer, consumed by Task 10). Seed block, sibling to the existing `DecisionEngineProvider` block:
  ```go
  if provider, ok := v.authorizer.(RemoteDecisionEngineProvider); ok {
      if engine := provider.RemoteDecisionEngine(); engine != nil {
          ctx = rbac.NewRemoteEngineContext(ctx, engine, provider.RemoteEngineMode())
      }
  }
  ```

- [x] **Step 1: Write the failing test** — a validator built with a remote authorizer in `enforce` mode seeds a context where `remoteEngineFromContext` (exercised via a test that runs a handler `Allow*`) routes to the remote engine. (Reuse the middleware test harness; assert via a handler that calls `AllowGlobalScope` and observing the remote engine was consulted.)
- [x] **Step 2: Run — expect FAIL.**
- [x] **Step 3: Implement** the interface, the `WithRemoteEngineMode` option + `remoteMode` field + the provider methods (`RemoteDecisionEngine`/`RemoteEngineMode`) on `remote.Authorizer`, and the seed block. `local.Authorizer` does NOT implement it (unchanged — identity keeps its local engine).
- [x] **Step 4: Run — expect PASS; run `./pkg/middleware/...`.**
- [x] **Step 5: Pre-commit + stage.** No commit.

---

## Task 9: Caller-side decision telemetry

**Files (grounded 2026-07-14 — the plan's original `pkg/rbac` placement was wrong):**
- Modify: `pkg/middleware/openapi/remote/engine.go` — instrument `RemoteEngine.AllowCoarse`/`AllowCoarseMany` (the caller-side path).
- Create: `pkg/middleware/openapi/remote/metrics.go` (the otel instruments + a credential-free decision-log helper), `pkg/middleware/openapi/remote/metrics_test.go`.
- Do NOT touch `pkg/rbac` — `RemoteEngine` lives in the `remote` package, and `pkg/rbac`'s A10 already records the SERVER-side decision for a remote `/authorization/check` call (it funnels through identity's `CheckMany` choke point). This task is the distinct **caller-side** view.

**Scope note:** caller-side = the CONSUMER's view of the remote round-trip — network latency and consumer-observed outcome (allow/deny/unavailable), which the server-side A10 cannot measure and which cut #2's circuit breaker will consume. Not redundant with A10.

**Interfaces:**
- Mirror `pkg/rbac/decision_log.go`'s `newDecisionInstruments` idiom: `otel.Meter(constants.Application)`, no-op-safe (`_ =` the config error), **exports only with `--otlp-endpoint`**.
  ```go
  // Int64Counter "unikorn_identity_authz_remote_decision_total", WithUnit("{decision}"), attribute outcome=allow|deny|unavailable
  // Float64Histogram "unikorn_identity_authz_remote_decision_latency", WithUnit("s"),
  //   round-trip buckets (larger than A10's localhost-gRPC pdp_latency — a cross-service hop): e.g. 0.005..5s
  ```
- Recorded in `AllowCoarse`/`AllowCoarseMany` around the `CheckMany` round-trip: **one latency observation per call**; **counter incremented per check outcome** (`nil`→allow, `errors.Is(ErrPolicyDenied)`→deny, else→unavailable). For the batch method, one latency obs + N counter increments.
- A credential-free decision-log line via `log.FromContext(ctx)`: resource kind, operation, org/project, decision, `source="remote"`, latency (+ the acting subject only if cleanly readable — NO tokens/claims/passports). **Level convention mirrors A10:** denies/unavailable at `Info`, allows at `V(1)` (deny-focused default stream, no per-allow spam). `pkg/rbac`'s `decisionSubject`/`decisionVerdict` are unexported — add a minimal local renderer here rather than exporting them.

- [x] **Step 1: Write the failing test** (`metrics_test.go`) — with a fake identity server returning allow / deny / 5xx, assert the counter increments with the correct `outcome` for each, one latency observation per call, and a deny emits the Info-level log line (reuse a `logCapture`-style helper). Use an in-memory otel meter reader if the repo has one; else assert via the log line + a thin seam.
- [x] **Step 2: Run — expect FAIL.**
- [x] **Step 3: Implement** mirroring `decision_log.go`.
- [x] **Step 4: Run — expect PASS; then `GOWORK=off go test ./pkg/middleware/openapi/...`.**
- [x] **Step 5: Pre-commit + stage.** No commit.

---

## Task 9b: Remote-engine impersonation trigger (identity-side; "Fix B")

**Corrected 2026-07-15** — supersedes the original force-on-`User` "Option A" (retained note at the end), which the grounding in `docs/downstream-remote-authorization-design.md` §4.3/§7 showed to be wrong.

**Decision.** Impersonate on the outbound `CheckMany` based on the **authenticated subject** (`authorization.Info`), NOT on the propagated principal's type. Rationale (design §4.3): the cert-relay (`Unikorn-Client-Certificate`) conveys the original caller to `/authorization/check`, so a **system-account (mTLS) caller is resolved directly** — forcing impersonation there would wrongly compute `intersect(user, caller)` and deny service-privilege ops the caller holds but the propagated user lacks (e.g. `compute→region:servers`). A **bearer caller** cannot be conveyed by cert (the check endpoint is mTLS-only and drops the bearer), so it must be impersonated to be resolved as the user (`intersect(user, consumer-service)`; needs the consumer-superset provisioning — "Fix A", Task 10). An inbound `X-Impersonate` (a caller already delegating) flows through unchanged. Scoped to the `CheckMany` call — reached only from `Allow*` dispatch, long after the middleware fetched the ACL via `GetACL` on the unmarked context — so `GetACL` and the shadow legacy baseline stay untouched.

**File:** `pkg/middleware/openapi/remote/engine.go` — in `AllowCoarseMany` (the choke point), replace the `principal.FromContext(ctx).Type == identityapi.User` block with:
```go
if info, err := authorization.FromContext(ctx); err == nil && info != nil && !info.SystemAccount {
    ctx = principal.NewImpersonateContext(ctx)
}
```
Marks impersonation for any bearer-authenticated caller (User or Service token), leaves system-account (mTLS) callers on attribution-only, and respects any inbound `X-Impersonate` (only ADDS marking, never strips). Add the `pkg/middleware/authorization` import. Mirrors identity's own `getSystemAccountACL` branch (`rbac.go:1029-1056`).

- [x] Step 1: rewrite the impersonation test to drive `authorization.Info`: (a) bearer caller (`SystemAccount:false`) → outbound `X-Impersonate: true`; (b) system-account caller (`SystemAccount:true`), no inbound flag → none; (c) system-account caller with an inbound `X-Impersonate` → flows through (idempotent).
- [x] Step 2: run — expect FAIL (current code keys off `principal.Type`).
- [x] Step 3: implement the trigger above.
- [x] Step 4: `GOWORK=off go test ./pkg/middleware/openapi/... ./pkg/rbac/...` → PASS.
- [x] Step 5: pre-commit + stage. No commit.

**Superseded note (force-on-`User`, 2026-07-14):** the original decision keyed impersonation off `principal.FromContext(ctx).Type == identityapi.User`, marking it in the shared remote engine (scoped to `CheckMany`, leaving `GetACL`/the shadow baseline untouched). The grounding showed `X-Principal` carries the user as attribution on attributed s2s too, so that forces `intersect(user, caller)` and wrongly denies service-privilege ops — see design §7. Replaced by the `authorization.Info`-keyed trigger above.

---

## Task 10: `uni-region` wiring + role provisioning (pilot, shadow)

**Status (2026-07-15): done.** uni-region Go wiring + chart committed (uni-region repo); identity `region-service` `region:*` superset = **Fix A** (`3e6254d3`). Verified via the workspace overlay (`go build ./...` + `pkg/server` tests + `helm lint` green). Step 5's `GOWORK=off make` checklist runs only once identity's seam is released and uni-region bumps `go.mod` (its `v1.17.8` pin predates the seam).

**Files (uni-region unless noted):**
- Modify: `pkg/server/options.go` (add `--authorization-engine-mode`, values `off|shadow|enforce`, default `off`), `pkg/server/server.go:~147-152` (pass the parsed mode into the remote authorizer construction), the chart `values.yaml` + `templates/.../deployment.yaml` (render the flag).
- Modify (uni-identity chart): the Helm values that map system-account CN→role — add `uni-region`'s CN with a role covering its endpoints.

**Interfaces:**
- Consumes: `remote.WithMode`/construction option added in Task 8; `rbac.ParseRemoteMode` (Task 5).
- Produces: a deployable `uni-region` whose remote authorizer is built with the configured mode; default `off` = today's behavior (reversible).

- [x] **Step 1: Read** `uni-region/pkg/server/server.go` around the `NewAuthorizer`/`NewValidator` wiring and its options plumbing; follow the existing flag pattern.
- [x] **Step 2: Write the failing test** — a server-options unit test: `--authorization-engine-mode=shadow` parses to `rbac.RemoteShadow`; unset defaults to `RemoteOff`; junk errors.
- [x] **Step 3: Run — expect FAIL.**
- [x] **Step 4: Implement** the flag, thread it into the authorizer construction, render it in the chart, and add the `uni-region` CN→role mapping in the identity chart values.
- [x] **Step 5: Run — expect PASS**; `GOWORK=off make lint test-unit generate` in uni-region; `helm template` renders the flag only when set.
- [x] **Step 6: Stage for review** (uni-region + identity chart). No commit.

---

## Task 11: `uni-region` cross-service kind e2e + downstream divergence gate

**Status (2026-07-16): committed (`bf3b3a5`); kind run deferred to CI.** The admin/user shadow RBAC matrix (`test/api/suites/rbac_matrix_test.go`) + `hack/ci/divergence-gate` are committed and reviewed (`go vet -tags integration` clean). **Scoped to shadow-only** — fail-closed + timeout are `enforce` behaviors (unit-covered by Tasks 4/6, deferred to the flip; they'd contradict a shadow deploy). Steps 3–4 (the kind run + the empirical 0-divergence result) are **deferred to CI/Linux**: the local Colima run is blocked by kind LoadBalancer routing (LB IPs on the Docker bridge inside the VM aren't reachable from the macOS host — see [[project-local-shadow-integration-run]]). The `unikorn-region`→`region-service` CN mapping needed no identity edit (already in chart defaults).

**Files (uni-region):**
- Modify/create: `hack/ci/install` deps (install identity via `../identity/hack/ci/install`), `hack/ci/test-values.yaml` (`authorizationEngineMode: shadow`; the CI system-account CN→role), `hack/ci/divergence-gate` (read the **uni-region** server logs for `remote shadow divergence`), `test/e2e/rbac_matrix_test.go`.

**Interfaces:** Consumes the Task 10 flag + Task 7 divergence message. Produces a green cross-service run proving parity, then readiness to flip.

- [x] **Step 1: Read** the kind CI strategy + uni-region's `hack/ci/*` and `test/api/` (its integration tests live under `test/api/suites/`, not `test/e2e/`).
- [x] **Step 2: Write the e2e** (BDD, typed client): admin/user RBAC matrix in `shadow`, asserting bodies + statuses. **Scoped to shadow-only** — fail-closed + timeout are `enforce` behaviors, unit-covered by Tasks 4/6 and deferred to the flip.
- [ ] **Step 3: Run the pipeline** on kind: `GOWORK=off make integration-test` (region). **Deferred to CI/Linux** — the local Colima run is blocked by kind LB routing (see status + [[project-local-shadow-integration-run]]).
- [ ] **Step 4: Run the divergence gate** — assert **zero** `remote shadow divergence`. **Pends the Step 3 run**; the empirical parity answer is still outstanding.
- [x] **Step 5: Committed** (`bf3b3a5`) after review. **Flip to `enforce` is a gated follow-up.**

---

## Task 12a: `uni-compute` wiring + Fix A (shadow)

**Rescoped (2026-07-17):** "repeat 10–11" split unevenly — compute's e2e is a *greenfield* CI build (no `hack/ci/`, no multi-principal/mTLS harness, a two-level identity→region→compute install) that can't run locally (Colima LB wall) and is CI-gated. So Task 12 is now **12a (wiring + Fix A)** here; **12b (the e2e/CI harness)** is deferred to a unified downstream-e2e follow-up (see Out of scope). Compute's shadow parity is validated by a **manual soak** (deploy in shadow, drive real traffic incl. compute→region, grep for `remote shadow divergence`), which — unlike the kind e2e — works on Colima.

**Files:**
- Identity: `charts/identity/values.yaml` `compute-service` role — add the **`compute:*` superset** (`compute:instances`/`clusters` [CRUD] + `compute:regions`/`flavors`/`images` [read] at global scope): the **Fix A analogue** for compute, else direct-user compute ops diverge. CN→role (`unikorn-compute`→`compute-service`) is already in defaults (`values.yaml:164`).
- uni-compute: `pkg/server/server.go` (fields + flags + `remoteAuthorizerOptions` helper + thread into `NewAuthorizer` ~`:153`; flags in `AddFlags`, NOT the dead `options.go`; `GetServer(client)` has no ctx — no signature change), the chart (`charts/compute/templates/server/deployment.yaml` + `values.yaml`; dir is `templates/server/`), and a flag-parse unit test (`server_test.go`/`export_test.go`, mirroring region's Task 10).

- [x] **Step 1: Fix A** — `compute-service` `compute:*` superset (identity `1e75c435`; cerbos generate testdata regenerated to match).
- [x] **Step 2: Wire** — flags + helper + thread-in + chart + flag-parse unit test (uni-compute `9d742b5`, `cerbos-integration`).
- [x] **Step 3: Verified** (go.work ON) — `pkg/server` build/vet/test + cerbos-generate + rbac tests pass; `helm template` renders the flags and the `compute:*` grants. **Shadow parity pends a manual soak** (kind e2e is 12b, deferred). NB: compute's *whole-repo* build has a pre-existing region-ID skew (`regionids.MustParse*ID` relocated by region `c9be20c`), unrelated to this task.

---

## Out of scope (follow-ups, not this plan)

- Full **circuit breaker** (`failsafe-go@0.9.6`, already in the module graph) — cut #2, before broad `enforce`.
- **`uni-kubernetes`** adoption — cut #3.
- **Unified downstream e2e/CI harness** ("Task 12b" + kubernetes) — the kind-based cross-service RBAC-matrix + divergence-gate for `uni-compute` (and later `uni-kubernetes`), built *once* as a shared harness rather than greenfield-per-service. Deferred: it can't run locally (Colima LB) and is CI-gated on the identity seam release; per-service shadow parity is validated by manual soak until then.
- Public **`rbac.AllowMany` list facade** wiring — added when the first per-resource ABAC list needs it (interface is already batch-native; §4.6).
- Remote paths for `AllowProjectScopeCreate*` (A19 create) and `AllowRole` (A16).
- The actual **`shadow`→`enforce` flip** per service (operational config change, gated on zero divergence).
