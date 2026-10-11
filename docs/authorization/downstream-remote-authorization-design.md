# Downstream remote authorization: adopting identity's central PDP

- **Date:** 2026-07-14
- **Status:** Proposed. Programme status is tracked in Linear, on the ID team.
- **Scope:** The authorization decision path of the downstream services, `uni-region` and
  `uni-compute` in this cut. Section 1 carries the full in-scope and out-of-scope lists.

This design implements the **"Central PDP First"** rollout: identity owns a single central Cerbos
PDP, which downstream services consume decisions from rather than running per-service sidecars. It
is the **downstream half** of the central-PDP authorization work. The identity-side half already
delivered `POST /api/v1/authorization/check` (`pkg/handler` `PostApiV1AuthorizationCheck`) and its
batched client (`pkg/middleware/openapi/remote` `CheckMany`); no consumer calls it yet. It extends
`cerbos-authorization-design.md`.

## 1. Goal

Route the authorization decisions of downstream services (`uni-region`, `uni-compute` in this cut)
through identity's central Cerbos PDP via `POST /authorization/check`, instead of each service
evaluating a fetched ACL locally, **with minimal consumer churn** and the mandatory Phase-1
resilience essentials, rolled out **shadow-first** so the cutover is proven before it enforces.

### In scope
- The identity-side **remote decision seam** (`pkg/rbac` + `pkg/middleware/openapi`).
- Guardrail **essentials**: hard per-call timeout, fail-closed, caller-side decision telemetry.
- **Shadow-first** downstream rollout on **`uni-region`** and **`uni-compute`** (serve the legacy
  verdict, evaluate the remote check alongside, log divergence, flip per service once clean).

### Out of scope (explicit follow-ups)
- The full **circuit-breaker** profile (`failsafe-go`): a follow-up, before broad enforce.
- **`uni-kubernetes`** adoption: a later follow-up.
- `AllowRole` remote enforcement (the grantability cross-parity): it intentionally stays on its
  existing thin-Go path.

## 2. Current state (verified)

- `uni-region` (~11 handler files), `uni-compute` (2), `uni-kubernetes` (1) import
  `github.com/unikorn-cloud/identity/pkg/rbac` and call `rbac.Allow*` at ~65 sites.
- They wire the **remote** authorizer (`remote.NewAuthorizer` → `openapi.NewValidator`), which does
  **not** implement `DecisionEngineProvider`. So no engine is seeded and **every `Allow*` call today
  takes the legacy ACL-walk path** (`allow*Legacy`, fed by `GetACL`). Downstream authz is therefore
  *local evaluation of the user's ACL as returned by `GetACL`*, not the central PDP.
- `uni-core` has **no** authorization surface (only ownership-assertion label helpers). Nothing here
  lands in `uni-core`.
- `CheckMany` is already a method on the same `*authorizer.Authorizer` the consumers construct; they
  simply hand it over as the narrower `openapi.Authorizer` interface and never call it.

## 3. Spec constraints that shape this design

From the Platform Architecture Specification:
- **§4.3**: authorization "is accessed **exclusively through the RBAC middleware library**
  (`identity/pkg/rbac`)." → We keep the facade and swap the engine underneath (Approach A). The facade
  exposes **both** a single-resource entry (`Allow*`) and a **batch** entry for list filtering; the
  batch entry dispatches to `CheckMany` so a list is **one round-trip for N resources, not N calls**
  (see §4.6). Both stay within `pkg/rbac`; only calling `CheckMany` *raw from handlers* (Approach B)
  would tension with this rule.
- **§2 / §4.3**: service-to-service auth is **mTLS**; the calling service's certificate **CN maps to
  an RBAC role**, configured in identity's Helm values at deploy time (not self-configured).
- **§4.6 / §4.6.1**: a service acting for a user propagates `X-Principal`; with `X-Impersonate: true`
  identity resolves RBAC against that user, and the effective ACL is
  **`intersection(user ACL, calling-service ACL)`** (anti-escalation).
- **§10.1**: ingress strips `X-Principal`/`X-Impersonate` from external requests (the trust boundary
  that makes header-based propagation safe); centralized decision telemetry is required.

## 4. Design

### 4.1 The seam (Approach A)

Introduce one small **exported**, **batch-native** interface in `pkg/rbac`:

```go
// CoarseEngine produces coarse (scope-level) allow/deny verdicts above binding
// resolution.  AllowCoarseMany is the primitive — one round-trip for N resources
// (list filtering); AllowCoarse is the single-resource convenience the Allow*
// facade uses.
type CoarseEngine interface {
    AllowCoarseMany(ctx context.Context, resources []Resource, action openapi.AclOperation) ([]bool, error)
    AllowCoarse(ctx context.Context, resource Resource, action openapi.AclOperation) error
}
```

- **Local** `*RBAC` already has the body: `AllowCoarseMany` wraps `RBAC.CheckMany`; `AllowCoarse` is
  the N=1 case over `allowCoarse` (preserving the decision cache + impersonation gate).
- **Remote** adapter (lives in `pkg/middleware/openapi/remote`, which may import `pkg/rbac`; no cycle
  since `pkg/rbac` imports neither `remote` nor `openapi`): both methods back onto the batched
  `authorizer.CheckMany` (single = N=1), translating `rbac.Resource` → `authorizer.Resource` and
  mapping to the existing sentinels: transport/`5xx`/nil/mismatch → `ErrDecisionUnavailable` (deny),
  a `false` verdict → `ErrPolicyDenied`. Mirrors `coarseForbidden`.

### 4.2 Seeding and dispatch

- A remote analog of the seeding provider, implemented by `remote.Authorizer`:
  ```go
  type RemoteDecisionEngineProvider interface { RemoteDecisionEngine() (rbac.CoarseEngine, RemoteMode) }
  ```
- Seed it at the **single existing middleware point** (`pkg/middleware/openapi/openapi.go:518-529`),
  as a sibling to the current `DecisionEngineProvider` block, via a new
  `rbac.NewRemoteEngineContext(ctx, engine, mode)`.
- **Dispatch** at the three existing forks (`handler.go:59-61,109-112,174-176`): consult the remote
  engine's **mode** ahead of the local-engine/legacy path. The remote path carries its own mode
  (mirrors the proven identity `EngineMode`), independent of `*RBAC`'s local mode/cutover/shadow
  machinery, which stays untouched. The remote and local engines are **mutually exclusive per
  deployment** (consumers seed the remote engine, identity keeps its local engine), so in the
  consumers this is simply remote-mode vs. legacy:

  | Remote mode | Behavior |
  |---|---|
  | `off` (not seeded) | legacy ACL walk (today's behavior) |
  | `shadow` | **serve the legacy walk** at once, call `AllowCoarse` remotely in the background, log any divergence |
  | `enforce` | remote is **authoritative** (no legacy fallback; fail-closed) |

  The `shadow` comparator is a downstream analog of `pkg/rbac/shadow.go` (`remoteShadowed`), emitting a
  distinct, greppable divergence message so a gate can assert zero divergence. The request does not
  wait for the remote call. In one process, at most `remoteShadowRunLimit` compares call identity at
  the same time, and up to `remoteShadowQueueLimit` more wait in a queue. Each compare has a backstop
  deadline (`remoteShadowBackstop`) from the time it gets a run slot. A check gets no remote call
  only when the run slots and the queue are full. Then the log has a `remote shadow compare skipped`
  line, which is neither divergence nor evaluation failure. `pkg/rbac/README.md` gives the values.

Consumer change: **one line in each `server.go`** to construct the service with the remote engine
mode from config. The ~65 `Allow*` sites are untouched.

### 4.3 Trust and principal semantics (load-bearing)

**Verified 2026-07-15.** Grounding in §7.

- **The cert-relay conveys the original caller.** `CheckMany` (like `GetACL`) relays the calling
  service's certificate in the `Unikorn-Client-Certificate` header (`CertificateRequestMutator` →
  `InjectClientCert`); identity's `ExtractClientCert` reads it with **priority over the TLS peer**
  (`clientcert.go:60-64`), so the check's authenticated subject is the **original caller** (e.g.
  `compute-service` for a `compute→region` call), not the consumer's own account
  (`region-service`), verified `openapi.go:238,251`. The middleware keeps the certificate out of
  the handler context, so that other calls from the handler do not relay it. It records the
  certificate in `authorization.Info.ClientCert`, and only `RemoteEngine` relays it.
- **The seam does NOT force impersonation.** The decision follows the **authenticated subject**. For
  a system-account caller it also follows the inbound `X-Impersonate` flag, mirroring identity's own
  `getSystemAccountACL` (`pkg/rbac/rbac.go`). A bearer caller's check carries the passport and never
  `X-Impersonate`:
  - **Attributed s2s** (system-account caller, no inbound flag) → decide against the **relayed caller
    alone** (`compute-service`). The propagated user rides `X-Principal` for **attribution/trace only**,
    never the decision. (Trusted-subsystem model.)
  - **Impersonated s2s** (inbound flag set) → `intersection(user, service)` per specification §4.6.1.
  - **Direct bearer user** → the user's own permissions, from the passport (see below).
- **Do not derive impersonation from "a User is present in `X-Principal`".** `X-Principal` carries the
  user as attribution on attributed s2s too; forcing impersonation there makes identity compute
  `intersect(user, caller)` and **wrongly denies** service-privilege ops the user lacks (e.g.
  `compute→region:servers`, where only `compute-service` holds `region:servers`). The trigger must key
  off `authorization.Info` (the authenticated subject), not the propagated principal's type.
- **Direct-user path: the passport.** A bearer user is not impersonated. The service exchanges the
  user's token at identity for a passport whose audience is the service's own certificate CN. The
  remote engine sends the raw passport in the body of the check. Identity verifies it and decides
  for the passport's subject, with no service role in between. The check carries no
  `X-Impersonate` header, because identity refuses the two together. The passport goes back to
  identity only, on this one call. Attributed s2s does not depend on this, because it resolves the
  caller.
- **Rejected, `intersection(caller-service, receiver-service)`:** an anti-escalation cap (bound the
  caller by the relaying receiver's own role) was considered and dropped. Revisit only to reduce
  trust in the relayer below the "trust the channel" model (specification §10.1).

### 4.4 Guardrail essentials

- **Hard per-call timeout:** ✅ landed as the `WithCheckTimeout` option (default
  **250ms**, within the plan's 100-300ms), applied as `context.WithTimeout` around `CheckMany`. Note it is a
  construction-time option, **not** the proposed `--authorization-check-timeout` flag: consumers get
  the bounded deadline with no configuration, and there is no operator knob to misset.
- **Fail-closed:** ✅ the behavior throughout (`ErrDecisionUnavailable` on any transport/server
  error), and explicitly tested.
- **Caller-side decision telemetry:** ✅ a decision counter and latency histogram keyed by
  endpoint/operation/decision/class, plus a decision log line, complementing identity's server-side
  decision log (`pkg/middleware/openapi/remote/metrics.go`).
- **Circuit breaker:** ✅ landed in the seam release, which also promoted `failsafe-go@0.9.6` from a
  transitive dependency (via the Cerbos SDK) to a **direct** one. Breaker state transitions are
  logged and counted. Of the intended breaker + timeout + bounded retry, the first two shipped;
  **bounded retry is deliberately deferred**, since the breaker already removes the timeout pileup
  that motivated it.

### 4.5 Rollout and reversibility

- Per-service config selects the remote mode (`off` | `shadow` | `enforce`); **`off` is the default
  and the instant rollback** (reverts to today's local ACL walk).
- Deploy order: identity with `cerbos.enabled: true` → then the service. The decision endpoint
  always asks the PDP, so it needs the sidecar even while identity's own engine is `legacy`. The
  `X-Principal` issuer does not constrain the order: identity reads a header without one as it did
  before issuer propagation.
- Deploy order for the passport path: identity with passport support on the check first, then the
  services. A service whose library sends the passport against an older identity gets no verdict.
  The older identity ignores the unknown body field, and the response has no `passportSubject`.
  The library requires that echo and fails closed. That failure does not count toward the circuit
  breaker, so the service's system-account checks still get verdicts from the older identity. Before
  you roll identity back past this change, set every service's remote mode to `off`.
- A cached passport can reach a handler with about 10 s of life left, because the token cache drops
  an entry 10 s before the passport expires. Identity accepts a passport for 5 s after it expires.
  So a check that a handler sends more than about 15 s after authentication can get a 401 and no
  verdict. In `shadow`, the downstream log has the same `remote shadow evaluation failure` line for a
  401, a 503 and an echo failure. Identity's own log shows each refused passport and its cause (the
  `error detail` line), so count the late-passport 401s there.
- Gate each service on its own. A mixed fleet, where some services are in `enforce` and some in
  `shadow`, is a normal state during rollout.
- Sequence per pilot service: deploy in `shadow` → run traffic / RBAC matrix → confirm **zero
  divergence** (fix provisioning if not) → flip to `enforce` → keep `off` as rollback.

### 4.6 List endpoints: one batched call, never N

Routing the *single-check* facade remotely would be pathological for per-resource list filtering
(N round-trips per list). It isn't, because list authorization is not N single checks:

- **Scope + query-scoping (the common case, and what region/compute do today):** one coarse
  `Allow*` scope gate, then push org/project filters to storage via `rbac.AddQuery` /
  `AddOrganizationIDQuery` (built from the ACL `GetACL` already returns). One coarse check +
  storage-side filtering: unaffected by the remote engine, **zero per-resource calls**. Coarse
  verdicts are cached, so even a small per-scope loop (e.g. `region/handler/image/query.go`) does not
  multiply network calls.
- **Per-resource ABAC filtering (only where a kind needs it):** fetch the page, then a **single
  batched** `AllowCoarseMany` for the whole page (one round-trip for N resources), return only
  allowed records. Exposed as a **batch method on the `pkg/rbac` facade** (so it stays compliant with specification §4.3,
  never a raw handler call, never N single calls).

This cut's region/compute lists all use query-scoping, so **no list handler is rewritten**; the batch
facade is provided (it is just the existing `CheckMany`) for any per-resource ABAC list going forward.

## 5. Testing (per the kind integration-testing strategy)

- **Cross-service kind e2e** (composable install units): a consumer's CI installs identity via
  `../identity/hack/ci/install`, then the service; run the **two-principal RBAC matrix**
  (`test/e2e/rbac_matrix_test.go`) asserting decisions route through the check endpoint.
- **Shadow divergence gate** for the pilot: adapt `hack/ci/divergence-gate` to read the *consumer's*
  server logs and fail on any `remote shadow divergence` after the matrix runs. Also count
  `remote shadow compare skipped` lines, because a skipped check was not compared.
  If the engine call honours its context, a full queue takes up to
  `remoteShadowQueueLimit / remoteShadowRunLimit` times the shorter of the check timeout and
  `remoteShadowBackstop` to drain. The gate must wait at least that long after the last request,
  plus a margin, before it reads the logs.
- **Fail-closed test:** identity unavailable ⇒ mutating/privileged ops denied with
  `ErrDecisionUnavailable` (not allowed, not a policy deny).
- **Timeout test:** a slow/no-response PDP ⇒ fail fast within the deadline.
- **Unit tests:** the remote `CoarseEngine` adapter (result/err mapping), the dispatch arm
  (mode selection), and the `remoteShadowed` comparator.

## 6. Risks

| Risk | Mitigation |
|---|---|
| Intersection (`intersect(user, service)`) tightens **impersonated** decisions vs the local walk. Attributed s2s is unaffected (resolves the caller, matches legacy) | Shadow-first proves parity for attributed s2s. A direct-user request is decided from its passport, not by intersection (§4.3) |
| Trusted-subsystem: attributed s2s decides on the **caller's** credential, so per-user confused-deputy checks on downstream refs are the **caller's** responsibility, not identity's | Caller must impersonate (or check entitlement) on user-facing forwards; the current lifecycle gap is the compute-lifecycle finding (§7) |
| Added network hop: latency + hard dependency on identity PDP | Hard timeout + fail-closed now; circuit breaker (a follow-up) before broad enforce |
| A service library that sends the passport meets an identity that ignores it ⇒ the service's own role would decide | The library requires the `passportSubject` echo and fails closed. The echo failure does not open the circuit breaker, so system-account checks still get verdicts. Set the remote mode to `off` before an identity rollback (§4.5) |
| A check sent more than about 15 s after authentication meets an expired passport ⇒ 401, no verdict | The 10 s cache margin stays for now. Identity's log shows each refused passport and its cause, so the shadow window can count it there (§4.5) |
| Regression in the shared `pkg/rbac` seam affecting identity itself | Remote path is a separate context slot/mode; local `*RBAC`/shadow/cutover untouched; existing identity tests must stay green |

## 7. Deferred findings: trusted-subsystem grounding (2026-07-15)

Grounding the `compute→region` deputy path (who authorizes what; the audit/correlation trail)
surfaced pre-existing gaps whose blast radius exceeds this cut. Recorded here to fix **separately**;
none block the cut-1 seam. `uni-compute` line numbers are its pinned `identity v1.17.8` build (the
working tree overlays a newer identity via `go.work`, but the cited `uni-compute` files are its own).

**The server-lifecycle path is under-authorized (`uni-compute`).**
- *Read-gated mutation:* Start/Stop/Reboot/Snapshot/Console/SSHKey have no dedicated authz check:
  each authorizes only through `GetRaw`'s `compute:instances`/**Read** gate
  (`pkg/server/handler/instance/client.go:757`; Snapshot notes it at `:1131`). So **read permission
  grants power-control** over an instance.
- *Unchecked deputy forward:* these ops call region on the plain ctx with **no impersonation**
  (`client.go:1030/1053/1078/1090/1150`), so region enforces compute's broad system-account
  credential, **not the user**. That is the confused-deputy exposure. (Create-path
  referenced-resource reads DO impersonate at `:343/:348/:361/:705`, so the gap is
  lifecycle-specific.)
- *Fix direction:* real permissions for lifecycle ops (e.g. `compute:instances`/Update) + impersonate
  the user on the region forward so region re-checks entitlement.

**Front-door audit is incomplete (`uni-compute` + identity `pkg/middleware/audit`).**
- The only correlation-ID-bearing records come from the generic audit middleware, which **omits** the
  resolved region, the referenced resources, and the authorization decision itself, and **misses the
  sensitive ops**: it skips GETs, drops instance CREATE (no path param), and drops Start/Stop/Reboot
  (empty-body 202s). It therefore logs only Update/Delete/Snapshot. The `rbac.Allow*` decisions
  emit no record on the legacy path.
- *Verified context:* identity's PDP decision log DOES stamp `traceID`/`spanID` on every record,
  including fail-closed denials (`pkg/rbac/decision_log.go:51-55`; confirmed 2026-07-15), so the seam
  supplies a correlation-bearing decision record once compute adopts it. What remains is capturing
  (resolved region + resource) and covering the missing ops.
- *Fix direction:* emit a front-door decision record for the sensitive ops carrying (user, operation,
  resolved region+resource, decision, correlation id).
- **Status (2026-07-17): DONE, identity central side.** A request-scoped decision stash
  (`pkg/rbac/decision_stash.go`) has the two `Allow*` choke points append each verdict (resource
  kind+id, action, allow/deny/unavailable, reason); the audit middleware seeds it and emits a
  `decisions` list, so the record now carries the referenced resources and the decision on each. The
  record's own `resource` field is unchanged, because existing log consumers parse it; the kind the
  handler authorized is in `decisions[].resourceKind`. Purely additive: no authorization decision
  changed. **Remaining:** the records the old resource derivation drops (body-less actions such as
  Start/Stop) and the **resolved region**, which was split to the region-dimension finding.

**Region is not a first-class authorization/audit dimension (identity; cross-cutting).**
- ACL scopes are **Global/Org/Project only**; region is never an authz scope, and decision-log fields
  carry org/project/kind/`resource_id` but **no RegionID**. (The `region` in `region:servers` is the
  service namespace, not a region instance.)
- *Impact:* (a) a grant cannot be scoped to a region (it applies across all regions); (b) the record
  never names which region an op touched, recoverable only by out-of-band `resource_id`→region
  resolution, unreliable after a delete. The residency/compliance stitch ("authorized-for vs. touched,
  per region") cannot be expressed.
- *Fix direction (cost ladder, verified 2026-07-15):*
  - **Audit field, caller-side (CHEAP, near-term win):** add `RegionID` to `rbac.Resource`
    (`check.go:109`) + one line in the decision fields (`decision_log.go:239`; opt. `metrics.go:158`),
    populated at the consumer's `Allow*` site via the existing `Allow{Organization,Project}ScopeReader`
    hook (`handler.go:126,189`, which already takes a caller resource "e.g. a region CRD"). No codegen.
    Lands RegionID + correlation-id in the **consumer's** decision stream, joinable to identity's
    central record by trace-id, enough for the residency stitch.
  - **Into identity's CENTRAL record (over the wire, MODERATE):** the check schema is closed, so add
    `regionId` to `AuthorizationCheckResource` (`server.spec.yaml`) + `make generate`, the coupled
    `Resource` DTOs (`check.go`/`decision.go`, coupled at `engine.go:98`), and both wire-mapping sites.
  - **Cerbos policy attribute (MODERATE):** `WithAttr` is codegen-free (`request.go:175`) but needs a
    `BuildResource` signature change, the coarse cache-key fix (`engine.go:286`; region must join the
    key if it ever changes a verdict), and depends on the wire field for a value.
  - **Full authz scope (EXPENSIVE):** core-model change (bindings 3-tuple→4-tuple, wire grammar,
    generated CEL, CRD scope buckets, parity/migration). Only if per-region *enforcement* is needed;
    otherwise keep region an optional attribute.
