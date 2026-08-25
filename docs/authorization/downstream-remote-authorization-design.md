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
- Remote paths for `AllowProjectScopeCreate*` (the project-scope-create migration) and `AllowRole`
  (the grantability cross-parity): these intentionally never dispatch to an engine and stay on
  their existing paths.

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
  | `shadow` | **serve the legacy walk**, also call `AllowCoarse` remotely, log any divergence |
  | `enforce` | remote is **authoritative** (no legacy fallback; fail-closed) |

  The `shadow` comparator is a downstream analog of `pkg/rbac/shadow.go` (`remoteShadowed`), emitting a
  distinct, greppable divergence message so a gate can assert zero divergence.

Consumer change: **one line in each `server.go`** to construct the service with the remote engine
mode from config. The ~65 `Allow*` sites are untouched.

### 4.3 Trust and principal semantics (load-bearing)

**Verified 2026-07-15.** Grounding in §7.

- **The cert-relay conveys the original caller.** `CheckMany` (like `GetACL`) relays the calling
  service's certificate in the `Unikorn-Client-Certificate` header (`CertificateRequestMutator` →
  `InjectClientCert`); identity's `ExtractClientCert` reads it with **priority over the TLS peer**
  (`clientcert.go:60-64`), so the check's authenticated subject is the **original caller** (e.g.
  `compute-service` for a `compute→region` call), not the consumer's own account
  (`region-service`), verified `openapi.go:238,251`. mTLS + trace + cert relay are already wired:
  **no new propagation code**.
- **The seam does NOT force impersonation.** The decision follows the **authenticated subject + the
  inbound `X-Impersonate` flag**, mirroring identity's own `getSystemAccountACL` (`rbac.go:1029-1056`):
  - **Attributed s2s** (system-account caller, no inbound flag) → decide against the **relayed caller
    alone** (`compute-service`). The propagated user rides `X-Principal` for **attribution/trace only**,
    never the decision. (Trusted-subsystem model.)
  - **Impersonated s2s / direct bearer user** (inbound flag set, or a bearer-authenticated user) →
    `intersection(user, service)` per specification §4.6.1.
- **Do not derive impersonation from "a User is present in `X-Principal`".** `X-Principal` carries the
  user as attribution on attributed s2s too; forcing impersonation there makes identity compute
  `intersect(user, caller)` and **wrongly denies** service-privilege ops the user lacks (e.g.
  `compute→region:servers`, where only `compute-service` holds `region:servers`). The trigger must key
  off `authorization.Info` (the authenticated subject), not the propagated principal's type.
- **Deployment prerequisite (still required):** each consumer's **system-account CN → RBAC role must be
  provisioned as a SUPERSET of what its own API authorizes** (`region-service` += `region:*`). This is
  the cap for the **direct-user** path: a bearer user is conveyed only by impersonation (the check
  drops the bearer and falls back to the consumer's own account as the TLS-peer subject), so identity
  computes `intersection(user, consumer-service)`, which equals the user's own perms only if the
  consumer role is a superset. Attributed s2s does not depend on it (it resolves the caller). The
  shadow soak verifies provisioning empirically before enforce.
- **Residual risk, direct-path blast radius (accepted):** provisioning the consumer role as a
  superset also widens what the consumer's OWN system account can do on a **direct**
  (non-impersonated) call. `region-service` now passes a direct authorization check for the full
  `region:*` set it previously lacked (create/update/delete on regions/flavors/images included);
  likewise `compute-service`/`kubernetes-service` for their domains. The `intersection(user,
  service)` cap constrains only **impersonated** checks (a direct service call resolves the
  service's own, now widened, role), so a **compromised or forged consumer mTLS credential** gains
  that service's entire resource domain platform-wide, where before it would have been denied. This
  is accepted as the cost of the seam (under-provisioning denies legitimate users; see §6), and is
  bounded by: mTLS credential hygiene (the credential is an X.509 CN, not a bearer token;
  rotation/scoping per the cluster's cert policy); and the deferred **region-dimension finding**
  (region as a first-class authz dimension, §7) and the **compute-lifecycle finding** (compute
  lifecycle under-authz, §7), each of which would narrow the direct-path grant. Revisit before broad
  `enforce`.
- **Rejected, `intersection(caller-service, receiver-service)`:** an anti-escalation cap (bound the
  caller by the relaying receiver's own role) was considered and dropped: since the receiver
  (`region-service`) is provisioned as the full superset (above), the intersection is a **no-op**.
  Revisit only to reduce trust in the relayer below the "trust the channel" model
  (specification §10.1).

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
- Deploy order: identity (with the new service-account roles) → then the service.
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
  server logs and fail on any `remote shadow divergence` after the matrix runs.
- **Fail-closed test:** identity unavailable ⇒ mutating/privileged ops denied with
  `ErrDecisionUnavailable` (not allowed, not a policy deny).
- **Timeout test:** a slow/no-response PDP ⇒ fail fast within the deadline.
- **Unit tests:** the remote `CoarseEngine` adapter (result/err mapping), the dispatch arm
  (mode selection), and the `remoteShadowed` comparator.

## 6. Risks

| Risk | Mitigation |
|---|---|
| Intersection (`intersect(user, service)`) tightens **impersonated / direct-user** decisions vs the local walk. Attributed s2s is unaffected (resolves the caller, matches legacy) | Shadow-first proves parity; provision the consumer superset (§4.3) to close the direct-user cap before enforce |
| Trusted-subsystem: attributed s2s decides on the **caller's** credential, so per-user confused-deputy checks on downstream refs are the **caller's** responsibility, not identity's | Caller must impersonate (or check entitlement) on user-facing forwards; the current lifecycle gap is the compute-lifecycle finding (§7) |
| Added network hop: latency + hard dependency on identity PDP | Hard timeout + fail-closed now; circuit breaker (a follow-up) before broad enforce |
| Consumer superset under-provisioned ⇒ direct-user denials on enforce | Caught as divergence in shadow before any flip |
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
  record's own resource is now derived authoritatively (kind from the `Allow*` the handler made, id
  from the request's last path parameter) instead of URL-guessing, which also covers the
  previously-dropped creates and body-less actions (Start/Stop/rotate). Sensitive reads opt in via an
  `x-unikorn-audit: sensitive` operation extension (routine reads still skipped). Purely additive:
  no authorization decision changed. **Remaining:** (a) per-service sensitive-read annotations that
  activate that path (compute console/sshkey, kubernetes kubeconfig), a small consumer follow-up; (b)
  the **resolved region** was split to the region-dimension finding and is deliberately excluded here.

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
