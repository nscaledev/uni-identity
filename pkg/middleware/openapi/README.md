# `pkg/middleware/openapi`

This package is the request-trust assembly layer for UNI services.

## Intent

`pkg/middleware/openapi` turns transport-level facts, token facts, delegated identity facts, and
authorization facts into a single normalized request context for handlers.

This is where the platform model stops being a set of separate packages and starts becoming a live
request pipeline.

Its main responsibilities are:

- authenticate callers
- validate requests and responses against the OpenAPI contract
- derive or extract principal information
- resolve and cache ACLs
- inject normalized authorization, RBAC, and principal context for handlers

The package provides the common machinery used both by identity itself and by downstream UNI
services that rely on identity for token validation and ACL resolution.

## Two Request Paths

The package operates around two distinct trust paths.

### User To Service

- the caller presents a bearer token
- token validation establishes the actor identity by exchanging the source
  token for a UNI passport at identity's RFC 8693 token endpoint
- RBAC is resolved as that user or service account, against the identity ACL
  endpoint, exactly as before
- principal information is derived from the passport claims and projected
  onto the existing `userinfo` shape so handler code is unchanged

### Service To Service

- the caller must use mTLS
- the calling service identity comes from the client certificate
- RBAC is resolved either as that service or as the intersection of that service and an impersonated principal
- principal information is required and is propagated explicitly

This distinction is central to how UNI services compose. `pkg/middleware/openapi` is the package
that keeps those two models separate while presenting handlers with one normalized interface.

## Trust Boundary Rules

- There are exactly two conceptual request-authentication paths: bearer-token user calls and mTLS
  service calls.
- Principal propagation is mandatory on service-to-service calls.
- For user-originated calls, principal information is derived from validated token/userinfo state.
- For service-originated calls, principal information is explicitly propagated and consumed as part
  of authorization.
- Service identity and delegated principal identity are separate concepts.
- ACL cache keys must distinguish direct calls from impersonated calls so cached results do not
  overgrant. Keys are also qualified by the authenticated issuer (`src_iss`), and every
  user-influenced segment is length-prefixed so a subject containing the join delimiter cannot be
  crafted to collide with another identity's key. The impersonated key additionally carries the
  impersonated actor's principal type and sorted organization set — the inputs the impersonated ACL
  is resolved from — so two distinct impersonated principals that share an actor string cannot
  collide (parity with the hardened coarse-decision cache in `pkg/rbac`). The direct key
  carries those same two dimensions from its auth claims.
- ACL cache keys also carry a digest of the presented token. The ACL is a function of the presented
  token plus cluster state, not only of `(sub, srcIss)`. Two live tokens for the same subject can
  resolve to different ACLs, so they must never share a cache entry.
  - Example: a global group role binding
    ([`pkg/rbac/README.md#global-role-bindings`](../../rbac/README.md#global-role-bindings)) grants
    global authority from the groups asserted in the specific token presented, so a subject's next
    token can carry different groups and resolve to a different ACL.
  - Keying by token is strictly finer than keying by subject, so it can only under-share an entry,
    never over-share one.
  - The key carries a digest rather than the raw token, because cache keys live in a large LRU in
    every downstream service and must not themselves be credential material.
  - The mTLS system-account path leaves the token empty, so every system-account request gets the
    same constant digest. That is harmless: system-account ACLs do not depend on token content.
  - `--acl-cache-size` keeps its default of `1<<16` entries. Live tokens × scopes now bounds the
    population, rather than subjects × scopes, but with the default 1-minute TTL and a few hundred
    bytes per entry (key ≈ sub + srcIss + account type + org set + digest + scope, value = ACL), 65,536 entries is still
    single-digit megabytes. Eviction pressure appears only above roughly 1,000 distinct token+scope
    pairs per second, sustained.
  - Nobody measured the resulting hit-rate shift before deployment. The default rests on the sizing
    arithmetic above, and the hit rate is a post-deploy monitoring item.
  - A client that mints a fresh token per request misses the cache every time. That is a client-side
    anti-pattern to fix at the client, not a reason to grow the cache.
- OpenAPI validation, authentication, principal propagation, and ACL resolution are colocated so
  handlers receive already-normalized request context.

## Local And Remote Modes

The package has two important integration modes:

- `local`, used by the identity service itself, where token validation and ACL resolution are handled
  directly against local `oauth2` and `rbac`
- `remote`, used by other services, where bearer tokens are exchanged at identity for a UNI passport
  and ACLs are fetched back from identity over the service client path

The shared `openapi` middleware layer defines the common request pipeline and the cache/propagation
rules across both modes.

### The Decision-Engine Crossing (authorization migration)

The middleware is the single production point that seeds the Cerbos-capable decision engine into
handler contexts for `pkg/rbac`'s dual-path `Allow*` dispatch. `DecisionEngineProvider` is an
**optional** interface asserted against the configured `Authorizer` at request handling time —
deliberately not part of the `Authorizer` interface, so the generated mock and any external
implementer keep compiling and their requests structurally take the legacy path. **Only the `local`
authorizer implements it** (identity's own `RBAC`, whose in-process PDP client backs
`rbac.Check`/`CheckMany`). The `remote` authorizer deliberately does **not** — a remote
`DecisionEngineProvider` was a **designed follow-up**, not delivered by the `/authorization/check`
endpoint, and has since been delivered as a sibling interface rather than by widening this one. What
that endpoint delivered is the `remote`
authorizer's decision **call** (`Authorizer.CheckMany` over `POST /authorization/check`,
`remote/decision.go`): a downstream service obtains a decision from identity. Routing a downstream
`Allow*` through that call would need a remote transport **above** `rbac.decide()` (a downstream
RBAC cannot read identity's authorization resources — the Group/Role/Project/Organization CRDs
binding resolution walks — so `ResolveBindings` would fail-closed-deny everything); the
`DecisionEngine()` seam sits **below** binding resolution and cannot express that, so it stays a
separate task (see the migration plan's follow-up entries). Seeding happens next to the ACL context
on the context handlers actually receive, and is unconditional on engine mode — whether the engine
actually serves decisions is the dispatch predicate's job (see [`pkg/rbac`](../../rbac/README.md)).
Until the strangle-by-kind cutover and legacy-path retirement, the per-request ACL resolution above
still runs even when the engine serves, so cerbos mode carries both resolution costs.

### The Remote Decision-Engine Seed

The gap the previous section calls a designed follow-up has been closed by
`RemoteDecisionEngineProvider`, the remote-side sibling of `DecisionEngineProvider` — same
optional-interface, not-widening-`Authorizer` rationale, seeded immediately after it at the same
production seeding point (`Validator.seedDecisionEngines`, `openapi.go`). **Only the `remote`
authorizer implements it** — the mirror image of the local split above — handing back the
`rbac.CoarseEngine` backed by its own decision call (`CheckMany`, described next) plus the
`rbac.RemoteMode` it should participate under. The mode is set at construction via
`remote.WithRemoteEngineMode`; left unset it defaults to the zero value `rbac.RemoteOff`, under
which `pkg/rbac`'s dispatch falls through to the legacy/local path exactly as before, so every
existing `remote`-authorizer deployment is unaffected until it opts in. `local.Authorizer` and
`remote.Authorizer` each implement only one of the two provider interfaces, never both, so exactly
one seed block ever matches for a given deployment (`TestLocalAuthorizerDoesNotImplementRemoteDecisionEngineProvider`
and `TestRemoteAuthorizerDoesNotImplementDecisionEngineProvider`, this package's
`remote_decision_engine_test.go`). Deciding what mode a downstream service actually configures
in production is a separate, later concern — this seam only makes the choice reachable.

### The Remote Decision Call

`remote/decision.go` adds `Authorizer.CheckMany(ctx, []CheckRequest) ([]bool, error)`, the
downstream side of identity's `POST /api/v1/authorization/check`. It mirrors the `GetACL` wire
pattern — the generated typed client (`PostApiV1AuthorizationCheckWithResponse`) over the cached
mTLS/trace-context HTTP client, with the `X-Principal`/`X-Impersonate` principal headers injected
via `principal.Injector` — with one deliberate divergence: it forwards **no** bearer. The check
endpoint is system-account-only and rejects any `Authorization` header, so the caller is
authenticated by the mTLS peer certificate and the acting user is conveyed by `X-Principal`, never a
token (unlike `GetACL`, which is not system-gated and forwards the bearer to name the user).
Identity requires `X-Principal` on every mTLS call (even a non-impersonating one —
`extractPrincipal` rejects its absence with a 400), so a caller that hand-rolls the request instead
of using this `CheckMany` must inject it itself or be denied. It uses a small local
`CheckRequest`/`Resource` DTO rather than importing `pkg/rbac`, keeping the seam free of that
dependency for downstream consumers. Absence semantics are preserved on the wire (a scope field is
populated only when non-empty, so an org check never gains a project attribute). **Fail-closed**: a
transport failure or 5xx maps to `ErrDecisionUnavailable`, a 401/other 4xx propagates via
`errors.PropagateError`, and a result-count mismatch is unavailability — the caller treats any error
as a deny, while a per-entry `false` is a policy deny. This remote call is uncached (the design's
no-cache-coarser rule plus impersonation keying). The coarse-decision cache has since been
delivered, but at identity's OWN dispatch — the `pkg/rbac` `allowCoarse` layer, keyed on the
policy-store hash (see [`pkg/rbac`](../../rbac/README.md#the-coarse-decision-cache)) — NOT on this
remote endpoint, which stays uncached. Wiring this call into downstream `Allow*` routing is the
recorded follow-up above.

### The Circuit Breaker

`CheckMany`'s round trip (above) is additionally guarded by a `failsafe-go` circuit breaker
(`remote/decision.go`, `remote/authorizer.go`), closing the resilience gap the migration design
calls out: today, when the central PDP degrades, every remote check would otherwise wait out the
full per-call timeout, keep hammering the struggling PDP, then fail closed. The breaker detects
sustained unavailability and **opens** — short-circuiting further calls (fail fast, no round trip,
no added load on the PDP) for a cooldown — then **half-opens** to probe recovery and **closes**
again. The security posture is unchanged (still fail-closed): the breaker only makes an
already-fail-closed system fail closed **faster** and **PDP-protectively**; it never introduces a
fallback to a legacy path.

**States:** `closed` (normal — every call reaches the transport), `open` (every call fails instantly
with `ErrDecisionUnavailable`, no HTTP round trip), `half_open` (a small number of trial calls are
let through to probe recovery). A `failsafe-go` `OnStateChanged` listener logs every transition
(`"remote authorization circuit breaker state changed"`, unconditional `Info` — including a failed
half-open probe dropping back to `open`, exactly as actionable as the initial trip) and increments
the `unikorn_identity_authz_remote_breaker_transitions_total` counter, keyed by the state entered —
this is how an operator sees the breaker open without reading source.

**Load-bearing invariant — trips on unavailability, never on denies.** `CheckMany` returns
`([]bool, nil)` for any successfully served check, however many entries denied; it returns
`(nil, err)` only when no verdict was obtained at all (transport failure, timeout, 5xx, or a
malformed response — see above). The breaker's default any-error-is-a-failure handling therefore
already trips on exactly "no verdict obtained" and never on a returned deny: a high deny rate under
normal load can never open the breaker, only a genuine failure to reach/parse identity can.

**Defaults (`NewAuthorizer`):** a time-based failure **rate** — not a raw consecutive count, so one
flaky call cannot trip it, but sustained majority failure trips it quickly — opens the breaker once
at least 10 executions have landed within a trailing 10s window and at least 50% of them failed;
once open it waits a 5s cooldown before probing recovery in half-open state, where 2 consecutive
successful probes close it again (any half-open failure reopens it immediately). Every consumer
(region/compute/kubernetes) gets this working breaker for free from `NewAuthorizer`, with no server
flag required.

**Tuning and disable (`WithCircuitBreaker`):** an `Option`, mirroring `WithCheckTimeout`'s shape,
that takes any `failsafe-go` `circuitbreaker.CircuitBreaker[[]bool]` — full control over the
thresholds/cooldown/half-open profile for a deployment that needs different tuning. Passing `nil`
disables the breaker entirely (e.g. for rollback): `CheckMany` then behaves exactly as it did before
this guardrail, still bounded only by `checkTimeout`.

**Deferred:** bounded retry. The migration design names "breaker + timeout + bounded retry" as the
full resilience profile; retry is deliberately **not** part of this cut — it interacts with the
tight per-call latency budget (N attempts × timeout) and deserves its own sizing decision, so it is
left as a follow-up rather than bundled in here.

### Remote Token Exchange

The `remote` authorizer's bearer-token path is exchange-backed. On a cache miss it performs RFC 8693
token exchange against identity's `/oauth2/v2/token` endpoint, decodes the returned passport claims
(without local signature verification — trust is established by the channel, not by JWKS), and
populates the existing `authorization.Info` and `userinfo` structures. The cached value is the
passport claims payload, and the per-entry TTL is derived from the passport's `exp` claim minus a
10 s clock-skew fudge. Identity caps the passport expiry to the source token's expiry before
minting it, so middleware does not need to parse the source token locally.

The exchange path fails closed. Token-endpoint responses project to the API edge as follows:

- 401 (subject token rejected, `ErrTokenExchangeUnauthorized`) → `access-denied` (401)
- 400 with RFC 6749 §5.2 `error=invalid_scope` (subject token valid, scope not granted,
  `ErrTokenExchangeForbidden`) → `forbidden` (403)
- 5xx and transport/timeout failures (`ErrTokenExchangeUnavailable`) → `access-denied` (401),
  via the catch-all. The middleware deliberately does not surface 502/503/504 to the caller: a
  transient identity outage must not let a request through, and exposing the upstream status
  would invite retries that defeat the fail-closed contract.
- Any other non-2xx outcome — including 400 with a different `error` code, malformed bodies, and
  unclassified 4xx — also falls through to `access-denied` (401). Same rationale: refuse
  ambiguous responses rather than guessing at intent.
- Malformed or temporally invalid passport after a successful exchange → 500

Passport decoding rejects both expired (`exp` ≤ now) and not-yet-valid (`nbf` > now) tokens. There
is no fallback to the legacy userinfo path. Passports are consumed in-process and are never
forwarded on outbound calls — internal service-to-service communication continues to use mTLS plus
`X-Principal` exactly as before.

## Validation Error Disclosure

Request and response schema validation are both performed here, and the two get very different
treatment on the way out.

**Request** validation failures are returned to the caller, so they go through
`clientValidationError`, which builds a description from the location of the fault and a reason.
`err.Error()` must never be used here. kin-openapi appends the whole schema and the value that
failed validation to a schema error, and prints the unparsable value in a parse error, so returning
it echoes the request body — bearer tokens included — back to the caller (OWASP API8:2023,
CWE-209). The specific fields that may and may not be used are recorded in the comments on
`schemaErrorDescription` and `parseErrorDescription`; the short version is that only the statically
written `Reason` fields are safe, and `Error()`, `Origin`, `Value` and `Cause` are not.

Two things this deliberately does not promise:

- Reasons may name a property the caller sent, and may quote `enum` or `const` values from the
  schema. Both are published API contract and both are needed to correct the request, so both are
  allowed. What is excluded is the caller's own data and anything naming the implementation — which
  is why the `format` reason is rewritten rather than passed on, as the library's version quotes its
  own internal regex rather than the format name.
- The library detail is not logged. Core's `errors.Error.Write` logs the description we build, so
  the fault is still recorded, but the raw error is not attached, as it would relocate the caller's
  credentials into the log store.

This is not solely a `kin-openapi` 0.144.0 problem. On 0.132.0 the same code path already returned
the full body for JSON requests; what 0.144.0 changed is form-encoded bodies, where absent
properties stopped being decoded as nil, so a missing required property now fails the object-level
`required` check whose error value is the entire decoded body. The token endpoint is form encoded,
which is how it surfaced.

**Response** validation failures never reach the client as a body, so they keep the library's full
rendering. The schema and the offending value are the whole point: that output is what tells you
which part of a handler response does not match the specification.

### Known Issue: Response Validation On Token Endpoints

`runtimeSchemaValidationPanic` defaults to on, and the panic text includes the response body. On
`/oauth2/v2/token` that body contains a freshly minted access token, so a response schema mismatch
writes a live credential into the pod log, and the panic aborts the connection rather than
returning a clean 500. Nothing installs a recovery middleware. Response validation is a
development aid, so this is not urgent, but the token endpoints want either redaction or the panic
disabled before anyone leans on it in production.

## Ingress And Header Invariants

The package relies on an important ingress invariant:

- end users cannot spoof the mTLS propagation headers used internally

That trust exists because the nginx ingress layer detects and rejects user attempts to override the
certificate-related headers used by the internal service chain. This is a core assumption of the
request model and should be treated as part of the security boundary, not merely deployment trivia.

### Trust The Channel, And The Deferred Signed-Propagation Option

Principal propagation is **trust-the-channel by design**. The primary `X-Principal` is unsigned
base64url(JSON) (`principal.Injector`), and its trustworthiness rests on two facts working together:

- the caller is a verified **mTLS** peer — its client-certificate CN is the acting service identity;
- the **ingress strips** `X-Principal`, `X-Impersonate`, `Ssl-Client-Cert`/`Ssl-Client-Verify` and
  the relayed `Unikorn-Client-Certificate` from external requests, so an end user cannot inject them.

Consequently `extractPrincipal` reads these headers only on the mTLS path
(`extractOrGeneratePrincipal` gates on the client-certificate header); a bearer or no-certificate
caller has its principal **derived from the validated token**, never from the header, and a forged
`X-Impersonate` on such a hop is ignored. That boundary is a hard, regression-guarded invariant: see
the trust-boundary negative tests `TestServiceToServiceForgedPrincipalWithoutMTLSIsNotHonored` and
`TestForgedPrincipalHeaderWithoutVerifiedPeerRejected` (this package's `openapi_test.go`), the
endpoint guard `TestAuthorizationCheckIgnoresForgedPrincipalHeaders` (`pkg/handler`), and a genuine
mTLS-handshake test for `/authorization/check` in the kind suite
(`test/api/suites/authorization_check_mtls_test.go`).

`extractPrincipal` also has a **signature-verified** path (`client.VerifyAndDecode`), used today for
principals signed by `principal.ControllerInjector` (uni-core's `EncodeAndSign`). Making
signature-verified propagation the **default** for all service-to-service calls — so trust does not
rest on ingress configuration alone — is a **recorded future option (deferred)**. It is deferred,
not adopted: the signing primitives live in **uni-core** (flipping the default is a cross-repo,
flag-day change) and per-request public-key verification carries a real performance cost. The owner
decision is to keep trust-the-channel for now.

## Caveats

- This package contains real trust-boundary logic rather than glue code.
- The `extractPrincipal` signature-verification fallback (`VerifyAndDecode`) is **retained**: it
  serves principals signed by `principal.ControllerInjector`. Whether signed propagation becomes the
  default (retiring the unsigned `X-Principal`) is a deferred **signed-propagation** decision — see
  [Trust The Channel, And The Deferred Signed-Propagation Option](#trust-the-channel-and-the-deferred-signed-propagation-option)
  above — not a blanket deletion candidate.
- Remote bearer-token validation depends on an identity round-trip per cache miss; cache hits avoid
  it. Phase 2 deliberately does not introduce downstream JWKS verification — the trust model for
  passports remains channel-scoped to identity rather than signature-scoped per service.

## TODO

- **Signed principal propagation (deferred):** decide whether to make signature-verified principal
  propagation the default for all service-to-service calls (retiring the unsigned `X-Principal`),
  weighed against the cross-repo/flag-day cost (the `EncodeAndSign`/`VerifyAndDecode` primitives
  live in uni-core) and the per-request public-key verification cost. Kept as trust-the-channel for
  now; the signed `VerifyAndDecode` fallback stays in place for `ControllerInjector` principals.

## Related Documentation

- [`pkg/oauth2`](../../oauth2/README.md), which establishes bearer-token actor identity and session state
- [`pkg/principal`](../../principal/README.md), which defines delegated identity propagation
- [`pkg/rbac`](../../rbac/README.md), which converts identity and principal context into effective ACLs
- [`pkg/jose`](../../jose/README.md), which underpins token cryptography and JWKS publication
