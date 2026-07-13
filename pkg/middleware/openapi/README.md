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
  overgrant. The impersonated key additionally carries the impersonated actor's principal type and
  sorted organization set — the inputs the impersonated ACL is resolved from — so two distinct
  impersonated principals that share an actor string cannot collide (parity with the A15-hardened
  coarse-decision cache in `pkg/rbac`).
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

The middleware is the single production point that seeds the Cerbos-capable decision engine
into handler contexts for `pkg/rbac`'s dual-path `Allow*` dispatch. `DecisionEngineProvider`
is an **optional** interface asserted against the configured `Authorizer` at request handling
time — deliberately not part of the `Authorizer` interface, so the generated mock and any
external implementer keep compiling and their requests structurally take the legacy path.
**Only the `local` authorizer implements it** (identity's own `RBAC`, whose in-process PDP
client backs `rbac.Check`/`CheckMany`). The `remote` authorizer deliberately does **not** — a
remote `DecisionEngineProvider` is a **designed follow-up**, not delivered by A8. What A8
delivered is the `remote` authorizer's decision **call** (`Authorizer.CheckMany` over
`POST /authorization/check`, `remote/decision.go`): a downstream service obtains a decision
from identity. Routing a downstream `Allow*` through that call would need a remote transport
**above** `rbac.decide()` (a downstream RBAC cannot read identity's authorization resources — the Group/Role/Project/Organization CRDs binding resolution walks — so `ResolveBindings` would
fail-closed-deny everything); the `DecisionEngine()` seam sits **below** binding resolution and
cannot express that, so it stays a separate task (see the migration plan's follow-up entries).
Seeding happens next to the ACL context on the context handlers actually receive, and is
unconditional on engine mode — whether the engine actually serves decisions is the dispatch
predicate's job (see [`pkg/rbac`](../../rbac/README.md)). Until A12/A17 the per-request ACL
resolution above still runs even when the engine serves, so cerbos mode carries both
resolution costs.

### The Remote Decision Call (A8)

`remote/decision.go` adds `Authorizer.CheckMany(ctx, []CheckRequest) ([]bool, error)`, the
downstream side of identity's `POST /api/v1/authorization/check`. It mirrors the `GetACL` wire
pattern exactly: the generated typed client (`PostApiV1AuthorizationCheckWithResponse`) over
the cached mTLS/trace-context HTTP client, the bearer forwarded only when present (mTLS-only
callers have an empty `Token`), and the `X-Principal`/`X-Impersonate` principal headers
injected via `principal.Injector`. Identity requires `X-Principal` on every mTLS call (even a
non-impersonating one — `extractPrincipal` rejects its absence with a 400), so a caller that
hand-rolls the request instead of using this `CheckMany` must inject it itself or be denied.
It uses a small local `CheckRequest`/`Resource` DTO rather than
importing `pkg/rbac`, keeping the seam free of that dependency for downstream consumers.
Absence semantics are preserved on the wire (a scope field is populated only when non-empty,
so an org check never gains a project attribute). **Fail-closed**: a transport failure or 5xx
maps to `ErrDecisionUnavailable`, a 401/other 4xx propagates via `errors.PropagateError`, and a
result-count mismatch is unavailability — the caller treats any error as a deny, while a
per-entry `false` is a policy deny. This remote call is uncached (the design's
no-cache-coarser rule plus impersonation keying). A15 has since delivered the coarse-decision
cache, but at identity's OWN dispatch — the `pkg/rbac` `allowCoarse` layer, keyed on the
policy-store hash (see [`pkg/rbac`](../../rbac/README.md#the-coarse-decision-cache-a15)) — NOT
on this remote endpoint, which stays uncached. Wiring this call into downstream `Allow*`
routing is the recorded follow-up above.

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

## Ingress And Header Invariants

The package relies on an important ingress invariant:

- end users cannot spoof the mTLS propagation headers used internally

That trust exists because the nginx ingress layer detects and rejects user attempts to override the
certificate-related headers used by the internal service chain. This is a core assumption of the
request model and should be treated as part of the security boundary, not merely deployment trivia.

## Caveats

- This package contains real trust-boundary logic, not just glue code.
- Some transitional behaviour still exists around principal extraction and historical propagation
  formats; these paths should be reviewed as deletion candidates rather than normalized into the
  long-term design.
- Remote bearer-token validation depends on an identity round-trip per cache miss; cache hits avoid
  it. Phase 2 deliberately does not introduce downstream JWKS verification — the trust model for
  passports remains channel-scoped to identity rather than signature-scoped per service.

## TODO

- Remove the legacy principal extraction/verification fallback once all callers use the current
  propagation model.

## Related Documentation

- [`pkg/oauth2`](../../oauth2/README.md), which establishes bearer-token actor identity and session state
- [`pkg/principal`](../../principal/README.md), which defines delegated identity propagation
- [`pkg/rbac`](../../rbac/README.md), which converts identity and principal context into effective ACLs
- [`pkg/jose`](../../jose/README.md), which underpins token cryptography and JWKS publication
