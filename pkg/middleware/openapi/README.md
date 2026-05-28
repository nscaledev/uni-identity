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
  overgrant.
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
