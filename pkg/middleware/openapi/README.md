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
- token validation happens locally in the middleware and is never delegated to
  a token-exchange broker. A bearer is routed by its issuer: a Unikorn-issued
  JWS access token is verified against identity's published JWKS, a third-party
  (Auth0) JWS against that issuer's JWKS, and a legacy Unikorn JWE (opaque,
  retiring as sessions rotate to JWS) is introspected at identity's `userinfo`
  endpoint
- RBAC is resolved as that user or service account, against the identity ACL
  endpoint, exactly as before
- the principal — the actor's subject and account type — comes from the verified
  token and is carried on `authorization.Info` (a `pkg/principal.Principal` plus
  the raw token) for handlers and audit

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
- For user-originated calls, principal information is derived from the verified token (the `userinfo`
  introspection response is consulted only for an opaque legacy JWE, which cannot be read locally).
- For service-originated calls, principal information is explicitly propagated and consumed as part
  of authorization.
- Service identity and delegated principal identity are separate concepts.
- ACL cache keys must distinguish direct calls from impersonated calls so cached results do not
  overgrant.
- OpenAPI validation, authentication, principal propagation, and ACL resolution are colocated so
  handlers receive already-normalized request context.

## Local And Remote Modes

The package has two important integration modes:

- `local`, used by the identity service itself, where a Unikorn JWS is verified in-process against
  our own keys (a legacy JWE is decrypted in-process) via `oauth2`, third-party tokens are verified
  locally against the issuer JWKS, and ACLs are resolved in-process via `rbac`
- `remote`, used by other services, where a Unikorn JWS is verified locally against identity's
  published JWKS (then session-checked at `userinfo`), a legacy JWE is introspected by an RPC to
  `userinfo`, third-party tokens are verified locally against the issuer JWKS, and ACLs are fetched
  back from identity over the service client path

The shared `openapi` middleware layer defines the common request pipeline, the cache/propagation
rules, and the `AuthenticationInfo` both authorizers carry. They share the multi-issuer JWS resolver
([`idp`](idp)), the token-shape sniffer and unverified-issuer router ([`bearer`](bearer)) and the
`Authorization` header parser ([`authorization.GetHTTPAuthenticationScheme`](../authorization)).
Both produce a **subject and account type only** — organisation membership is resolved by `rbac`
from the subject, never carried on the principal. The principal comes from the **verified token**
(via the resolver's per-issuer claim transform); the only real difference between them is that the
`local` authorizer verifies Unikorn tokens against in-cluster keys and executes the session check
and `GetACL` in-process, while the `remote` authorizer verifies against the published JWKS and
reaches the session check and `GetACL` by RPC.

### Distributed Local Validation

Neither authorizer delegates to a token-exchange broker. A bearer is routed by shape and then by its
**unverified issuer** (a routing hint only — the signature is always re-verified against that
issuer's trusted JWKS before any claim is acted on):

- a **Unikorn JWS** (`iss` is the platform issuer) is verified against identity's keys — locally
  in-cluster (`local`) or against the published, unauthenticated JWKS (`remote`) — and the principal
  (subject + account type) is read from its claims. It is **additionally** session-checked at
  identity's `userinfo` endpoint: the revocation point, required for long-lived service accounts and
  applied to all Unikorn tokens. That result is cached for a short staleness budget
  (`userinfoCacheTTL`) and **fails closed** once it expires.
- a **third-party JWS** (a configured external issuer, e.g. Auth0) is verified **fully locally**
  against the issuer JWKS (signature, issuer, audience, algorithm and expiry, via go-jose) — no
  identity round-trip. The principal comes from that issuer's claim transform; organisation
  membership and RBAC are resolved later against our own graph via `GetACL`, never read from the
  foreign token.
- a legacy **Unikorn JWE** is opaque, so it is introspected at `userinfo` (cached, fails closed) —
  the only channel that can recover its account type. These age out as sessions rotate to JWS.

A bearer that is neither a JWS nor a JWE, or a JWS from an untrusted issuer, is rejected outright, so
a token-format change surfaces as an alertable signal rather than a scatter of generic 401s.
Resolved identity is consumed in-process and is never forwarded on outbound calls — internal
service-to-service communication continues to use mTLS plus `X-Principal` exactly as before.

## Ingress And Header Invariants

The package relies on an important ingress invariant:

- end users cannot spoof the mTLS propagation headers used internally

That trust exists because the nginx ingress layer detects and rejects user attempts to override the
certificate-related headers used by the internal service chain. This is a core assumption of the
request model and should be treated as part of the security boundary, not merely deployment trivia.

## Caveats

- This package contains real trust-boundary logic, not just glue code.
- Principal propagation is a single format: the `X-Principal` header carries a base64url-encoded JSON
  principal. There is no longer a certificate-based extraction fallback.
- Remote third-party (Auth0) validation is fully local against the issuer JWKS and makes no identity
  round-trip. Remote Unikorn-JWS validation verifies the signature locally against the published
  JWKS (failing fast on a bad token with no network call) but still depends on a `userinfo` session
  check per cache miss (cache hits avoid it) and fails closed past the staleness budget; a legacy
  Unikorn JWE depends on the `userinfo` introspection round-trip outright.

## Related Documentation

- [`pkg/oauth2`](../../oauth2/README.md), which establishes bearer-token actor identity and session state
- [`pkg/principal`](../../principal/README.md), which defines delegated identity propagation
- [`pkg/rbac`](../../rbac/README.md), which converts identity and principal context into effective ACLs
- [`pkg/jose`](../../jose/README.md), which underpins token cryptography and JWKS publication
