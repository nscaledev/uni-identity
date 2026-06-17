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
  a token-exchange broker: a third-party (Auth0) JWS access token is validated
  fully locally against the issuer JWKS, while a Unikorn-issued token (user or
  service account) is resolved by an introspection call to identity's
  `userinfo` endpoint
- RBAC is resolved as that user or service account, against the identity ACL
  endpoint, exactly as before
- principal information is projected onto the existing `userinfo` shape so
  handler code is unchanged

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
- `remote`, used by other services, where bearer tokens are validated locally (third-party tokens
  against the issuer JWKS) or by an introspection call to identity (Unikorn tokens via `userinfo`),
  and ACLs are fetched back from identity over the service client path

The shared `openapi` middleware layer defines the common request pipeline and the cache/propagation
rules across both modes. The two authorizers share the third-party OIDC validator
([`pkg/oauth2/auth0`](../../oauth2/auth0)), the token-shape router
([`pkg/oauth2/bearer`](../../oauth2/bearer)) and the `Authorization` header parser
([`authorization.GetHTTPAuthenticationScheme`](../authorization)); the only real difference between
them is that the `local` authorizer executes `userinfo` and `GetACL` in-process, while the `remote`
authorizer reaches them by RPC.

### Distributed Local Validation

The `remote` authorizer authenticates bearer tokens itself; there is no token-exchange broker. It
routes on the JOSE header:

- a **JWS** is a third-party (Auth0) access token. When a third-party IdP is configured it is
  validated **fully locally** against the issuer JWKS (signature, issuer, audience, algorithm and
  expiry, via go-jose) on **every** request — no network call and no cache, because the check is
  cheap. Authentication yields the subject only; organisation membership and RBAC are resolved
  later against our own graph via `GetACL`, never read from the foreign token.
- a **JWE** is a Unikorn-issued token (user or service account). It is resolved by an introspection
  call to identity's `userinfo` endpoint — the service-token revocation point. The result is cached
  for a short staleness budget (`userinfoCacheTTL`), justified because the call is a network
  round-trip plus a JWE decrypt at identity. The path **fails closed**: once the entry expires, a
  request cannot proceed unless identity confirms the token afresh, and any non-200 or transport
  failure denies the request rather than guessing at intent.

A bearer that is neither a JWS nor a JWE is rejected outright, so a token-format change surfaces as
an alertable signal rather than a scatter of generic 401s. Resolved identity is consumed in-process
and is never forwarded on outbound calls — internal service-to-service communication continues to
use mTLS plus `X-Principal` exactly as before.

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
- Remote third-party (Auth0) validation is fully local against the issuer JWKS and makes no identity
  round-trip. Remote Unikorn-token validation depends on a `userinfo` introspection round-trip per
  cache miss (cache hits avoid it) and fails closed past the staleness budget.

## TODO

- Remove the legacy principal extraction/verification fallback once all callers use the current
  propagation model.

## Related Documentation

- [`pkg/oauth2`](../../oauth2/README.md), which establishes bearer-token actor identity and session state
- [`pkg/principal`](../../principal/README.md), which defines delegated identity propagation
- [`pkg/rbac`](../../rbac/README.md), which converts identity and principal context into effective ACLs
- [`pkg/jose`](../../jose/README.md), which underpins token cryptography and JWKS publication
