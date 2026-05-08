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
- token validation establishes the actor identity
- RBAC is resolved as that user or service account
- principal information is generated from validated `userinfo` claims

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

## Local, Remote, And Passport Modes

The package has three integration modes:

- `local`, used by the identity service itself, where token validation and ACL resolution are handled
  directly against local `oauth2` and `rbac`
- `remote`, used by other services, where bearer tokens are validated through identity and ACLs are
  fetched back from identity over the service client path
- `passport`, used by other services that prefer to verify short-lived passport JWTs locally against
  identity's published JWKS, falling through to the `remote` authorizer for non-passport tokens and
  for all ACL lookups

The shared `openapi` middleware layer defines the common request pipeline and the cache/propagation
rules across all three modes.

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
- Remote bearer-token validation still depends on identity round-trips plus caching today.
- The passport-token model shifts authentication toward local JWKS-backed JWS verification in
  downstream services. ACL resolution still goes through identity — passports carry identity, not
  ACL — so the round-trip cost moves from per-call validation to per-call ACL lookup, which is
  cached by the existing remote-authorizer cache.

## TODO

- Remove the legacy principal extraction/verification fallback once all callers use the current
  propagation model.

## Related Documentation

- [`pkg/middleware/openapi/passport`](./passport/README.md), the local-verification authorizer for
  passport JWTs that delegates non-passport tokens and ACL lookups to the remote authorizer
- [`pkg/oauth2`](../../oauth2/README.md), which establishes bearer-token actor identity and session state
- [`pkg/principal`](../../principal/README.md), which defines delegated identity propagation
- [`pkg/rbac`](../../rbac/README.md), which converts identity and principal context into effective ACLs
- [`pkg/jose`](../../jose/README.md), which underpins token cryptography and JWKS publication
