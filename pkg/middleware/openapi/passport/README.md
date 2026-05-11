# `pkg/middleware/openapi/passport`

This package is the local-verification authorizer for passport JWTs.

## Intent

`pkg/middleware/openapi/passport` is the request authorizer that downstream UNI services use to
verify short-lived passport JWTs against identity's published JWKS, without round-tripping to
identity for every authenticated call.

It exists so the hot authorization path can run on cached public-key material instead of a
remote bearer-token validation call, while preserving identity as the single source of truth
for both signing keys and ACLs.

Its main responsibilities are:

- detect whether an incoming bearer token is a passport
- verify the passport's signature, issuer, expiry, and `typ` claim against cached JWKS
- populate normalized authorization context from verified passport claims
- delegate non-passport bearer tokens to the remote authorizer untouched
- delegate every ACL lookup to the remote authorizer

## Trust Boundary Rules

- The passport JWT is the only source of identity facts when the local path is taken; the package
  does not consult any other claim source on the hot path.
- Verification is fail-closed: a token whose `typ` claim says it is a passport but which fails
  signature, expiry, issuer, `typ` re-check, or whose `kid` is absent from a successfully fetched
  JWKS returns access denied without falling back to the remote authorizer. All of these are
  credential failures (`ErrPassportInvalidSig` / `ErrPassportExpired`).
- A confirmed passport whose verification cannot proceed because the JWKS endpoint itself is
  unreachable or returns an unparsable response (`ErrJWKSUnavailable`) does not fall back to the
  remote authorizer either; the remote authorizer cannot validate that token type and silently
  accepting it would defeat the local-verification model. This is service degradation rather
  than a credential failure, so it is distinguished from `ErrPassportInvalidSig` to avoid
  classifying forged or stale-`kid` tokens as infrastructure outages.
- ACL is **not** embedded in the passport. Every ACL request is delegated to the remote
  authorizer, keyed off passport-verified identity, so RBAC stays consistent with the rest of the
  platform model and a stale or compromised passport cannot extend its own permissions.
- `ErrNotPassport` is the only error class that delegates to the remote authorizer — it is
  treated as a routing decision, not a failure. The remote authorizer then enforces its own
  trust boundary on those tokens.

## Verification Path

- The package decodes the JWT payload without verifying the signature to read the `typ` claim.
  This is a routing hint only — non-passport tokens fall through to the remote authorizer; a
  forged `typ` cannot grant access because signature verification still has to succeed.
- Passport signatures are verified using the cached JWKS public key whose `kid` matches the JWT
  header. The signature algorithm is restricted to ES512.
- Standard JWT claims (`iss`, `nbf`, `exp`, …) are validated after signature verification, with
  zero leeway.
- The `typ` body claim is re-checked after full verification as defence-in-depth against
  type-confusion across token kinds signed by the same key.

## JWKS Cache

- The cache is populated lazily on the first authorization that needs a key. There is no
  startup-time fetch.
- A successful fetch is held for the configured TTL (default 5 minutes); a request for an unknown
  `kid` triggers a refresh so that key rotation propagates without operator intervention.
- Refresh outcomes are labelled on `identity_jwks_cache_refresh_total` (`ttl`, `kid_miss`,
  `error`) for observability.
- HTTP fetches share the identity client's TLS configuration and are bounded by an explicit
  short timeout to keep the hot path responsive when identity is degraded.

## Caveats

- This package is intended for downstream services that have a network path to identity's JWKS
  endpoint. The identity service itself uses the local `oauth2`/`rbac` packages directly and
  does not need this authorizer.
- The local authorizer does not currently coalesce concurrent JWKS fetches; under a cold cache
  with high concurrency the same JWKS URL may be fetched more than once. This is acceptable for
  initial deployment but a candidate for `singleflight` later.
- `ErrJWKSUnavailable` for a confirmed passport currently surfaces as a generic server error;
  once `core/pkg/server/errors` exposes an explicit 503 surface, that path should map there so
  clients can distinguish credential failure from service degradation.
- Metrics are package-level and registered at import time; embedding services should reuse the
  default Prometheus registry rather than constructing their own.

## Related Documentation

- [`pkg/middleware/openapi`](../README.md), the parent middleware that selects between local,
  remote, and passport authorizers
- [`pkg/middleware/openapi/remote`](../remote/README.md), the authorizer this package delegates
  to for non-passport tokens and for all ACL lookups
- [`pkg/oauth2`](../../../oauth2/README.md), which defines `PassportClaims`, the passport issuer,
  and the JWKS publication endpoint
- [`pkg/jose`](../../../jose/README.md), which underpins the signing key material consumed via
  JWKS
