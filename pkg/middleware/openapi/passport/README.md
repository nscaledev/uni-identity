# `pkg/middleware/openapi/passport`

This package is the passport-first authorizer for downstream UNI services.

## Intent

`pkg/middleware/openapi/passport` is the request authorizer that turns every
incoming bearer token into a verified passport on the hot path and then
authorizes from passport-verified identity. Passports presented directly are
verified locally against identity's published JWKS. Bearer tokens that are
not passports are exchanged into a passport via identity's RFC 8693
token-exchange endpoint, then verified locally.

It exists so the hot authorization path can run on cached public-key material
instead of a remote bearer-token validation call, while preserving identity as
the single source of truth for signing keys, exchange policy, and ACLs.

Its main responsibilities are:

- detect whether an incoming bearer token is already a passport
- verify passport signature, issuer, expiry, audience, and `typ` claim against
  cached JWKS
- exchange non-passport bearer tokens for passports via identity's token
  endpoint, then verify the minted passport locally
- populate normalized authorization context from verified passport claims
- fall back to the configured legacy authorizer on token-exchange
  unavailability — and only on that error class
- delegate every ACL lookup to the configured legacy authorizer

## Trust Boundary Rules

- The passport JWT is the only source of identity facts when the local path
  is taken; the package does not consult any other claim source on the hot
  path.
- Verification is fail-closed: a token whose `typ` claim says it is a
  passport but which fails signature, expiry, issuer, audience, `typ`
  re-check, or whose `kid` is absent from a successfully fetched JWKS returns
  access denied without falling back to the legacy authorizer. All of these
  are credential failures (`ErrPassportInvalidSig` / `ErrPassportExpired`).
- Audience binding is enforced when the verifier is constructed with at least
  one expected audience. The token's `aud` claim must contain at least one of
  the verifier's accepted audiences. An unbound verifier (constructed with an
  empty audience list) accepts any audience and is therefore vulnerable to
  cross-service replay — production wiring must always supply an audience.
- A confirmed passport whose verification cannot proceed because the JWKS
  endpoint itself is unreachable or returns an unparsable response
  (`ErrJWKSUnavailable`) does not fall back to the legacy authorizer either.
  This is service degradation rather than a credential failure, so it is
  distinguished from `ErrPassportInvalidSig` to avoid classifying forged or
  stale-`kid` tokens as infrastructure outages.
- Token exchange has its own error taxonomy. `ErrTokenExchangeUnauthorized`
  fails closed (the source token is invalid). `ErrTokenExchangeFailed` also
  fails closed because the response was non-retriable policy/protocol output
  rather than transport degradation. Only `ErrTokenExchangeUnavailable`
  (transport or upstream availability failure) triggers the legacy-authorizer
  fallback, and that fallback still performs its own credential validation —
  it is an availability path, not an authorization bypass.
- ACL is **not** embedded in the passport. Every ACL request is delegated to
  the legacy authorizer, keyed off passport-verified identity, so RBAC stays
  consistent with the rest of the platform model and a stale or compromised
  passport cannot extend its own permissions.
- Passport-only authorization contexts (no source bearer token) trigger
  delegated-principal impersonation on the downstream ACL hop rather than
  bearer propagation. The internal service authenticates with mTLS and carries
  user context via `X-Principal` + `X-Impersonate`, keeping ACL resolution
  aligned with the platform's service-to-service trust model.

## Verification Path

- The package decodes the JWT payload without verifying the signature to read
  the `typ` claim. This is a routing hint only — non-passport tokens are
  exchanged via the token endpoint; a forged `typ` cannot grant access
  because signature verification still has to succeed.
- Passport signatures are verified using the cached JWKS public key whose
  `kid` matches the JWT header. The signature algorithm is restricted to
  ES512.
- Standard JWT claims (`iss`, `nbf`, `exp`, …) are validated after signature
  verification, with zero leeway. When audience binding is configured, the
  `aud` claim is validated alongside.
- The `typ` body claim is re-checked after full verification as
  defence-in-depth against type-confusion across token kinds signed by the
  same key.

## Token Exchange

- The exchange entry point is pluggable via the `TokenExchange` interface so
  embedding services can choose between an HTTP exchange against identity's
  `/oauth2/v2/token` endpoint or an in-process exchange (used by identity
  itself).
- The HTTP exchange POSTs an RFC 8693 form body and serialises the route's
  organization/project context as `x_organization_id` / `x_project_id`
  (matching the server's `TokenRequestOptions` schema). Sending the camelCase
  forms would be silently dropped by the server and would mint a passport
  without the route's intended scope.
- Exchange errors are classified into sentinels (`ErrTokenExchangeUnauthorized`,
  `ErrTokenExchangeUnavailable`, `ErrTokenExchangeFailed`,
  `ErrTokenExchangeInvalidResponse`, `ErrTokenExchangeMissingAccessToken`) so
  the authorizer can route between fail-closed and fallback paths.
- Exchange latency is observed on `identity_passport_exchange_duration_seconds`
  and outcomes are labelled on `identity_passport_exchange_total`.

## JWKS Cache

- The cache is populated lazily on the first authorization that needs a key.
  There is no startup-time fetch.
- A successful fetch is held for the configured TTL (default 5 minutes); a
  request for an unknown `kid` triggers a refresh so that key rotation
  propagates without operator intervention.
- Refresh outcomes are labelled on
  `identity_passport_jwks_cache_refresh_total` (trigger × result) for
  observability.
- Concurrent refreshes are coalesced via `singleflight` so a cold cache under
  high concurrency does not produce a thundering herd on identity's JWKS
  endpoint.
- HTTP fetches share the identity client's TLS configuration and are bounded
  by the embedding service's HTTP timeout to keep the hot path responsive
  when identity is degraded.

## Outbound Propagation

- The verified passport is carried on the authorization context alongside the
  original source token (when exchange occurred). Outbound principal
  injection propagates `X-Principal` and, on internal calls that accept
  bearer credentials, sets `Authorization: Bearer <passport>` so the next hop
  can verify locally without re-exchanging.
- The remote ACL hop is an exception — it uses delegated-principal
  impersonation rather than bearer propagation in passport-only contexts. See
  the `Trust Boundary Rules` section above.

## Caveats

- This package is intended for downstream services that have a network path
  to identity's JWKS and token-exchange endpoints. The identity service
  itself uses the in-process token exchange wired to `oauth2.Authenticator`.
- `ErrJWKSUnavailable` for a confirmed passport currently surfaces as a
  generic server error; once `core/pkg/server/errors` exposes an explicit 503
  surface, that path should map there so clients can distinguish credential
  failure from service degradation.
- Metrics are package-level and registered at import time; embedding services
  should reuse the default Prometheus registry rather than constructing their
  own.

## Related Documentation

- [`pkg/middleware/openapi`](../README.md), the parent middleware that
  selects between local, remote, and passport authorizers and owns the ACL
  cache keying
- [`pkg/middleware/openapi/remote`](../remote/README.md), the legacy
  authorizer this package delegates to for the exchange-unavailable fallback
  and for all ACL lookups
- [`pkg/oauth2`](../../../oauth2/README.md), which defines `PassportClaims`,
  the passport issuer, the token-exchange endpoint, and the JWKS publication
  endpoint
- [`pkg/principal`](../../../principal/README.md), which carries the
  delegated identity propagated by the outbound injectors
- [`pkg/jose`](../../../jose/README.md), which underpins the signing key
  material consumed via JWKS
