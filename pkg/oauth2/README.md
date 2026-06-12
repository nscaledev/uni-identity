# `pkg/oauth2`

This package implements identity's OIDC/OAuth2 protocol layer.

## Intent

The package is the point where external identity proof is turned into UNI-internal token and
session state.

Its main responsibilities are:

- implement the authorization and token endpoints
- drive federated login against configured upstream identity providers
- issue UNI access tokens and refresh tokens
- validate UNI-issued tokens and project them into internal authn context
- expose userinfo/introspection-like behaviour for downstream consumers

Although the package name says `oauth2`, the responsibility is broader: it implements the OIDC/OAuth2
protocol boundary used by identity.

This implementation remains a supported first-party deployment option. It is particularly important
for local development and lower-friction deployments that should not require complex or costly
integration with another authentication service.

## Design Direction

Where possible, the package prefers stateless and opaque protocol handling.

Rather than persisting large amounts of protocol state server-side, it protects and round-trips
state using encrypted tokens:

- login dialog state
- upstream OIDC state
- authorization codes

That design reduces shared mutable state and helps the implementation scale without turning every
protocol step into a database-backed workflow.

## Internal Token Model

The package does not simply forward upstream provider tokens through the platform. It normalizes
external identity into UNI-issued tokens that downstream services can handle consistently.

The main token classes are:

- federated user tokens
- service account tokens
- service-to-service tokens

`pkg/jose` is the cryptographic trust anchor underneath this layer. `pkg/oauth2` defines how those
tokens are used, validated, refreshed, and mapped into local session semantics.

## Invariants

- This package is the built-in OIDC/OAuth2 implementation for identity and remains a supported path.
- The package should prefer stateless, opaque, encrypted protocol state where practical.
- UNI access tokens and refresh tokens are locally issued and locally verified.
- Authorization codes, login state, and related protocol artifacts are protected as JWE rather than
  trusted as plain client-supplied data.
- Redirect URI validation, PKCE validation, and client authentication are part of the security
  boundary.
- Federated user sessions are persisted per client in the user record.
- The package intentionally keeps a single active session/token chain per client.
- Refresh tokens are single-use.
- Reissuing tokens for a client session invalidates the prior active token for that session.
- This session model is intended to reduce replay risk and detect token reuse rather than allowing
  multiple independently active refresh-token chains for the same client.
- Token verification is intentionally cached because full validation is expensive.
- Token classes for federated users, service accounts, and services are intentionally distinct.
- Admission is intentionally coupled to local system validity: users who are inactive or not
  meaningful participants in the local authorization model should not be allowed to proceed as if
  they had a valid local identity.

## Relationship To RBAC

This package is intentionally somewhat coupled to RBAC.

The goal is not only to prove who a user is, but also to avoid admitting principals into the local
system when they are inactive or effectively not allowed to do anything useful. That is stricter
than a pure external-authentication boundary, but it reduces attack surface and keeps local actor
state aligned with local authorization rules.

`pkg/oauth2` therefore establishes identity and session context in a way that later RBAC resolution
can consume directly.

## Service Authentication Direction

Historically, client credentials tokens were used as the service-to-service authentication and
authorization mechanism, bound to X.509 client certificates.

That model is now transitional:

- it was workable, but operationally messy
- it has been superseded by direct mTLS identity derived from the client certificate common name

The `client_credentials` path is therefore still part of the package, but it is not the preferred
long-term service-to-service model.

## Token Exchange

The token endpoint implements the RFC 8693 token-exchange grant for UNI passports.

In the current flow, a caller presents a validated UNI access token as the `subject_token` and identity
issues a short-lived signed passport JWT. The passport records the source identity, account type,
organization context, optional project context, and requested audience/resource values. It does not
embed an ACL. The exchange computes ACL only to authorize the requested organization/project scope;
downstream services continue to resolve permissions through the normal remote authorizer path keyed
off the passport-verified principal.

Token-endpoint refusals follow RFC 6749 §5.2:

- malformed token-exchange requests (missing or unsupported `subject_token` fields) →
  `400 invalid_request`
- presented subject-token failures (expired, malformed, principal not active) → `401 access_denied`
- scope failures (valid subject token, principal not a member of the requested org/project) →
  `400 invalid_scope`

The remote middleware maps `invalid_scope` to `403 forbidden` at the API edge.

Passport exchange is intentionally handled by the existing `/oauth2/v2/token` endpoint rather than a
separate route. Token-exchange parameters must be form-encoded in the POST body so credentials are not
accepted from URL query strings.

This keeps room for alternate authentication frontends to complement this package rather than replace
it: external authentication can happen outside identity, while identity remains the issuer of the
internal token shape consumed by downstream UNI services.

### Source-token types

The `subject_token` presented to passport exchange may be either:

- a UNI-issued access token, validated through `GetUserinfo` against the local user database, or
- an Auth0 access-token JWT, validated through `pkg/oauth2/auth0` against the Auth0 tenant JWKS.

The Auth0 path is opt-in and requires both `--auth0-exchange-issuer` and `--auth0-exchange-audience`
to be set; partial configuration fails closed at startup. When only one of the two is set, the
identity process refuses to start. When neither is set, Auth0 tokens are not accepted and the
existing UNI path is unaffected.

For Auth0 tokens, validation covers signature, issuer, audience, temporal claims, verified email,
and the UNI authorization claim emitted by the Auth0 post-login Action (`acctype` and non-empty
`orgIds`). Because Auth0 only places the standard `email`/`email_verified` claims on the ID token —
and a post-login Action cannot set bare, non-namespaced claims on the access token — the Action
surfaces them on the access token as the namespaced `https://unikorn-cloud.org/email` and
`https://unikorn-cloud.org/email_verified` claims, which is where this validator reads them from.
The claimed `orgIds` are required as a signal that the Action ran but are intentionally
not used as organization membership: UNI's user database remains authoritative for which
organizations a principal belongs to. The minted passport's `source` claim records whether the
exchange originated from a UNI or Auth0 subject token, and the passport expiry is capped at the
source token's `exp` so a passport never outlives the proof of identity that produced it.

Auth0 access tokens may be presented in two ways:

1. As the `subject_token` to the RFC 8693 token-exchange endpoint (`/oauth2/v2/token`),
   which returns a signed passport.
2. Directly as a bearer token to local-authorizer-protected endpoints (`/api/v1/*`),
   where they are dispatched to the Auth0 validator via `GetUserinfoFromBearer`.

Both paths use the same validation and membership resolution, via one shared dispatcher
(`dispatchUserinfo`). It routes on the JOSE header rather than a token's dot count: UNI
access tokens are JWEs (an `enc` header) and resolve through the local userinfo path, while
a JWS is treated as an Auth0 access token. A bearer that is neither — for example after an
upstream access-token format change — is rejected outright and counted by
`unikorn_identity_bearer_tokens_unroutable`, so such a change alerts quickly instead of
surfacing as scattered generic 401s. (An empty bearer is the common client misconfiguration,
not a format change, so it is rejected without counting.) Any unauthenticated caller can
increment this counter
with a garbage bearer, so alert on a sustained rise rather than isolated events and expect
scanner noise. The second path is available only when Auth0 exchange
is configured and avoids the token-exchange round-trip for user calls against the identity
service itself.

The Auth0 validator throttles upstream JWKS fetches with a minimum refresh interval,
enforced by an HTTP transport wrapped around the `go-oidc` key set's client. The library
refetches JWKS whenever no cached key verifies a token's signature — on unknown kids and
on forged signatures over known kids alike — and only deduplicates concurrent refetches,
so a stream of invalid tokens could otherwise drive one JWKS request per token and
exhaust the Auth0 tenant rate limit. Tokens verified by cached keys never reach the
transport; a token demanding a refetch inside the interval is rejected as invalid
without contacting Auth0. The interval is configurable via
`Options.JWKSMinRefreshInterval` and defaults to 60s. Each fetch is also bounded by a
client timeout: `go-oidc` runs the fetch detached from the per-request context and
deduplicates concurrent fetches against it, so an unbounded hung fetch would otherwise
wedge the key set permanently.

Each suppressed fetch increments the `unikorn_identity_auth0_jwks_refreshes_throttled`
counter; a sustained rise is the refetch-storm attack signature and what to alert on. The
throttled path also logs, but at most once per refresh interval — under a storm the
throttle fires on nearly every request, so a per-request log would reproduce the flooding
it prevents. Both this counter and `unikorn_identity_bearer_tokens_unroutable` are only
exported when the service runs with `--otlp-endpoint` set: core attaches the metrics reader
only then, and the chart leaves the endpoint unset by default, so a default deployment
records the metrics but exports nothing and the alerts cannot fire until that endpoint is
configured.

## Caveats

- The package mixes protocol handling, provider integration, local session persistence, local user
  admission checks, and token issuance. It is not a narrow wrapper around an OAuth library.
- The package reaches into higher-level local concepts such as user database lookups and RBAC-aware
  admission decisions, so it is intentionally not protocol-pure.
- Service token support and passport token exchange are both transition-sensitive areas and should be
  read in the context of the broader authn/authz evolution, not as isolated features.
- Federated access tokens are still effectively bearer-style UNI tokens rather than sender-constrained
  tokens, so replay resistance depends more on lifetime, rotation, and session invalidation than on
  proof-of-possession.
- Refresh token rotation and single-use enforcement are in place, but this area should continue to be
  reviewed against current OAuth security guidance for stronger replay-compromise handling.

## Related Documentation

- [`pkg/jose`](../jose/README.md), which provides key rotation, JWKS publication, and token
  cryptography
- [`pkg/userdb`](../userdb/README.md), which shields this package from the raw local
  `User`/`OrganizationUser`/`ServiceAccount` storage joins used to resolve local identity state
- [`pkg/apis/unikorn/v1alpha1`](../apis/unikorn/v1alpha1/README.md), which defines the persisted
  user, provider, client, and signing-key resources this package relies on
- [`pkg/rbac`](../rbac/README.md), which consumes the identity and session context established here

## TODO

- Mark the silent reauthentication session cookie as `Secure` for normal deployments so it is never
  sent over a non-TLS transport path, while allowing an explicit insecure-cookie mode for local HTTP
  development if that workflow must remain supported.
- Harden login input validation in provider inference paths such as email-to-organization mapping so
  malformed input fails closed without panic-prone parsing.
