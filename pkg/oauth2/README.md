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

In the current flow, a caller presents an access token as the `subject_token` and identity issues a
short-lived signed passport JWT. The passport records the source identity, account type, organization
context, optional project context, and requested audience/resource values. It does not embed an ACL.
The exchange computes ACL only to authorize the requested organization/project scope; downstream
services continue to resolve permissions through the normal remote authorizer path keyed off the
passport-verified principal.

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

### Source-token types and multi-issuer dispatch

The `subject_token` presented to passport exchange may be either:

- a UNI-issued access token (a JWE), validated through `GetUserinfo` against the local user database, or
- an external access token (a JWS) from any bearer-trusted OAuth2 provider.

The single entry point for both paths is `dispatchUserinfo`, which is also shared by the
direct-bearer surfaces described below.

**Routing on the JOSE header.** Dispatch routes on the JOSE header of the compact serialization
rather than counting dots. UNI access tokens are JWEs: their header carries an `enc`
content-encryption field. External access tokens are JWSs: their header carries `alg` but no `enc`.
The segment count (3 for JWS, 5 for JWE) is cross-checked against the header type so a stray
member cannot misroute a token. A bearer that is neither — for example after an upstream
access-token format change — is rejected outright and counted by
`unikorn_identity_bearer_tokens_unroutable`.

**External-token dispatch.** For a JWS, `dispatchUserinfo` calls `peekIssuer` to extract the `iss`
claim from the payload **without signature verification** (the peek only selects which keyset to
verify against; trust still requires JWKS-validated signature plus issuer and audience equality).
The issuer is then passed to `validatorForIssuer`, which:

1. Lists all `OAuth2Provider` resources in the **identity operator namespace**. Providers in
   organization namespaces are never trusted.
2. Filters to those with a `bearerTrust` block (bearer trust is opt-in; federation configuration
   alone never confers bearer trust).
3. Includes a synthetic `auth0-legacy` entry built from the deprecated `--auth0-exchange-issuer` /
   `--auth0-exchange-audience` flags when those are set, preserving backward compatibility.
4. Performs an **exact string match** on the issuer URL — the `iss` as the IdP emits it, verbatim
   (OIDC §3.1.3.7); no normalization. Operators must set `spec.issuer` to the exact `iss` (for
   Auth0, including the trailing slash).
5. Returns the per-provider `*auth0.Validator` (cached by provider name + spec fingerprint via an
   LRU cache) together with the `BearerTrustSpec` and provider name.

When `validatorForIssuer` returns a cache-not-ready error (informer not yet synced), the dispatcher
returns `503 Service Unavailable` — this is a transient warm-up condition, not a trust failure.
When the provider List succeeds but no provider matches the issuer, the token is rejected with
`401 Unauthorized`.

**`externalUserinfo`** then validates the token (signature, iss, aud, temporal claims, email,
optional authz-claim), looks up UNI organization membership by email, and builds the userinfo and
source-claims pair. UNI membership is always authoritative; claimed `orgIds` from the external
token are discarded.

**The `src_iss` claim.** The resulting `dispatchResult` carries both a `Source` (coarse provider
audit label, e.g. the `OAuth2Provider` name) and a `SrcIss` (the issuer URL verbatim, or the
`PassportSourceUNI` sentinel for UNI-local tokens). `SrcIss` is stamped on the minted passport as
`src_iss` and is the security-load-bearing value used by RBAC's platform-administrator fast-path.
The sentinel `"uni"` is deliberately not a valid URL so it cannot collide with a real issuer.

### Per-provider claim contract

Each bearer-trusted provider has a `BearerTrustSpec` that governs claim validation:

- **`audience`** (required): the value that must appear in the token's `aud` claim by membership.
- **`skipEmailVerification`** (default `false`): when `false`, the
  `https://unikorn-cloud.org/email_verified` claim must be present and `true`. Set to `true` only
  for providers that do not emit the claim.
- **`requireAuthzClaim`** (default `false`): when `true`, the `https://unikorn-cloud.org/authz`
  claim must be present with `acctype == "user"` and at least one `orgId`. Used as a defense-in-depth
  signal that the UNI post-login Action ran. The claimed `orgIds` are discarded regardless.
- **`allowExternalIdentity`** (default `false`): when `true`, subjects with no UNI user record are
  accepted with an empty `orgIds` slice instead of being rejected.
- **`signingAlgorithms`** (default `[RS256]`): permitted JWS algorithms. Only asymmetric algorithms
  are accepted; symmetric algorithms (e.g. `HS256`) and `none` are rejected at trust-list build time.

The full claim contract and operator invariants are specified in
[`docs/multi-issuer-token-contract.md`](../../docs/multi-issuer-token-contract.md).

### Bearer surfaces

External access tokens may be presented in three ways:

1. As the `subject_token` to the RFC 8693 token-exchange endpoint (`/oauth2/v2/token`),
   which returns a signed passport.
2. Directly as a bearer token to local-authorizer-protected endpoints (`/api/v1/*`),
   where the local authorizer dispatches them via `GetUserinfoFromBearer`.
3. Directly as a bearer token — or as the `access_token` form parameter — to the OIDC-advertised
   userinfo endpoint (`/oauth2/v2/userinfo`, both `GET` and `POST`), which dispatches via the same
   `GetUserinfoFromBearer` and returns the resolved userinfo claims.

All three paths share `dispatchUserinfo` and produce the same validation outcome. The two
direct-bearer surfaces report `surface="bearer"` on the `unikorn_identity_bearer_tokens_unroutable`
metric; token exchange reports `surface="exchange"`. Any unauthenticated caller can increment this
counter with a garbage bearer, so alert on a sustained rise rather than isolated events and expect
scanner noise. UNI access tokens resolve on the userinfo endpoint regardless of external-provider
configuration, as they always have.

### JWKS throttling

The per-provider validator throttles upstream JWKS fetches with a minimum refresh interval,
enforced by an HTTP transport wrapped around the `go-oidc` key set's client. The library refetches
JWKS whenever no cached key verifies a token's signature — on unknown kids and on forged signatures
over known kids alike — and only deduplicates concurrent refetches, so a stream of invalid tokens
could otherwise drive one JWKS request per token and exhaust the provider's rate limit. Tokens
verified by cached keys never reach the transport; a token demanding a refetch inside the interval
is rejected as invalid without contacting the provider. The interval is configurable via
`Options.JWKSMinRefreshInterval` and defaults to 60s. Each fetch is also bounded by a client
timeout: `go-oidc` runs the fetch detached from the per-request context and deduplicates concurrent
fetches against it, so an unbounded hung fetch would otherwise wedge the key set permanently.

Each suppressed fetch increments the `unikorn_identity_auth0_jwks_refreshes_throttled` counter
(the metric name is historical); a sustained rise is the refetch-storm attack signature and what to
alert on. Both this counter and `unikorn_identity_bearer_tokens_unroutable` are only exported when
the service runs with `--otlp-endpoint` set: core attaches the metrics reader only then, and the
chart leaves the endpoint unset by default, so a default deployment records the metrics but exports
nothing and the alerts cannot fire until that endpoint is configured.

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
