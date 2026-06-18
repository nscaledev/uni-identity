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

Service-to-service authentication is mTLS plus a propagated principal (`X-Principal`), not a token
grant. The historical `client_credentials`/`svc` token path has been removed; this package no longer
issues service-to-service tokens.

## Token Issuance and Introspection

The token endpoint issues UNI access tokens via the `authorization_code` and `refresh_token` grants
only. A UNI access token is a **signed JWS** (`at+jwt`, ES512): transparent, so a resource server
can verify it locally against the published JWKS and read its claims. Refresh tokens, authorization
codes and login state stay **JWE** — they are identity-internal and never presented to a resource
server. Legacy JWE access tokens issued before this change remain accepted until they rotate out.
`Verify` decodes either shape (`bearer.IsJWE`), then applies the same claim validation and session /
service-account check; `GetUserinfo` builds on it and is what the OIDC `/oauth2/v2/userinfo` endpoint
serves.

Authentication produces a **subject and account type only**. Organisation membership is
authorisation data, owned by UNI and resolved by [`pkg/rbac`](../rbac/README.md) from the subject
with request context — it is never read from a token. The subject and type come from the verified
token; `userinfo` additionally publishes the account type (a flat `acctype` field) purely so a
resource server introspecting an **opaque legacy JWE** can recover it.

Validation of **third-party (Auth0) access tokens** is not an issuance concern and lives outside
this package, in [`pkg/middleware/openapi/idp`](../middleware/openapi/idp), now a generic
multi-issuer JWS resolver (UNI and Auth0 are two issuer configs). Routing — JWE-vs-JWS by shape, then
JWS by its unverified issuer — lives in [`pkg/middleware/openapi/bearer`](../middleware/openapi/bearer).
Both authorizers ([`pkg/middleware/openapi`](../middleware/openapi/README.md)) consume them.

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
