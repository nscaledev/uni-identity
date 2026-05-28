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

Token-endpoint refusal preserves an authentication-vs-authorization split that downstream
middleware projects to the API edge:

- subject-token-related failures (missing, expired, malformed, principal not active) → `401`
  `access_denied`
- scope-related failures (valid subject token, but the principal is not a member of the requested
  organization or project) → `400` `invalid_scope` per RFC 6749 section 5.2

The 401/400 distinction is load-bearing for callers: it lets refresh-loop logic tell "your token is
bad, reauthenticate" apart from "your token is fine, you don't have access to that scope". The
remote middleware maps the latter to `403` `forbidden` at the downstream API edge.

Passport exchange is intentionally handled by the existing `/oauth2/v2/token` endpoint rather than a
separate route. Token-exchange parameters must be form-encoded in the POST body so credentials are not
accepted from URL query strings.

This keeps room for alternate authentication frontends to complement this package rather than replace
it: external authentication can happen outside identity, while identity remains the issuer of the
internal token shape consumed by downstream UNI services.

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
