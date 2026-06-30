# Multi-Issuer Token Contract

This document specifies the contract any external identity provider must satisfy to be
bearer-trust-eligible in the UNI identity service, and states the invariants that operators
must uphold when enabling bearer trust for a provider.

See [`pkg/oauth2/README.md`](../pkg/oauth2/README.md) for the implementation description of how
these requirements are enforced at runtime.

## Opting a provider in

Bearer trust is opt-in. Adding a `bearerTrust` block to an `OAuth2Provider` CRD resource in
the identity operator namespace is the only way to enable bearer trust for a provider. Providers
configured solely for federated interactive login (browser-based OIDC) do not automatically receive
bearer trust.

```yaml
apiVersion: identity.unikorn-cloud.org/v1alpha1
kind: OAuth2Provider
metadata:
  name: my-idp
  namespace: <identity-operator-namespace>
spec:
  issuer: https://my-idp.example.com/
  bearerTrust:
    audience: https://identity.example.com
    allowExternalIdentity: false
    skipEmailVerification: false
    requireAuthzClaim: false
    signingAlgorithms: [RS256]
```

All fields in `bearerTrust` have safe zero-value defaults. Only `audience` is required at
runtime (empty audience is rejected when building the validator).

## Required token claims

The validator checks the following claims on every incoming token from a bearer-trusted provider:

| Claim | Requirement |
|---|---|
| `iss` | Must equal the `OAuth2Provider`'s `spec.issuer` **verbatim** (exact string match, case- and slash-sensitive, per OIDC §3.1.3.7); configure `spec.issuer` to the exact `iss` the IdP emits — for Auth0, with the trailing slash. |
| `aud` | Must include `bearerTrust.audience` by membership. |
| `exp` / `nbf` / `iat` | Standard temporal claims validated with the configured leeway. |
| `https://unikorn-cloud.org/email` | Must be present and non-empty after normalization. |
| `https://unikorn-cloud.org/email_verified` | Must be `true` unless `skipEmailVerification: true`. |

The email and email-verified claims use the `https://unikorn-cloud.org/` namespace because OIDC
access tokens do not carry bare `email`/`email_verified` claims (those live on the ID token).
Providers that surface email on access tokens using namespaced claims — as the UNI Auth0 post-login
Action does — satisfy this requirement directly.

## Email normalization

Extracted email addresses are lowercased and whitespace-trimmed before any UNI lookup.
Providers must emit the email address in a canonical form that survives this normalization
consistently. Normalization is applied before the UNI user database lookup and before the
email is stamped on the passport.

## Membership resolution

UNI is authoritative for organization membership. The external token's claimed `orgIds` (if any)
are discarded. Organization membership is always resolved through the UNI user database by
email address lookup.

When the email is found, the resolved `orgIds` from UNI are used. When the email is not found:

- If `allowExternalIdentity: false` (the default), the request is rejected with
  `access_denied`.
- If `allowExternalIdentity: true`, the subject is accepted with an empty `orgIds` slice.
  RBAC decides what that principal can reach. This is intended for platform-administrator
  subjects that are not registered as ordinary UNI users (e.g. CI service identities).

## The `https://unikorn-cloud.org/authz` claim

The `https://unikorn-cloud.org/authz` claim is an optional UNI-defined claim emitted by the
Auth0 post-login Action. Its behavior is governed by `requireAuthzClaim`:

- **`requireAuthzClaim: false` (default):** the claim may be absent or zero-valued. When absent,
  `acctype` defaults to `"user"`. The `orgIds` within the claim are never used for membership.
- **`requireAuthzClaim: true`:** the claim must be present with `acctype == "user"` and at least
  one non-empty `orgIds` entry. This is used as a defense-in-depth signal that the UNI post-login
  Action ran — not as a membership source.

In both cases the claimed `orgIds` are discarded. UNI membership is always resolved from the user
database, not from the token.

## `allowExternalIdentity` semantics

`allowExternalIdentity: true` does not grant any permissions by itself. A subject accepted with
an empty `orgIds` slice can only reach resources through the platform-administrator fast-path in
RBAC (if listed in `--platform-administrator-subjects`) or through other RBAC paths that do not
require organization membership. Ordinary user access to organization resources requires a UNI
user record and group membership.

## Signing algorithms

The `signingAlgorithms` field limits which JWS algorithms are accepted from the provider.
When empty, it defaults to `[RS256]`. Only asymmetric algorithms are permitted; symmetric
algorithms (e.g. `HS256`) and `none` are rejected at trust-list build time. This constraint
applies regardless of what the provider's JWKS endpoint advertises.

## The `issuer::subject` admin-list contract

Platform administrators are registered via the `--platform-administrator-subjects` flag using the
`issuer::subject` syntax, where `issuer` is the exact issuer URL of the authenticating IdP (verbatim,
matching the token's `iss`) and `subject` is the email address of the administrator:

```
--platform-administrator-subjects https://my-idp.example.com/::admin@example.com
```

For UNI-local tokens (access tokens issued by the UNI identity service itself), the issuer is the
`uni` sentinel and a bare subject without the `::` prefix is equivalent.

The issuer component is mandatory when any non-UNI bearer trust is configured. A deployment that
has at least one `bearerTrust` provider and still carries a bare admin subject will fail the
startup validation gate (`Options.Validate`). However, this gate is advisory and can be bypassed
by creating a `bearerTrust` CRD at runtime after startup; the always-on runtime control is the
issuer-qualified match in `processUserAccountACL`.

## Invariants

The following invariants must hold for any deployment using bearer trust. Violating them is
misconfiguration and may result in unauthorized access.

**(a) Email-namespace authority.** Adding an issuer as a bearer-trusted provider is an
assertion that this IdP is authoritative for the email namespace it attests. Overlapping
email authority — two providers that can both issue tokens for the same email address — is
misconfiguration. UNI has no mechanism to detect or prevent it; the operator is responsible
for ensuring that the set of trusted issuers collectively covers a disjoint email namespace.

**(b) `email_verified` is not a domain-ownership attestation.** The `email_verified` claim
indicates that the IdP performed some verification of the address at enrollment time. It does
not mean the IdP is authoritative over the email domain, and it does not prevent another
provider from asserting the same address. Operators must choose trusted issuers that each
own their claimed email namespace as an organizational matter, not as a technical enforcement.

**(c) `aud` is matched by membership.** The `aud` claim check uses set-membership semantics:
the configured `bearerTrust.audience` must appear somewhere in the token's `aud` array. A
token with multiple audiences is accepted if the configured value is among them. Operators
must ensure the configured audience value is specific enough to prevent replay of tokens
minted for unrelated audiences at this IdP.

**(d) Downstream passport decode is unverified (trusted channel).** The passport issued after
a successful bearer exchange is a short-lived signed JWT carried over internal service-to-service
channels. Downstream services decode passports without reverifying the signature on the original
bearer token — the identity service is the verification trust anchor. The internal channel trust
model is based on the assumption that connections between UNI services are made over a
mutually-authenticated channel (e.g. mTLS). Full sender-constraining of passports (proof-of-possession,
token-binding) is a separate, not-yet-implemented track.
