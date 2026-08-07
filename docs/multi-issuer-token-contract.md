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

When the email is found and the local user is active, the resolved `orgIds` from UNI are used.
UNI distinguishes two different not-found-or-not-usable cases:

- **Never onboarded** (no local user record for the email at all): if
  `allowExternalIdentity: false` (the default), the request is rejected with `access_denied`.
  If `allowExternalIdentity: true`, the subject is accepted with an empty `orgIds` slice — RBAC
  decides what that principal can reach. This is intended for global-role-binding subjects that
  are not registered as ordinary UNI users (e.g. CI service identities or staff accounts).
- **Exists but inactive** (the global `User` record's `state` is not `Active`): the request is
  always rejected with `access_denied`, **regardless of `allowExternalIdentity`**. A local
  suspension is a deliberate revocation; `allowExternalIdentity` only widens admission for
  identities UNI has never seen, never re-admits one UNI has explicitly deactivated. This check is
  scoped to the global `User` record only — nothing in the product currently writes a non-active
  global `User`, and a user suspended (or removed) from every organization instead resolves to an
  empty `orgIds` list with no error. That path is not closed by this change.

  The check can only fire on a record the lookup actually finds, and the lookup is **case
  sensitive**: `UserDatabase.GetUser` compares `spec.subject` verbatim, while the bearer path
  lower-cases the email claim before lookup (`auth0.Validator.validateEmail`). A `User` created
  with a mixed-case subject — the create API stores `spec.subject` as supplied — is therefore
  never matched, falls into the *never onboarded* branch above, and is admitted with empty
  `orgIds` when `allowExternalIdentity: true`, even while its record says suspended. Global role
  bindings match case-insensitively, so such a principal keeps its bound authority. Until the
  lookup and storage agree on normalization, revocation is only reliable for subjects stored
  lower-case; create users with lower-case subjects.

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
an empty `orgIds` slice can only reach resources through RBAC's global role binding resolution (if
matched by a `--global-role-binding` or legacy `--platform-administrator-subjects` entry) or
through other RBAC paths that do not require organization membership. Ordinary user access to
organization resources requires a UNI user record and group membership.

## Signing algorithms

The `signingAlgorithms` field limits which JWS algorithms are accepted from the provider.
When empty, it defaults to `[RS256]`. Only asymmetric algorithms are permitted; symmetric
algorithms (e.g. `HS256`) and `none` are rejected at trust-list build time. This constraint
applies regardless of what the provider's JWKS endpoint advertises.

## The `--global-role-binding` contract

Global privileges — platform administrators and any future issuer-wide grant — are all expressed
through one mechanism: a **global role binding**, mapping an `(issuer, subject | "*")` pair to a
set of role IDs. Implementation and full rationale live in
[`pkg/rbac/README.md`](../pkg/rbac/README.md#global-role-bindings); this section states the
operator-facing contract.

Bindings are registered with the repeated flag:

```
--global-role-binding=<issuer>::<subject>::<roleID>[,<roleID>...]
```

`issuer` must be the exact issuer URL the authenticating IdP emits (verbatim, matching the token's
`iss` — for Auth0, including the trailing slash) or the `uni` sentinel for UNI-local tokens.
`subject` is either an exact subject (an email address, matched case-insensitively with surrounding
whitespace trimmed on both sides) or the literal wildcard `*`, which matches every subject
authenticated by that issuer. Parsing is right-anchored — the role list follows the
*last* `::`, the subject sits between the second-to-last and last `::` — so issuer URLs containing
`::` (IPv6 literals) parse unambiguously.

**Wildcard semantics.** A wildcard-subject binding is clamped to the `read` operation of each
referenced role's global scopes, regardless of role content — but the clamp bounds verbs only, not
response sensitivity, so any role referenced by a wildcard binding must be individually
read-surface-audited before use (some read endpoints return credential material). Full rationale:
[`pkg/rbac/README.md#global-role-bindings`](../pkg/rbac/README.md#global-role-bindings). A wildcard
subject can never be combined with the `uni` sentinel issuer, since that would grant every
UNI-local user.

**Chart guard, not a substitute for the clamp.** The Helm chart also fails to render a wildcard
binding whose role(s) declare any non-`read` global operation, naming the offending binding, role,
and scope — no role shipped in `charts/identity/values.yaml` passes it today, so a wildcard binding
needs a dedicated, audited read-only role. It does not replace the runtime clamp above; why:
[`pkg/rbac/README.md#global-role-bindings`](../pkg/rbac/README.md#global-role-bindings).

**Parse-time rejections.** The process fails to start on: malformed grammar (fewer than two `::`
separators); an empty issuer, empty subject, or empty role-list member; a wildcard subject
combined with the `uni` sentinel; and an issuer that is neither the `uni` sentinel nor an absolute
URL (scheme + host, no commas or whitespace — this specifically catches accidentally comma-joining
multiple bindings into one flag value).

Legacy `--platform-administrator-subjects` / `--platform-administrator-role-ids` continue to work,
each subject translated into an exact (non-wildcard) global role binding. For UNI-local tokens the
issuer is the `uni` sentinel and a bare subject without the `::` prefix is equivalent. Bare entries
carry legacy-compatible semantics: while the deprecated `--auth0-exchange-issuer` flag is set, each
bare entry is mirrored at server construction onto that flag's issuer, so it matches both UNI-login
and Auth0-exchange sessions — exactly the issuer-unaware behaviour that predates issuer
qualification. A bare entry never matches a CRD-declared `bearerTrust` issuer, and a legacy subject
that is literally `*` stays an exact match — it never gains wildcard semantics.

Multiple administrators, or multiple bindings, may be given as repeated flags; the Helm chart
renders `platformAdministrators.subjects` as a single comma-joined `--platform-administrator-subjects`
value and `globalRoleBindings` as one `--global-role-binding` flag per subject in each entry.

### Operator invariants

**(1) Migration to explicit `issuer::subject` form is recommended but not forced.** A deployment
that has at least one `bearerTrust` provider and still carries a bare (UNI-sentinel)
`--platform-administrator-subjects` entry logs a startup warning (`Options.Validate`) and
continues to boot. The always-on runtime control is the issuer-qualified match in
`processUserAccountACL`, not the warning.

**(2) Every `--global-role-binding` issuer should be a trusted issuer.** `Options.Validate` also
warns, without blocking startup, when a binding's issuer is neither the `uni` sentinel nor one of
the currently trusted non-UNI `bearerTrust` issuers — note the deprecated `--auth0-exchange-issuer`
value is deliberately excluded from that trusted set, so a binding aimed at the legacy exchange
issuer warns too, even though it can still match a real token. Most often, though, this catches a
mistyped or stale issuer that can never match a real token. As with (1), the warning is advisory;
the issuer-qualified runtime match is the actual control.

Only (1) is skipped when the trusted non-UNI issuer list is empty — a bare admin entry only matters
once a non-UNI issuer is trusted to migrate away from. (2) has no such gate: it runs even against a
genuinely empty list, so with no `bearerTrust` providers configured every non-UNI binding issuer is
reported as untrusted. The caller that computes the trusted-issuer list distinguishes a `List`
failure on the `OAuth2Provider` resources from a genuinely empty result — on failure it logs that
the advisory check was skipped and does not call `Validate` at all, rather than risk misreading
"provider list unavailable" as "no non-UNI issuers trusted".

Note the legacy-flag mirror copies the flag value verbatim: a flag issuer lacking Auth0's canonical
trailing slash will not match the emitted `iss` — the same match-`iss`-verbatim rule stated above
applies to the flag too.

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
