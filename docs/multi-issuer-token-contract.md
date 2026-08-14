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
| groups claim (the name is per-issuer configuration, e.g. `https://unikorn-cloud.org/groups`) | Optional. The validator reads it only when this issuer's `bearerTrust.groupsClaim` names it. The value must be a JSON array of strings when present. The validator skips non-string entries one by one. A missing claim, a non-array value, or entry filtering that leaves nothing usable all degrade to "no groups". The claim never causes token rejection. |

The email and email-verified claims use the `https://unikorn-cloud.org/` namespace because OIDC
access tokens do not carry bare `email`/`email_verified` claims (those live on the ID token).
Providers that surface email on access tokens using namespaced claims — as the UNI Auth0 post-login
Action does — satisfy this requirement directly.

The groups claim has no fixed name, unlike the fixed claims above. It is whichever claim the
`OAuth2Provider`'s `bearerTrust.groupsClaim` names for that issuer, and that name must be a
namespaced URI that contains `://`. It is not a contract constant that every provider must emit
under one identical key. An issuer with `groupsClaim` unset emits no groups as far as UNI is
concerned, and no group-based global role binding can ever match its tokens.

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
  always rejected with `access_denied`, **regardless of `allowExternalIdentity`**, because a local
  suspension is a deliberate revocation. The check covers the global `User` record only — nothing
  currently writes a non-active global `User`, while a user suspended in (or removed from) every
  organization still resolves to an empty `orgIds` list with no error.

  It can also only fire on a record the lookup finds, and the lookup is **case sensitive**:
  `UserDatabase.GetUser` compares `spec.subject` verbatim, while the bearer path lower-cases the
  email claim first (`auth0.Validator.validateEmail`) and the create API stores `spec.subject` as
  supplied. A mixed-case record is therefore treated as *never onboarded* and admitted with empty
  `orgIds` under `allowExternalIdentity: true`, even while suspended. Global role binding matching
  is case-sensitive too, so a mixed-case record gains no unearned authority through that path — the
  residual gap is narrower than a bypass: the inactive-user rejection simply cannot fire on a record
  its case-sensitive lookup cannot find. Until storage and lookup agree on normalization, create
  users with lower-case subjects.

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

Two mechanisms express global privileges — platform administrators and any future issuer-wide
grant. Both are rooted in the same `(issuer, ...)` shape:

- A **global role binding** maps an `(issuer, subject | "*")` pair to a set of role IDs.
- A **global group role binding** maps an `(issuer, group)` pair to a set of role IDs. It applies to
  any subject whose token carries that group in the issuer's configured `groupsClaim` (above).

This section states the operator-facing contract for the subject-keyed form. For the group-keyed
form, its grammar, matching rules, and consequences are in
[`pkg/rbac/README.md#group-bindings`](../pkg/rbac/README.md#group-bindings). Implementation and
full rationale for both live in
[`pkg/rbac/README.md`](../pkg/rbac/README.md#global-role-bindings).

Bindings are registered with the repeated flag:

```
--global-role-binding=<issuer>::<subject>::<roleID>[,<roleID>...]
```

`issuer` must be the exact issuer URL the authenticating IdP emits (verbatim, matching the token's
`iss` — for Auth0, including the trailing slash) or the `uni` sentinel for UNI-local tokens.
`subject` is either an exact subject (an email address, matched case-sensitively with surrounding
whitespace trimmed on both sides) or the literal wildcard `*`, which matches every subject
authenticated by that issuer. Parsing is right-anchored — the role list follows the
*last* `::`, the subject sits between the second-to-last and last `::` — so issuer URLs containing
`::` (IPv6 literals) parse unambiguously. Because matching is case-sensitive and the authenticated
subject always arrives lower-cased, a binding's subject must be in its canonical lower-case form;
the chart fails to render one that contains an upper-case ASCII letter (the wildcard `*` is exempt).

**Wildcard semantics.** A wildcard-subject binding is clamped to the `read` operation of each
referenced role's global scopes, and can never be combined with the `uni` sentinel issuer, which
would grant every UNI-local user. The clamp bounds verbs, not response sensitivity — some read
endpoints return credential material — so any role used this way needs a read-surface audit first.
The chart additionally refuses to render a wildcard binding on a role declaring any non-`read`
global operation; no role shipped in `charts/identity/values.yaml` passes that guard today. Why
both layers exist:
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

`Options.Validate` logs two advisory startup warnings and never blocks boot: a bare (UNI-sentinel)
`--platform-administrator-subjects` entry that should migrate to a `globalRoleBindings` entry,
and a `--global-role-binding` issuer outside the currently trusted set — usually a stale or
mistyped issuer that can never match a real token. Neither warning is a security control; the
issuer-qualified runtime match in `processUserAccountACL` is. Their gating, the deliberately
excluded legacy exchange issuer, and provider-list failure handling are documented in
[`pkg/rbac/README.md#global-role-bindings`](../pkg/rbac/README.md#global-role-bindings).

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
