# Generic Passport Exchange — Design Note

Status: draft for discussion
Owner: @nscale-peter
Last updated: 2026-06-01

## Problem

The passport token-exchange endpoint currently accepts subject tokens from two
sources:

- UNI-issued access tokens (validated via `GetUserinfo`)
- Auth0 access tokens (validated via `pkg/oauth2/auth0`, gated by
  `--auth0-exchange-issuer` / `--auth0-exchange-audience`)

The Auth0 path was the first concrete external-IdP integration. The validator
itself is mostly generic OIDC — but the package name, the passport `source`
label, the CLI flags, and the chart values all bake `auth0` into the codebase.
We want identity to be able to accept exchanges from any OIDC-compliant IdP
(Okta, Cognito, Entra, a self-hosted dex, …) without further code changes —
purely through configuration.

## What is actually Auth0-specific today

Walking the current implementation against the requirement:

| Concern | Auth0-specific? | Notes |
|---|---|---|
| JWKS fetch (`/.well-known/jwks.json`) | No | Standard OIDC discovery convention. |
| Signature, `iss`, `aud`, temporal claim validation | No | Pure OIDC. |
| `email` + `email_verified` requirement | No | Reasonable for any IdP that proves a human identity. |
| `https://unikorn-cloud.org/authz` claim sanity check | No, but contract-specific | UNI-defined claim. Could be emitted by any IdP that supports custom claims. Not actually load-bearing — see below. |
| Org membership lookup by email | No | UNI is authoritative; claimed `orgIds` are discarded. |
| Package name `pkg/oauth2/auth0` | Yes | Cosmetic. |
| Passport `source = "auth0"` | Yes | Hard-coded. |
| CLI flags `--auth0-exchange-{issuer,audience}` | Yes | Single-tenant only. |
| Chart values `identity.auth0Exchange.{issuer,audience}` | Yes | Single-tenant only. |

Net: the validator is ~95% generic. The remaining ~5% is naming and a
single-tenant config surface. The UNI authz claim is *checked* but its
`orgIds` are discarded; only the presence-and-shape sanity check influences
acceptance. We can either keep that as an opt-in contract or drop it.

## Federation vs. exchange: same provider, different capability

The existing `OAuth2Provider` CRD already represents an external IdP. A
reasonable first question is "isn't exchange just another OIDC provider
registration?". It's not — they describe the same IdP but bind UNI to it in
two different roles, with two different trust models. That's why the design
adds a separate `tokenExchange` block rather than re-using the existing
fields.

| | Federation (today) | Exchange (new) |
|---|---|---|
| UNI role | OAuth2 *client* | *Resource server* |
| Token type | `id_token` (with nonce, redirect, PKCE) | access token |
| `aud` semantics | UNI's `client_id` | UNI's advertised exchange audience |
| Credentials needed | `client_id` + `client_secret` | none — JWKS only |
| Trust attestation | UNI drove the flow end-to-end | IdP minted a token UNI did not directly request |
| Audience controlled by | UNI (its client registration) | IdP operator (when the token was minted) |

The key implication is that **federation trust does not transitively imply
exchange trust**. An Auth0 tenant configured for federated login attests to
"this person authenticated to UNI's client". The same tenant can also mint
access tokens for unrelated audiences — e.g. an internal analytics API —
where UNI was never the intended recipient. Accepting those at the exchange
endpoint would be a confused-deputy: UNI would be honouring an attestation
that was never about UNI.

Concretely this is why `tokenExchange.enabled` and `tokenExchange.audience`
are mandatory and independent of the federation config:

- `enabled` is the operator's explicit statement that *this IdP is allowed to
  attest user identity to UNI's exchange endpoint*, separately from whether
  it's allowed to drive browser logins.
- `audience` is the value UNI requires in the `aud` claim — typically a URI
  identifying UNI's exchange API, distinct from the federation `client_id`.
  This is what stops tokens minted for unrelated audiences from being
  replayed at the exchange endpoint.

Same CRD object (one provider, one record), two capabilities, each with its
own opt-in.

## Proposed design

### 1. Extend `OAuth2Provider` CRD with an exchange block

Add an optional `tokenExchange` block to `OAuth2ProviderSpec`:

```yaml
apiVersion: identity.unikorn-cloud.org/v1alpha1
kind: OAuth2Provider
metadata:
  name: auth0-prod
spec:
  type: custom
  issuer: https://nscale.eu.auth0.com/
  # existing fields (clientID, clientSecret*, etc.) unchanged
  tokenExchange:
    enabled: true                     # explicit opt-in, default false
    audience: https://identity.nscale.com
    # optional: claim contract
    requireAuthzClaim: true           # default false; require UNI authz claim
    requireVerifiedEmail: true        # default true
    # optional: which signing algs the IdP is allowed to use
    signingAlgorithms: [RS256]        # default [RS256]
```

Existing providers without `tokenExchange` are not exchange-eligible. This is
the explicit-opt-in we need for the trust model (see below).

### 2. Dispatch by issuer at exchange time

Replace the current `if isCompactJWS && a.auth0Validator != nil` branch with:

1. If the subject token is a compact JWS, peek at the unverified `iss` claim
   (header.payload split — *no signature trust yet*).
2. Look up an `OAuth2Provider` in the identity namespace whose `spec.issuer`
   matches and whose `spec.tokenExchange.enabled` is true.
3. Run the generic validator against that provider's `issuer` / `audience` /
   claim contract.
4. If no provider matches, fall through to the existing UNI userinfo path
   (which will reject foreign tokens as it does today).

The unverified `iss` peek is safe because it only selects *which* keyset to
verify against — actual trust still comes from JWKS-validated signature plus
`iss`/`aud` equality.

### 3. Rename and generalize the validator package

- Rename `pkg/oauth2/auth0` → `pkg/oauth2/external` (or fold into
  `pkg/oauth2/oidc`).
- Drop the `auth0`-named constants and replace with parameterized
  `ExchangeOptions` derived from the matched `OAuth2Provider`.
- Drop the `--auth0-exchange-*` flags and the
  `identity.auth0Exchange` chart values. The validator is constructed
  per-request (or per-provider, cached) from CRD state, not from process
  flags.

### 4. Stamp passport `source` from the provider

`passport.source` becomes the `OAuth2Provider` resource name (e.g. `auth0-prod`,
`okta-staging`). That keeps audit logs and downstream RBAC inspection
informative without coupling them to a specific vendor.

`PassportSourceUNI` stays as-is for the in-house path.

### 5. JWKS caching

Today the Auth0 validator builds a `gooidc.RemoteKeySet` lazily, once. With
multiple providers we want one keyset per provider, cached. The remote keyset
already handles rotation/refresh; we just need a `map[providerName]*Validator`
on the authenticator with cache invalidation when the CRD changes (a watch on
`OAuth2Provider` would handle this — same mechanism the federated-login flow
uses today).

## Trust model

The hard part isn't the code — it's making sure operators can't accidentally
trust the wrong IdP.

- **Explicit opt-in.** `tokenExchange.enabled` defaults to `false`. A provider
  configured only for federated login does *not* automatically accept exchange.
- **Audience binding.** `tokenExchange.audience` is required when enabled.
  Identity will only accept tokens whose `aud` matches — this prevents a
  legitimate Auth0 token issued for an unrelated API from being replayed at
  the exchange endpoint.
- **Claim contract documented.** We need a single page (probably under
  `docs/`) that specifies the contract any IdP must satisfy to be
  exchange-eligible: required claims, normalization rules (we lowercase
  `email`), how membership is resolved (always via UNI, never trust the
  token's claimed orgs), and what happens when the optional UNI authz claim
  is or isn't present.
- **Email-verified required by default.** Operators can opt out per provider
  but the default is "verified or reject".
- **No wildcard issuers.** Issuer match is exact-string against
  `spec.issuer`. We do not accept `iss` values that "look like" a known
  provider.

## Migration path

1. Ship the generic implementation behind the new CRD field. The legacy
   `--auth0-exchange-*` flags continue to work and are mapped internally to a
   synthetic `OAuth2Provider` named `auth0-legacy`. (Or: gate this whole
   change behind a feature flag and ship CRD-only from day one — see open
   questions.)
2. Update the chart so `identity.auth0Exchange.*` values render an
   `OAuth2Provider` with `tokenExchange.enabled: true` instead of CLI flags.
3. Mark the flags deprecated in a release; remove in the following one.

This is expand-contract: the CRD field is purely additive in v1, and the
deprecation of flags is a separate step.

## Open questions

1. **Feature flag vs. parallel deployment.** Do we want to keep
   `--auth0-exchange-*` working through one release (lower risk, slightly
   more code) or hard-cut to CRD on day one (cleaner, requires deployment
   coordination)?
2. **Per-provider rate limiting.** Today there's nothing stopping a misconfigured
   IdP from being hammered. Probably out of scope for v1 but worth a stub.
3. **What does `type: custom` mean for federation today?** If we keep the
   existing enum (`google`, `microsoft`, `github`, `custom`) we need to
   decide whether `tokenExchange` is valid for all of them or only `custom`.
   I think: valid for all — exchange acceptance is independent of how the
   provider is used for browser-based federation.
4. **Should the UNI authz claim be required, optional, or removed?** It's not
   load-bearing today. Argument for keeping it: defense-in-depth — an Auth0
   tenant that hasn't been configured with the UNI Action shouldn't be
   accidentally exchange-eligible. Argument against: extra coupling for
   IdPs that can't easily emit custom claims.
5. **Multi-audience.** Auth0 supports multiple audiences in one token.
   Today we check a single audience. Should the CRD accept a list?

## Out of scope

- Federated login flow refactoring. The existing `providers` package handles
  browser-based OIDC and is independently configurable. This design only
  affects the token-exchange endpoint.
- Service account or service-to-service token issuance.
- Revocation / introspection of exchanged passports beyond the existing
  expiry-cap rules.

## Concrete code-touch estimate

- `pkg/apis/unikorn/v1alpha1/types.go` + CRD regen — small.
- `pkg/oauth2/auth0` → `pkg/oauth2/external` rename + parameterization — small.
- `pkg/oauth2/passport.go` dispatcher — small.
- `pkg/oauth2/oauth2.go` validator construction moves from flags to a
  CRD-watching cache — medium.
- `charts/identity` values plumbing — small.
- Tests: extend `passport_test.go` to cover multiple providers and
  CRD-driven dispatch — medium.
- Docs: claim-contract page + update to `pkg/oauth2/README.md` — small.

Total: a focused two- to three-PR change, not a multi-week effort.
