# `pkg/jose`

This package is the cryptographic trust anchor for identity, primarily for `pkg/oauth2`.

## Intent

The package owns two tightly related responsibilities:

- signing-key lifecycle management
- JOSE/JWT/JWE issue and verification primitives

Its primary consumer is `pkg/oauth2`, which relies on it to issue and validate the tokens used
by the identity service. It is also general enough to issue JWTs for other audiences that can
validate them against the service JWKS endpoint.

This is not just a helper around a crypto library. The package defines the live rotation model,
the published verification material, and the token compatibility window that higher layers depend on.

## Key Lifecycle Model

The root cryptographic material comes from a cert-manager managed TLS secret. `JWTIssuer.Run()`
uses leader election so only one replica manages key rotation state at a time.

The package then projects that live key into the `SigningKey` resource as a rolling compatibility
window:

- the first key is the current primary
- the second key is the immediately previous primary

New tokens are always issued with the current primary. Verification and decryption accept either
the current or previous key so tokens survive one rotation, but not two.

## Invariants

- `pkg/oauth2` is the primary consumer, but the package also supports other JWT/JWE issuing use
  cases that rely on the same JWKS and rotation model.
- The cert-manager private key is the source cryptographic material for token issue.
- `SigningKey.Spec.PrivateKeys` is an ordered compatibility window, not a passive backup copy.
- Only one active leader should mutate the `SigningKey` window.
- Key ordering is semantically significant: newest first.
- Issued tokens are expected to survive one key rotation and fail after the signing key is rotated
  out of the retained window.
- `kid` lookup is mandatory for verification and decryption.
- Token `typ` values are part of the security model and are used to prevent reuse across token
  contexts.
- Signed JWTs use ES512.
- Encrypted tokens are nested signed-then-encrypted JWTs.
- The symmetric encryption key used for JWE is intentionally derived from the signing private key.

## OAuth2 Relevance

This package should be read as the cryptographic substrate under `pkg/oauth2`:

- it publishes JWKS material
- it signs tokens
- it encrypts token payloads
- it defines how long old tokens remain valid across key rotation

Higher layers should not redefine those rules independently.

## Caveats

- This package is coupled to Kubernetes runtime state. It depends on cert-manager managed secrets,
  leader election, and the `SigningKey` resource.
- Signing and encryption material are intentionally coupled. That is a pragmatic design here, but
  it should not be mistaken for a generic best-practice template.
- The package contains a transition compatibility path for decrypting older `ECDH_ES` tokens even
  though new token issue had already switched to `A256GCMKW`.
- `ECDH_ES` was an expedient choice when originally written, but it is not an acceptable steady-state
  issue model here. Anyone with the public key material from JWKS can encrypt their own token
  payloads. The only reason the decode fallback is tolerable as a migration aid is that ES512
  signatures are still enforced on the nested token.
- That `ECDH_ES` path is a bounded, one-way migration aid for already-issued tokens, not a permanent
  design requirement or mixed ongoing algorithm support.
  `A256GCMKW` issuance landed in commit `194bc975` and first shipped in `v1.4.0` on July 31, 2025.
  The fallback was explicitly added in commit `a54875e3` and first shipped in `v1.4.1` on August 18,
  2025. With the default 90-day token/renewal window from the charts, the conservative safe-removal
  point was approximately November 16, 2025.
- Some token types in this package support older onboarding or email-related flows. Those are not
  the architectural center of the package and should not dominate its documentation.

## Cross-Repo Context

The package exposes a JWKS-based trust model that can be consumed outside `identity` itself. Other
internal services may legitimately depend on tokens issued here so long as they follow the same
verification and rotation assumptions.

## Related Documentation

- [`pkg/apis/unikorn/v1alpha1`](../apis/unikorn/v1alpha1/README.md), which defines the `SigningKey`
  resource this package manages
