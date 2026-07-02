# `pkg/apis/unikorn/v1alpha1`

This package defines the persisted Kubernetes resource contract for the identity service.
It is the canonical schema for identity-owned resources and also implements the common
controller-facing helper contract expected by the shared `core` libraries.

## Intent

The package owns the `identity.unikorn-cloud.org/v1alpha1` API group and the types
stored behind the current identity API:

- `Organization`
- `Project`
- `Group`
- `Role`
- `User`
- `OrganizationUser`
- `ServiceAccount`
- `OAuth2Provider`
- `OAuth2Client`
- `QuotaMetadata`
- `Quota`
- `Allocation`
- `SigningKey`

This is intentionally not "schema only". Types that participate in the generic controller
machinery also implement helper behaviour such as:

- pause semantics
- status condition read/write helpers
- scheme registration
- resource label derivation where the surrounding controller model requires it

The schema/helper mix is by design. The package is part of the common contract that lets
the controller layer in `core` handle resources generically.

## Scoping Model

Kubernetes namespace layout and platform tenancy are separate concerns.

Identity's current external API is a `v1` model that is organization/project scoped in
the API path. That model is still live and production-relevant. In particular, the legacy
Kubernetes service still uses the older nested namespace layout, where organizations and
projects project into managed namespaces. That layout historically solved user-visible name
reuse and gave convenient cascading deletion behaviour.

At the same time, that namespace hierarchy is not the desired long-term architectural
direction for newer services. The direction used by newer services is:

- keep the same CRDs and underlying Kubernetes storage model
- preserve organization/project mappings in labels
- remove organization/project scope from most API paths
- use list filtering for scoped queries
- use direct resource ID addressing for most non-list operations

In other words, the storage model remains largely the same while the external API model
changes from scoped `v1` routing to a flatter `v2` routing model.

## Invariants

- This package is the source of truth for identity's persisted Kubernetes resource shapes.
- The package must remain compatible with the generic controller contracts defined in `core`.
- Kubernetes namespace is an implementation detail of storage and controller behaviour, not
  the complete definition of logical tenancy.
- Organization and project scope are logical properties of resources even when they are also
  reflected in namespace-oriented production behaviour.
- Labels must be applied maximally and transitively so resources carry the ancestry/context
  needed for indexed lookup.
- Labels are part of the storage query model, not optional decoration.
- The `v1` to `v2` API migration depends on those labels already being present on stored
  resources.
- `Role` scope remains split into `global`, `organization`, and `project`.
- `User` lifecycle remains explicit through `active`, `pending`, and `suspended`.
- `SigningKeySpec.PrivateKeys` is ordered newest first, so key rotation semantics depend on
  list order.
- `Group.UserIDs` is compatibility-only and `Group.Subjects` is the forward path for
  membership that may refer to identities outside the local user database.
- An `OAuth2Provider`'s issuer URL must be unique across all bearer-trusted providers in the
  operator namespace. Duplicate issuers produce undefined dispatch behavior.

## `bearerTrust` and multi-issuer bearer trust

`OAuth2ProviderSpec.BearerTrust` is a CRD-only field. It does not appear on the REST or OpenAPI
surface; there is no API endpoint for managing it. It is an operator trust anchor applied
directly to the cluster by platform operators.

When `BearerTrust` is non-nil on an `OAuth2Provider` in the **identity operator namespace**,
the identity service accepts access tokens from that provider's issuer on all bearer surfaces
(token exchange, `/api/v1/*`, `/oauth2/v2/userinfo`). Providers in organization namespaces are
never trusted for bearer tokens; only the operator namespace is consulted.

The verbatim issuer invariant: the issuer URL stored in `OAuth2ProviderSpec.Issuer` is matched
**verbatim** — both dispatch selection and token verification compare it to the token's `iss` by
exact string equality (OIDC §3.1.3.7), with no normalization. Operators must set `Issuer` to the
exact `iss` their IdP emits (for Auth0, including the trailing slash); a case- or slash-mismatched
value simply never matches and the token is rejected as an untrusted issuer.

`BearerTrustSpec` fields:

- `audience` (required at runtime): the value required in the token's `aud` claim.
- `allowExternalIdentity`: accept subjects with no UNI user record (empty `orgIds`).
- `skipEmailVerification`: skip the `email_verified` check.
- `requireAuthzClaim`: require the `https://unikorn-cloud.org/authz` claim.
- `signingAlgorithms`: permitted JWS algorithms (asymmetric only; defaults to `[RS256]`).

The full bearer-trust operator contract is in
[`docs/multi-issuer-token-contract.md`](../../../../docs/multi-issuer-token-contract.md).

## Label Query Model

The package follows the broader platform rule that resource labels should carry the maximum
useful context for indexed lookup. A resource should expose not just its own identity but
also the parent context needed for efficient queries.

Examples:

- a project carries its organization
- higher-level resources in other services may carry organization, project, network, and
  other ancestry as labels

This matters because labels are indexed. They are used as the queriable database surface
for operations such as:

- "give me all projects in an organization"
- "give me all instances on a network"

A missing contextual label is therefore not just untidy metadata. It breaks the query model.

## Caveats

- The package carries a dual reality: it supports current production behaviour used by the
  `v1` scoped API and legacy Kubernetes service, while also supporting the flatter API model
  used by newer service migrations.
- Some fields and helper methods exist partly because of older CD-linked or namespace-hierarchical
  workflows that are still relevant for compatibility.
- `OrganizationStatus.Namespace` and `ProjectStatus.Namespace` remain operationally relevant
  today, but are expected to become redundant as API routing stops depending on organization/project
  path scope.
- `ResourceLabels()` does not mean exactly the same thing for every type. Its usefulness
  depends on how that type participates in the generic controller model and older CD-oriented
  identification behaviour.
- The future API migration does not imply new CRDs. The same stored objects are intended to
  support both API generations.

## Cross-Repo Context

This package builds on shared patterns from `github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1`
for conditions, tags, and generic controller integration. When documenting or evolving this
package, prefer alignment with those shared contracts over service-local reinvention.
