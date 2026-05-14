# `pkg/principal`

This package defines the delegated identity and attribution contract used by identity and
related services.

## Intent

The package records who a request is for and who originated it, then carries that information
across:

- in-process request context
- service-to-service HTTP headers
- persisted resource labels and annotations

Its primary purpose is attribution and delegated identity propagation, not direct authorization.

That attribution is used for:

- auditing
- billing
- quota management
- ownership lineage
- support and operational investigation

This matters most when a service acts on behalf of a principal while still executing with its own
system identity.

The package also supports the stricter case where a service acts as a principal. That signal is
consumed later by RBAC to resolve effective authority with least-privilege behaviour.

## Core Model

The package distinguishes several concerns that must not be collapsed:

- attribution: who the work is for or who originated it
- placement: where the resulting resource lives
- visibility: whether the attributed principal can see or manage the resulting resource
- effective authorization: what the caller is actually allowed to do

Those concerns often overlap, but they are not equivalent.

For example, a service may create a resource on behalf of a user inside a service-owned
organization or project. The user is still the correct attribution subject for audit, billing,
or quota purposes, but may have no direct visibility of that resource.

## Invariants

- `Principal` is the canonical delegated identity payload.
- `X-Principal` carries propagated principal identity across HTTP calls.
- `X-Impersonate` is not just attribution metadata; it changes how downstream RBAC should resolve
  effective authority.
- Acting on behalf of a principal and acting as a principal are different modes and must remain
  distinct.
- Persisted resource labels and annotations are part of the delegated identity contract, not just
  in-flight request context.
- Reconstructing principal information from resource metadata is a supported and expected workflow.
- Missing principal-related labels or annotations on resources that require them are consistency
  failures.
- The package is designed to work closely with the request injection machinery in `core/pkg/client`
  and with downstream RBAC resolution.

## Resource Attribution Model

`FromResource()` and `ControllerInjector()` show that delegated identity is durable, not merely
transport-scoped.

Resources may carry:

- placement context such as organization/project ownership
- principal-specific organization/project context
- creator attribution
- creator-principal attribution for work done on behalf of someone else

That distinction allows downstream services to answer questions like:

- who created this resource directly?
- on whose behalf was it created?
- where does it live?
- who should quota or billing be attributed to?

## Caveats

- Attribution does not imply visibility. A principal may be the correct audit or billing subject
  for a resource that lives in service-owned scope and is not exposed back to that principal.
- Attribution does not by itself grant access. Effective access is a later RBAC concern.
- Impersonation is semantically sharp. Misusing it risks broadening authority instead of merely
  preserving attribution.
- Older resources may lack the newer principal metadata, so transition-era gaps are possible.
- The package reuses API-facing identity vocabulary from `pkg/openapi`, so it is intentionally
  coupled to the broader authn/authz model rather than being a fully isolated abstraction.

## Relationship To RBAC And Handlers

This package becomes operationally important in two later layers:

- RBAC, where service authority and principal authority may be intersected to enforce least
  privilege
- API handlers and downstream service clients, where delegated identity becomes user-visible
  through request routing, filtering, ownership attribution, and access decisions

It should therefore be read as part of an end-to-end model:

- handlers and clients propagate identity
- resources persist attribution context
- RBAC interprets the authority consequences

## Cross-Repo Context

This is not a repository-local helper. The delegated identity model is intended to compose cleanly
with `core/pkg/client` and with later service repositories that need consistent attribution,
service-to-service scoping, and least-privilege delegated access behaviour.

## Related Documentation

- [`pkg/rbac`](../rbac/README.md), which consumes delegated identity and impersonation signals to
  compute effective authority
