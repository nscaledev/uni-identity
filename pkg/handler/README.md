# `pkg/handler`

This package is the API application layer for identity.

## Intent

The handler layer sits below middleware and above the persisted Kubernetes resources.

It is where the identity API turns:

- authenticated and authorized request context
- OpenAPI request/response models
- persisted CRD-backed storage

into resource-specific behaviour.

At the top level, [`handler.go`](./handler.go) is mostly transport glue: it performs the final
handler-level RBAC checks, reads request bodies, delegates to resource-specific clients, and
normalizes response/error handling. The real package behaviour lives in the per-resource handler
clients beneath it.

## Shared Handler Model

Most handler clients are expected to follow the same broad pattern:

1. resolve scope
2. load current state where mutation is involved
3. convert user-facing request shape into required stored shape
4. merge system-owned metadata and derived context
5. write back with conflict detection
6. convert stored state back into user-facing read models

This is not a blind REST-to-CRD translation layer. The handler layer is allowed to enforce local
application invariants, reconcile related state, and reject requests that would create obviously
broken cross-resource relationships.

## Conventions

### Read / Modify / Write

Mutable API operations are intended to follow an explicit read/modify/write model.

That means the handler does not treat the request body as a full authoritative replacement for the
stored object. Instead it:

- reads the current object
- computes the desired user-controlled changes
- preserves or re-applies system-owned metadata and derived state
- writes the result back with concurrency protection

That final write step is a semantic requirement, not a preference for one Kubernetes client method
over another. A full `Update()` and an optimistic-locking `Patch()` are both valid so long as the
operation preserves the read/modify/write conflict-detection model.

This is the main reason many clients have both `generate(...)` and update-specific merge logic.

### Read Shapes Should Inform Write Shapes

The API is intended to make read/modify/write practical for clients too.

Where possible, read models should be close enough to update models that a caller can:

- read an object
- change the fields they control
- send it back as an update

System-owned or derived fields may be separated, but the user-controlled structure should stay
duck-typable across read and write forms where practical.

### Scope First, Storage Second

Handler clients generally resolve logical scope before touching storage.

Examples:

- organizations resolve visible tenancy roots
- organization-scoped clients resolve the parent organization and its current namespace
- project-scoped clients resolve the project namespace before reading or writing child resources

That keeps the user-facing scope model separate from raw Kubernetes access.

### Conversion Boundary

Handlers are responsible for the explicit boundary between:

- OpenAPI request/response types
- stored CRD resource shapes

This is why most clients have `convert(...)`, `convertList(...)`, and `generate(...)` helpers. The
external API model and the persisted storage model are related, but they are not the same thing.

### Shared Metadata Discipline

Handlers use the shared conversion and identity metadata helpers from `core` and local
`pkg/handler/common` rather than inventing per-client metadata rules.

That includes:

- resource naming and scoped metadata generation
- organization/project labels
- creator/modifier identity metadata
- metadata merge behaviour during updates

### Bad-Path Taxonomy

The handler layer should be secure by default when surfacing bad-path behaviour.

The status-code taxonomy is expected to follow these broad rules:

- `400`: the request shape or protocol-level structure is wrong
- `422`: the request is structurally valid but semantically wrong for the domain model
- `401`: authentication failed
- `403`: the caller is authenticated but not allowed to perform the operation
- `404`: the addressed resource is absent from the visible model
- `409`: the request is valid but conflicts with current state, including lost-update and
  uniqueness conflicts
- `5XX`: the fault is on the server side and the client cannot reasonably fix it

The disclosure model matters as much as the status code:

- `4XX` responses should be useful enough for honest clients to recover
- `5XX` responses should make it clear the problem is ours, not the caller's
- `403`, `404`, and some `422` paths must be careful not to reveal policy structure, tenant
  layout, or resource existence unnecessarily
- status-code, body, header, redirect, and timing differences can all become attacker-visible
  discrepancy factors

So this layer should prefer secure-by-default concealment where more specific error detail would
turn the API into an enumeration or policy oracle.

## Cross-Resource Consistency

Many handler clients do more than mutate one object.

Examples include:

- `users`, which coordinate global users, organization users, and groups
- `serviceaccounts`, which coordinate service accounts, groups, and token lifecycle
- `groups`, which coordinate members, roles, and project references
- `quotas` and `allocations`, which together implement a small accounting subsystem

So a recurring responsibility of the handler layer is manual cross-resource consistency
maintenance.

## Shared Caveat: Atomicity

This layer is built on Kubernetes objects, not an ACID database.

That has an important consequence: many handler-level invariants are only enforceable on a
best-effort basis.

Across the package, the common limitations are:

- multi-object updates are not truly transactional
- referential integrity is maintained in application logic rather than by the backing store
- partial failure can leave consistency gaps that later reconciliation or follow-up writes must
  repair

This is a systemic property of the storage model, not just an isolated flaw in one client.

## Package Map

- [`organizations`](./organizations/README.md): tenancy-root visibility and current `v1`
  namespace handoff
- [`roles`](./roles/README.md): filtered user-facing role catalogue
- [`users`](./users/README.md): global identity plus organization membership
- [`serviceaccounts`](./serviceaccounts/README.md): organization-local non-human identities with
  token rotation
- [`groups`](./groups/README.md): primary local delegation unit
- [`projects`](./projects/README.md): project-scoped selection of delegation units
- [`oauth2providers`](./oauth2providers/README.md): organization-scoped upstream provider
  configuration for the built-in auth flow
- [`quotas`](./quotas/README.md): organization-wide capacity contract
- [`allocations`](./allocations/README.md): consumption ledger checked against quotas

## Related Documentation

- [`pkg/middleware`](../middleware/README.md), which establishes the trusted request context that
  handlers consume
- [`core/pkg/server`](https://github.com/nscaledev/uni-core/blob/main/pkg/server/README.md), which documents the generic server
  and request-processing foundation beneath identity's service-specific handler layer
- [`core/pkg/server/conversion`](https://github.com/nscaledev/uni-core/blob/main/pkg/server/conversion/README.md), which provides
  shared metadata and API/storage conversion helpers used heavily here
- [`pkg/apis/unikorn/v1alpha1`](../apis/unikorn/v1alpha1/README.md), which defines the persisted
  resource contract the handlers read and write
