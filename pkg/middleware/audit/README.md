# `pkg/middleware/audit`

This package emits request-level audit records for state-changing API operations.

## Intent

`pkg/middleware/audit` is the accountability layer that turns normalized request context into audit
 log events.

It is intentionally selective rather than exhaustive. The goal is to record who changed what, in
 which scope, with what result and under what authorization decision, rather than logging every
 routine read.

That selectivity is deliberate for two reasons:

- reduce signal-to-noise for the end user or auditor consuming the logs
- avoid paying unnecessary logging cost on hot API paths at high request volumes

Its main responsibilities are:

- log write-like API activity
- attach actor, component, scope, resource, operation, result, and authorization-decision
  information
- rely on the normalized authorization context built earlier in the middleware stack

## Decisions and resource identification

The record now carries the authorization decision, and the rest of the record keeps its existing
 shape:

- **The record previously carried no authorization decision.** An audit line showed that a request
  happened, not whether — and against what — it was authorized. The middleware now seeds a
  request-scoped decision accumulator (`rbac.NewDecisionAccumulatorContext`) into the request
  context **before** calling the handler chain, so every `Allow*` dispatch the handler performs
  appends an entry (resource kind, resource id, action, `allow`/`deny`/`unavailable`, reason) to it.
  Once the handler returns, the middleware reads the accumulator back
  (`rbac.DecisionsFromContext`) and attaches it to the record as the `decisions` field — converted
  to this package's own `Decision` DTO, matching `Resource`/`Operation`/etc. in `types.go`, so the
  record's on-wire shape stays decoupled from `pkg/rbac`'s internal type. A `GET` returns before
  seeding, because the method alone decides that it is never logged. Every other request is
  seeded unconditionally, since whether it ends up logged is only known after the handler runs, and
  one that turns out to be skipped simply discards its accumulator with the rest of its context. See [`pkg/rbac`](../../rbac/README.md#the-decision-stash) for the
  accumulator itself and why its outcome vocabulary is not a verbatim reuse of the PDP decision
  log's classifier.
- **The resource field does not change.** `resource.type` and `resource.id` are still derived from
  the route and the response metadata, as before, because existing log consumers parse them. The
  kind the handler authorized (for example `identity:groups`, where `resource.type` says `groups`)
  is in `decisions[].resourceKind`.

## Invariants

- Audit logging depends on trusted authorization context already being present.
- `GET` requests are never audit logged.
- The package is focused on mutating operations rather than routine reads.
- Resource identification is derived from route structure and response metadata rather than custom
  per-handler audit code.
- The decision accumulator is seeded before the handler chain runs and is a no-op for any `Allow*`
  call outside this middleware (see `pkg/rbac`) — enriching the record never changes an
  authorization decision.
- The log record shape is intended to be stable enough for downstream audit processing.

## Caveats

- Global or unscoped calls may be intentionally skipped when the package cannot derive meaningful
  accountability context.
- The package depends on route shape and response structure matching the expected API patterns.
- If upstream middleware fails to populate authorization or route context correctly, audit quality
  degrades silently.

## Related Documentation

- [`pkg/middleware/openapi`](../openapi/README.md), which assembles the request context this package
  depends on
- [`pkg/middleware/authorization`](../authorization/README.md), which carries the actor facts used
  for audit attribution
- [`pkg/principal`](../../principal/README.md), which explains how delegated identity and attribution
  concepts relate to downstream accountability
- [`pkg/rbac`](../../rbac/README.md#the-decision-stash), which owns the decision accumulator this
  package seeds and reads, and the `Allow*` facade it observes
