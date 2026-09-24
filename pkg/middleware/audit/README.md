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

- log authenticated, scoped, state-mutating API activity
- attach actor, component, scope, resource, operation, result, and authorization-decision
  information
- rely on the normalized authorization context built earlier in the middleware stack

## Decisions and resource identification

Two gaps in the original selective design were closed together, since both are about completing
 what an audit record can prove rather than changing which requests are logged for their own sake:

- **The record previously carried no authorization decision.** An audit line showed that a request
  happened, not whether — and against what — it was authorized. The middleware now seeds a
  request-scoped decision accumulator (`rbac.NewDecisionAccumulatorContext`) into the request
  context **before** calling the handler chain, so every `Allow*` dispatch the handler performs
  appends an entry (resource kind, resource id, action, `allow`/`deny`/`unavailable`, reason) to it.
  Once the handler returns, the middleware reads the accumulator back
  (`rbac.DecisionsFromContext`) and attaches it to the record as the `decisions` field — converted
  to this package's own `Decision` DTO, matching `Resource`/`Operation`/etc. in `types.go`, so the
  record's on-wire shape stays decoupled from `pkg/rbac`'s internal type. A read or preflight method returns before
  seeding, because the method alone decides that those are never logged. Every other request is
  seeded unconditionally, since whether it ends up logged is only known after the handler runs, and
  one that turns out to be skipped simply discards its accumulator with the rest of its context. See [`pkg/rbac`](../../rbac/README.md#the-decision-stash) for the
  accumulator itself and why its outcome vocabulary is not a verbatim reuse of the PDP decision
  log's classifier.
- **Resource identification no longer guesses from the URL.** The original design
  reverse-engineered both the resource type and its instance id from the route's path shape: a URL
  segment for the type, a trailing `/{type}/{id}` regex for the id, and response-body emptiness to
  decide create-vs-action. That heuristic mis-typed several real routes — a group became `groups`
  instead of `identity:groups`, an organization quota update walked `path.Dir` up to
  `organizations`, and a service account token **rotate** (`POST .../{serviceAccountID}/rotate`,
  `x-no-body` in the spec) returned a populated body and was misread as a create, recording its type
  as `rotate`. Fixed: **type** is now read straight from the authorization decision the handler
  already made — the `ResourceKind` of the last entry in the request's decision accumulator
  (`rbac.DecisionsFromContext`, the same accumulator the `decisions` field above reads), i.e. the
  exact endpoint string the handler passed to `Allow*` (e.g. `identity:groups`). **id** is the value
  of the last `{param}` in the route's path template — the most specific resource the URL addresses
  — with one exception: a **create** (a `POST` carrying a `requestBody` to a collection, i.e. its
  path ends in a literal segment rather than an instance `{parameter}`) has its new id minted
  server-side, so it is read from the response body's canonical `metadata.id` instead, falling back
  to the path if the body carries none. A body-less action like rotate (`x-no-body`, no
  `requestBody`) is therefore never mistaken for a create regardless of what its response body
  contains — only the presence of a request body on a collection route decides that branch, never
  response-body shape.

## Invariants

- Audit logging depends on trusted authorization context already being present.
- `GET`, `HEAD`, and `OPTIONS` requests are never audit logged.
- The package is focused on mutating operations, not reads or preflight requests.
- Resource identification is authoritative, not heuristic: the type comes from the authorization
  decision the handler already made (`rbac.DecisionsFromContext`), and the id from the request
  itself — the response body's canonical metadata for a create, the last path parameter for every
  other audited op — never from custom per-handler audit code or URL guessing.
- The decision accumulator is seeded before the handler chain runs and is a no-op for any `Allow*`
  call outside this middleware (see `pkg/rbac`) — enriching the record never changes an
  authorization decision.
- The log record shape is intended to be stable enough for downstream audit processing.

## Caveats

- Global or unscoped calls may be intentionally skipped when the package cannot derive meaningful
  accountability context.
- Resource identification depends on the handler actually having called `Allow*`: if a handler
  returns without making a scope check, the decision accumulator carries no entry, so
  `resource.Type` is empty in that record. The id is still derived from the request independently,
  so the record is still emitted rather than dropped — a missing type is a gap to notice in the log,
  not a reason to withhold the rest of the record.
- The last-path-parameter id derivation assumes an audited route's final `{parameter}` names the
  instance being acted on, true of every route in this repo's spec today. A future route that ever
  places a non-instance parameter last (e.g. a trailing filter/query-style path parameter) would
  need a per-operation override extension to name the correct parameter explicitly; deliberately not
  built now (YAGNI), since no such route exists today.
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
