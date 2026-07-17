# `pkg/middleware/audit`

This package emits request-level audit records for state-changing API operations and for reads a
 spec has explicitly marked sensitive.

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

- log write-like API activity, and reads an OpenAPI spec marks with `x-unikorn-audit: sensitive`
- attach actor, component, scope, resource, operation, result, and authorization-decision
  information
- rely on the normalized authorization context built earlier in the middleware stack

## Decisions and the sensitive-read marker

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
  record's on-wire shape stays decoupled from `pkg/rbac`'s internal type. Seeding is unconditional
  (every request gets an accumulator) because whether a request will end up logged is only known
  after the handler runs; a request that turns out to be skipped simply discards its accumulator
  with the rest of its context. See [`pkg/rbac`](../../rbac/README.md#the-decision-stash-f2) for the
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
  response-body shape. This also means a **sensitive** read is not implicitly covered by the blanket
  GET skip: a GET whose OpenAPI operation carries the `x-unikorn-audit: sensitive` extension —
  console URLs, credentials/kubeconfig, SSH keys are the motivating examples — is logged exactly like
  a mutation instead of being skipped; every other GET is skipped exactly as before. The marker is
  declarative and central: each consumer annotates its own sensitive operations in its own OpenAPI
  spec, and this middleware only has to look for the one extension key
  (`route.Route.Operation.Extensions["x-unikorn-audit"]`, read via the route resolver already in
  context). The same last-path-parameter derivation resolves the id for a marked sensitive read,
  since these are typically sub-resource GETs (e.g. `.../{id}/kubeconfig`).

## Invariants

- Audit logging depends on trusted authorization context already being present.
- The package is focused on mutating operations and spec-marked sensitive reads, not routine reads.
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
- The `x-unikorn-audit: sensitive` mechanism is delivered here, but no operation in this repo's own
  spec is annotated with it yet; per-service annotation (e.g. compute's console/SSH-key reads,
  kubernetes' kubeconfig read) is a follow-up for those repos, not delivered by this package.

## Related Documentation

- [`pkg/middleware/openapi`](../openapi/README.md), which assembles the request context this package
  depends on
- [`pkg/middleware/authorization`](../authorization/README.md), which carries the actor facts used
  for audit attribution
- [`pkg/principal`](../../principal/README.md), which explains how delegated identity and attribution
  concepts relate to downstream accountability
- [`pkg/rbac`](../../rbac/README.md#the-decision-stash-f2), which owns the decision accumulator this
  package seeds and reads, and the `Allow*` facade it observes
