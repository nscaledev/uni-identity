# `pkg/middleware/audit`

This package emits request-level audit records for state-changing API operations.

## Intent

`pkg/middleware/audit` is the accountability layer that turns normalized request context into audit
 log events.

It is intentionally selective rather than exhaustive. The goal is to record who changed what, in
 which scope, and with what result, rather than logging every routine read.

That selectivity is deliberate for two reasons:

- reduce signal-to-noise for the end user or auditor consuming the logs
- avoid paying unnecessary logging cost on hot API paths at high request volumes

Its main responsibilities are:

- log write-like API activity
- attach actor, component, scope, resource, operation, and result information
- rely on the normalized authorization context built earlier in the middleware stack

## Where a record comes from

Everything in a record comes from the authorization decision the handler made, not from the
request's URL.

The URL was never a dependable source. v1 APIs happened to carry the organisation and project in
the path and v2 APIs do not, so scope was already unrecoverable there. Worse, the resource was
derived by matching a path ending in an identifier, and anything that did not match that shape was
dropped in silence: changing an organisation's quotas produced no record at all, and rotating a
service account credential was recorded against a resource type of `rotate`.

A missing entry in an audit log is not a gap, it is evidence that something did not happen. Guessing
from the request's shape produced both missing and wrong entries, which is why it is gone.

The decision supplies the scope, the resource type, the resource identifier and the action. One
exception remains: a create is authorised before the resource exists, so its identifier is still
read from the response body.

A request may make several decisions. Only those the handler marked as describing the request
itself become records; the checks it had to pass first, such as proving the caller may grant each
role they are adding to a group, are not separate events. A request acting on several resources
produces one record each.

A mutation that authorised something but never said what it was doing cannot be described. That is
reported as an `audit gap`, because silence is the failure this exists to prevent. The gap names the
endpoints that were checked and deliberately claims no operation: the HTTP method is the obvious
thing to reach for and it would be a lie, since a POST to an action sub-resource reads as a
creation, so a failed rotation would be reported as a create.

## Invariants

- Nothing in a record is derived from the request path.
- Audit logging depends on trusted authorization context already being present.
- The package is focused on mutating operations rather than routine reads.
- Resource identification is derived from route structure and response metadata rather than custom
  per-handler audit code.
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
