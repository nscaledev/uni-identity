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

## Invariants

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
