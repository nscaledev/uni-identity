# `pkg/server`

This package is the runtime assembly layer for the identity API process.

## Intent

`pkg/server` is where the identity service turns its documented building blocks into one running
HTTP server.

It does not own the shared generic server framework in the way `../core/pkg/server` does, and it
does not own business behaviour in the way handlers do. Instead it composes:

- the shared `core` server substrate
- identity-specific authn/authz and trust middleware
- the concrete handler layer
- the helper services those layers depend on

into one application-level runtime pipeline.

## What Is Specific Here

### Identity Runtime Composition

This package wires together the process-wide services that the rest of the API stack relies on:

- `jose` for token cryptography and JWKS/signing-key lifecycle
- `userdb` for local identity resolution
- `rbac` for effective authority construction
- `oauth2` for built-in token and session handling
- middleware for request-time trust assembly
- handlers for resource-specific API behaviour

That makes `pkg/server` the place where separately documented packages become one coherent identity
service.

### Shared Core Stack Plus Local Trust Stack

The package deliberately composes two layers of middleware:

- the shared pre-routing server pipeline from `core`
- the identity-specific post-routing trust pipeline

This split is important because it preserves platform-wide request behaviour while still allowing
identity to inject its own authentication, authorization, principal, validation, and audit model.

## Middleware Ordering

The ordering here is intentional and should be read as precedent for other API services.

### Pre-Routing Shared Middleware

The `core` middleware stack is applied directly to the raw router in this order:

1. OpenTelemetry
2. logging
3. route resolver
4. CORS

The reasons matter:

- OpenTelemetry must run first so trace context exists before anything else happens.
- Logging must run early so even requests that fail before deep routing or service-specific
  middleware still get captured, and so those logs can include the trace context established
  earlier.
- Route resolution must happen before middleware that depends on OpenAPI operation/schema metadata.
- CORS comes after route resolution because its schema-driven `OPTIONS` behaviour depends on the
  resolved route information.

This is dependency layering, not arbitrary taste. Each stage establishes context the next stage
needs.

### Post-Routing Identity Middleware

Identity-specific middleware is then attached through the generated OpenAPI server wrapper.

The current stack is:

- OpenAPI validator / local authorizer
- audit

Those are applied in reverse by the generated router wrapper, so the validator/authorizer becomes
the inner trust-establishing layer around handlers, and audit wraps the resulting handler execution
with normalized identity and authorization context already available.

The important architectural rule is:

- generic transport/request context first
- route/schema context next
- service-specific trust context after routing
- audit and handlers after trust context exists

## Runtime Flow

At a high level, `GetServer()` does the following:

1. build the OpenAPI schema helper
2. create the raw router
3. install the shared `core` middleware stack
4. install generic `NotFound` and `MethodNotAllowed` handling
5. construct process-wide identity helper services (`jose`, `userdb`, `rbac`, `oauth2`)
6. construct identity-specific middleware (`local` authorizer, validator, audit)
7. construct the top-level handler implementation
8. attach everything through the generated OpenAPI router and return `http.Server`

This makes the trust pipeline an application-level invariant rather than a handler-by-handler
convention.

## Invariants

- `pkg/server` owns runtime composition, not business-domain behaviour
- the shared `core` middleware stack runs before identity-specific middleware
- middleware ordering is part of the package contract because later stages depend on context from
  earlier stages
- `jose`, `userdb`, `rbac`, and `oauth2` are process-wide shared services in the API server
- generated OpenAPI routing, validation, and schema helpers are load-bearing parts of the runtime
  model

## Caveats

- The package is highly ordering-sensitive. Small changes in middleware order can change trust,
  observability, or schema behaviour materially.
- Because this package is orchestration-heavy, stale documentation here is especially risky: it can
  give a false picture of how the service actually behaves at runtime.
- The package is intentionally coupled to the current built-in identity stack. Changing the authn or
  trust model would require coordinated changes across several of the composed subsystems.

## Related Documentation

- [`core/pkg/server`](https://github.com/nscaledev/uni-core/blob/main/pkg/server/README.md), which defines the shared server
  substrate this package builds on
- [`core/pkg/server/middleware`](https://github.com/nscaledev/uni-core/blob/main/pkg/server/middleware/README.md), which defines
  the canonical shared pre-routing middleware pipeline composed here
- [`pkg/middleware`](../middleware/README.md), which defines the identity-specific trust pipeline
  attached after routing
- [`pkg/handler`](../handler/README.md), which defines the resource-specific API behaviour invoked
  once request context has been normalized
- [`pkg/userdb`](../userdb/README.md), [`pkg/rbac`](../rbac/README.md),
  [`pkg/oauth2`](../oauth2/README.md), and [`pkg/jose`](../jose/README.md), which are the main
  process-wide helper services assembled here
