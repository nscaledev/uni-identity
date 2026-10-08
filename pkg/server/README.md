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

1. request deadline
2. OpenTelemetry
3. logging
4. route resolver
5. RED metrics
6. CORS

The reasons matter:

- The request deadline runs first so it bounds all later work. The server's write timeout stops
  response writes but does not cancel the request context, so the deadline is the shorter of
  `--server-request-timeout` and `--server-write-timeout` minus two seconds. Those two seconds
  cover organization Lease cleanup and the response write. The server refuses to start if the
  deadline is shorter than an organization Lease takeover plus its critical section (see
  [`pkg/handler/allocations`](../handler/allocations/README.md)).
- OpenTelemetry must run first so trace context exists before anything else happens.
- Logging must run early so even requests that fail before deep routing or service-specific
  middleware still get captured, and so those logs can include the trace context established
  earlier.
- Route resolution must happen before middleware that depends on OpenAPI operation/schema metadata.
- RED metrics run after route resolution so labels contain stable OpenAPI paths, never resource IDs.
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
3. compute the request deadline and install the shared `core` middleware stack
4. install generic `NotFound` and `MethodNotAllowed` handling
5. construct process-wide identity helper services (`jose`, `userdb`, `rbac`, `oauth2`)
6. construct identity-specific middleware (`local` authorizer, validator, audit)
7. construct the top-level handler implementation
8. attach everything through the generated OpenAPI router and return `http.Server`

The command process publishes build metadata for its lifetime. It serves readiness on
`/readyz` on a separate health listener (`:6081`), which the Service does not expose, so the
ingress cannot route to it; other pods can still reach it on the Pod IP unless a NetworkPolicy
prevents that, and the chart does not install one. A failing probe gets a bare 503; the cause is logged. A replica is ready when
it is not shutting down and it has read the primary token signing key once. The key is
cluster-wide state written by the JOSE leader, so on a fresh install every replica stays not
ready until the first leader has written it. After that first read the probe does not call the
API server, so an API server slowdown cannot take every replica out of service together.
Leadership itself, external OIDC providers and the audit collector do not gate readiness.

On SIGTERM the process reports not ready, keeps serving for 5 seconds so endpoint removal reaches
every node, then stops the background work and drains in-flight requests for up to 10 seconds.
It exits only once the drain has finished. The chart's 30 second termination grace period covers
both; `pkg/server/shutdown.go` owns the timings.

This makes the trust pipeline an application-level invariant rather than a handler-by-handler
convention.

## Invariants

- `pkg/server` owns runtime composition, not business-domain behaviour
- the shared `core` middleware stack runs before identity-specific middleware
- middleware ordering is part of the package contract because later stages depend on context from
  earlier stages
- `jose`, `userdb`, `rbac`, and `oauth2` are process-wide shared services in the API server
- the API server reads Kubernetes directly, except through one synchronized read cache. The
  cache holds Organizations in the identity namespace, for namespace routing and the full
  organization list, and Quotas, Allocations and Projects in all namespaces, for the organization
  list includes. Revocation-sensitive token and membership state is always read directly
- each API server replica may keep only refreshable derived caches locally; authorization codes,
  sessions, revocation checks, allocation admission, and quota changes use persisted state or
  per-organization Kubernetes Leases instead
- JOSE key rotation is leader-elected through its Kubernetes Lease, while every replica reads the
  shared `SigningKey` resource for signing and verification
- generated OpenAPI routing, validation, and schema helpers are load-bearing parts of the runtime
  model
- API readiness means this replica can serve a request end to end: not shutting down and
  signing key read. The read cache syncs before the listener binds, so it needs no check. The
  `unikorn_server_ready` metric reports listener ownership only

## Caveats

- The package is highly ordering-sensitive. Small changes in middleware order can change trust,
  observability, or schema behaviour materially.
- Because this package is orchestration-heavy, stale documentation here is especially risky: it can
  give a false picture of how the service actually behaves at runtime.
- The package is intentionally coupled to the current built-in identity stack. Changing the authn or
  trust model would require coordinated changes across several of the composed subsystems.
- A lost API server that held an organization Lease delays that organization's allocation or quota
  requests until a contender has seen the Lease unchanged for its three-second duration and takes
  it over. The default eight-second request deadline leaves time for that and the critical section;
  a request that runs out of time gets a retryable HTTP 409. Other organizations and login traffic
  continue through remaining replicas.

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
