# OpenAPI

## Purpose

This package is the canonical wire-contract package for the identity service.

Its job is to define the HTTP/API surface in one place and materialize that
contract into the generated client, server, router, and type bindings used by
the rest of the service.

The important point is that this package is not "just generated stubs". The
generated files are derivative. The authoritative source is
[`server.spec.yaml`](./server.spec.yaml), and the running service depends on
that contract both at build time and at runtime.

## What Lives Here

- `server.spec.yaml`: the authoritative API specification
- `types.go`: generated request/response/domain types
- `client.go`: generated typed client bindings
- `router.go`: generated server interface and router bindings
- `schema.go`: embedded schema used at runtime
- `builder.go`: a small local adapter used by
  [pkg/client](../client/README.md) to construct generated clients in the shape
  expected by the identity service

## Why This Package Matters

This package sits at the meeting point of several layers:

- [pkg/server](../server/README.md) uses it to bind the concrete handler
  implementation to the generated HTTP router
- [pkg/middleware/openapi](../middleware/openapi/README.md) uses the runtime
  schema for route resolution and request/response validation
- [pkg/client](../client/README.md) wraps the generated client with the
  identity service-to-service trust model
- [pkg/handler](../handler/README.md) implements the user-facing request and
  response semantics expressed by these types

So this package is the canonical wire contract, while those other packages
explain how the service enforces, consumes, or implements that contract.

## Visibility And Publication

The specification includes both externally relevant resource endpoints and
service-internal or protocol-supporting endpoints in one unified schema.

Annotations such as `x-hidden` control whether an endpoint appears in
public-facing generated documentation. They do **not** mean the endpoint is
outside the canonical API contract.

Keeping the schema unified matters because it allows:

- one generated client/server contract
- one runtime validation/routing source
- one merged documentation model for tools such as Mintlify

For public-facing API documentation, the specification should also be treated as
the primary authoring surface:

- every public-facing endpoint should have a `summary`
- every public-facing endpoint should have `tags` so related operations group
  together coherently in published docs
- every endpoint should have a meaningful `description` explaining what the user
  is doing, how the operation works, and any important caveats

## Invariants And Guard Rails

- `server.spec.yaml` is the source of truth; generated code is derivative
- the service runtime depends on the embedded schema, not only on generated Go
  interfaces
- schema changes can affect documentation, client generation, server binding,
  and request/response validation simultaneously
- public documentation quality depends directly on the quality of endpoint
  `summary`, `tags`, and `description` fields in the schema
- shared platform API primitives are imported from
  [`core/pkg/openapi`](../../core/pkg/openapi), rather than being redefined here

## Semantics That Live Elsewhere

The schema defines the transport contract, but a number of important service
semantics are intentionally documented in higher-level packages rather than
fully encoded here:

- [pkg/handler](../handler/README.md): read/modify/write mutation model, API
  error taxonomy, API/storage conversion rules
- [pkg/middleware/openapi](../middleware/openapi/README.md): trust-boundary
  behaviour, authentication paths, request/response validation
- [pkg/server](../server/README.md): runtime composition of the generated router
  into the actual middleware and handler stack
- [pkg/oauth2](../oauth2/README.md): token, session, and protocol semantics
  behind the OAuth2/OIDC endpoints

## Caveats

- the specification still contains historically layered surfaces such as older
  onboarding and built-in login flows, so the contract reflects the live system
  rather than only the preferred future architecture
- because generated code dominates the package by line count, it is easy to
  under-document the package even though it is architecturally central
- if higher-level docs drift from the schema, this package is the place where
  those mismatches become concrete first
