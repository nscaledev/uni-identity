# `pkg/middleware`

This package tree contains the request-shaping and trust-boundary machinery that sits between raw
HTTP transport and the business handlers.

## Intent

The middleware layer is where UNI request handling becomes coherent.

It is responsible for taking:

- transport facts
- token facts
- client certificate facts
- delegated principal facts
- authorization and ACL facts

and assembling them into a normalized request context that handlers can safely consume.

At a high level, the middleware stack is responsible for:

- authenticating requests
- validating requests and responses against the OpenAPI contract
- propagating and normalizing delegated identity
- carrying request-local authorization facts
- emitting audit records for meaningful state changes

## Package Roles

- [`openapi`](./openapi/README.md) is the core integration layer where authentication, principal
  propagation, ACL resolution, request validation, and response validation are assembled into a
  single request pipeline
- [`authorization`](./authorization/README.md) carries normalized authorization facts such as token,
  userinfo, account type, and propagated client certificate context
- [`audit`](./audit/README.md) turns that normalized context into selective write-path audit events

## Architecture Role

This package tree is where the rest of the documented stack gets composed:

- [`pkg/oauth2`](../oauth2/README.md) establishes actor identity and local token/session validity
- [`pkg/principal`](../principal/README.md) defines delegated identity and impersonation semantics
- [`pkg/rbac`](../rbac/README.md) computes effective authority
- `pkg/middleware` makes those layers usable at request time
- handlers then consume the normalized result

That is why middleware is such an important documentation point for this and later services: it is
the first place where the platform model is visible as a complete execution path instead of a set of
separate concepts.

## Invariants

- Middleware packages here are part of the trust boundary, not mere plumbing.
- Request normalization should happen centrally so handlers do not need to rediscover raw authn/authz
  facts independently.
- Delegated identity, actor identity, and effective authority are kept distinct but assembled into one
  handler context.
- Selective audit logging is preferred over exhaustive logging to preserve signal and control cost on
  high-RPS paths.

## Caveats

- Much of the security posture of the service depends on middleware invariants remaining true, especially
  around trusted ingress header handling and principal propagation.
- Some transitional compatibility behaviour still exists in lower-level middleware packages and should
  continue to be treated as deletion candidates rather than normalized design.

## Reading Order

For drill-down:

1. [`openapi`](./openapi/README.md)
2. [`authorization`](./authorization/README.md)
3. [`audit`](./audit/README.md)
