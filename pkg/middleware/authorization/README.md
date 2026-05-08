# `pkg/middleware/authorization`

This package carries request-local authorization facts through the middleware and handler stack.

## Intent

`pkg/middleware/authorization` is a context-and-header helper package for normalized authorization
state.

It exists to make the already-established identity facts of a request available to later layers
without forcing each package to rediscover them from raw headers or tokens.

Its main responsibilities are:

- carry normalized authorization information in request context
- distinguish user, service account, and system account request modes
- propagate the originating client certificate through an internal service chain when needed

## Invariants

- `Info` is the canonical request-local authorization payload.
- Authorization facts are set once by trusted middleware and then consumed downstream.
- The propagated client certificate is carried verbatim from the trusted ingress/service chain
  headers and is used primarily for certificate-bound token handling.
- Client certificate propagation is contextual and explicit, not global process state.
- This package does not itself authenticate the request; it carries the results of authentication.

## Caveats

- The package is intentionally small, but it sits on a trust boundary because downstream packages
  assume the information here has already been normalized by trusted middleware.
- The client certificate propagation model depends on the surrounding ingress and middleware
  invariants that prevent end-user spoofing of internal certificate headers.
- Incorrect or missing context population here breaks later principal, RBAC, and audit behaviour.

## Related Documentation

- [`pkg/middleware/openapi`](../openapi/README.md), which populates and consumes this context
- [`pkg/oauth2`](../../oauth2/README.md), which provides bearer-token userinfo and token facts
- [`pkg/principal`](../../principal/README.md), which carries delegated identity alongside these
  authorization facts
