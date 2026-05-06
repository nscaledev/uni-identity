# Client

## Purpose

This package is the identity-specific realization of the generic client
machinery in [`core/pkg/client`](../../core/pkg/client/README.md).

Its main job is to construct outbound identity API clients that obey the same
internal trust model that identity enforces on inbound requests in
[`pkg/middleware/openapi`](../middleware/openapi/README.md).

In practice that means:

- building generated [OpenAPI](../openapi/README.md) clients for the identity API
- applying the internal service-to-service transport model
- propagating distributed trace context
- propagating delegated principal context in the form expected by the identity
  middleware stack
- exposing a few higher-level helpers for identity-specific lifecycle
  coordination

This is not a general client abstraction and it is not the main place where
Kubernetes client construction is documented. The Kubernetes/TLS foundations
come from [`core/pkg/client`](../../core/pkg/client/README.md). This package
turns those foundations into concrete identity API callers.

## Main Components

### BaseClient

`BaseClient` wraps:

- a Kubernetes client
- identity HTTP endpoint options
- optional HTTP client certificate configuration

It uses the shared TLS configuration support from
[`core/pkg/client`](../../core/pkg/client/README.md) to construct an
`http.Client` suitable for calling the identity API.

### APIClient

`APIClient(...)` is the normal service-to-service path.

It constructs a generated identity API client from [`pkg/openapi`](../openapi)
and applies request mutators for:

- W3C trace-context propagation
- service-to-service transport identity handling
- principal propagation from the current request context via
  [`pkg/principal`](../principal/README.md)

This is the outbound counterpart to the inbound normalization performed by
[`pkg/middleware/openapi`](../middleware/openapi/README.md).

### ControllerClient

`ControllerClient(...)` is the controller/provisioner path.

Instead of assuming an active request principal is already present in context,
it reconstructs the principal from a Kubernetes resource and applies it to the
outbound request using [`pkg/principal`](../principal/README.md).

This is what allows controller-style workflows to participate in the same
delegated identity model as API-originated calls.

### References

`References` is not just a convenience wrapper.

It provides idempotent add/remove operations for project dependency references
over the identity API, keyed from the shared resource-reference model in
[`core/pkg/manager`](../../core/pkg/manager/README.md).

That matters for lifecycle coordination because it gives other services a way to
block project deletion without requiring prior knowledge of the project
namespace. A project can remain undeletable while logical dependants still hold
registered references.

This is an important forward-looking deletion mechanism because it is based on
explicit dependency registration rather than only namespace-local descendant
discovery.

### Allocations

`Allocations` wraps the identity quota/allocation API used by API handlers and
controller-style resource lifecycles.

It exists so allocation create/update/delete flows are retriable and can be made
idempotent from the caller side, reducing unnecessary user-visible errors during
normal reconcile or teardown retries.

It is closely related to:

- [`pkg/handler/allocations`](../handler/allocations/README.md)
- [`pkg/handler/quotas`](../handler/quotas/README.md)

The current implementation still carries transitional debt: it persists the
returned allocation ID back onto the owning resource via annotation rather than
keying directly on the shared resource reference.

## Invariants And Guard Rails

- This package is the outbound realization of identity's internal trust model,
  not a general-purpose API client wrapper.
- Outbound identity API calls are expected to propagate trace context.
- Service-to-service identity calls are expected to propagate delegated
  principal information in the form consumed by
  [`pkg/middleware/openapi`](../middleware/openapi/README.md).
- Controller-originated calls should reconstruct principal context from durable
  resource metadata rather than assuming a live request principal exists.
- `References` and `Allocations` should be safe to retry during convergence and
  teardown flows.
- The shared resource-reference model from
  [`core/pkg/manager`](../../core/pkg/manager/README.md) is the correct durable
  identity for cross-service resource dependency tracking.

## Caveats

- The package name is broader than the real responsibility. The important part
  here is identity API client construction and identity-specific lifecycle
  helpers.
- `context.go` contains older static/dynamic Kubernetes-client scoping helpers.
  That is local legacy machinery, not the center of this package's design.
- `Allocations` still relies on an allocation ID annotation on the owning
  resource. The better long-term model is to key allocations directly by the
  shared resource reference.
- If request mutators drift from the expectations enforced by
  [`pkg/middleware/openapi`](../middleware/openapi/README.md), service-to-service
  trust semantics can break in subtle ways even though transport-level calls
  still succeed.
