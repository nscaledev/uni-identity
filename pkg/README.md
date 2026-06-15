# Packages

## Purpose

This tree contains the identity service implementation.

At a high level it splits into four layers:

- API and storage model definition
- authentication, delegated identity, and authorization
- request handling and server composition
- controller/provisioner lifecycle management

The package docs below are written so a reader can start from this summary and
then drill into the part of the system they need without rereading the whole
repository.

## Recommended Reading Order

### API And Identity Model

- [apis/unikorn/v1alpha1](./apis/unikorn/v1alpha1/README.md)
- [constants](./constants/README.md)
- [principal](./principal/README.md)
- [userdb](./userdb/README.md)

These packages define the resource model, runtime identity metadata, delegated
principal model, and the boundary between RBAC/authn consumers and the internal
identity storage layout.

### Trust, Tokens, And Authorization

- [jose](./jose/README.md)
- [oauth2](./oauth2/README.md)
- [rbac](./rbac/README.md)
- [client](./client/README.md)

These packages define how identity issues and validates tokens, how it resolves
effective authority, and how internal callers construct outbound requests that
match the same service-to-service trust model enforced on inbound requests.

### Middleware, Handlers, And Server Composition

- [openapi](./openapi/README.md)
- [middleware](./middleware/README.md)
- [handler](./handler/README.md)
- [server](./server/README.md)

These packages show how the request pipeline is assembled, how the API layer
applies read/modify/write and secure error-handling conventions, how the API
wire contract is defined and consumed, how authenticated service version
discovery is exposed through `GET /api/version`, and how the service composes
the generic `core` server stack with identity-specific trust logic.

### Controllers And Provisioners

- [controllers](./controllers/README.md)
- [provisioners/organization](./provisioners/organization/README.md)
- [provisioners/project](./provisioners/project/README.md)
- [provisioners/oauth2client](./provisioners/oauth2client/README.md)

These packages cover the controller-runtime side of the service: how manager
factories attach concrete resource types to the shared controller framework, and
how provisioners implement the current lifecycle behaviour for those resources.

## Important Cross-Cutting Themes

### Current And Future API Shape

The current `v1` API still carries historical organization/project scoping and
namespace handoff behaviour. The package docs call this out as current
operational reality, not the preferred long-term shape.

Start with [apis/unikorn/v1alpha1](./apis/unikorn/v1alpha1/README.md) and
[handler](./handler/README.md) if you need that distinction explained first.

### Delegated Identity

Identity makes a strict distinction between:

- who authenticated
- who the work is being done for
- what authority is actually effective

That model is explained across:

- [principal](./principal/README.md)
- [oauth2](./oauth2/README.md)
- [rbac](./rbac/README.md)
- [middleware/openapi](./middleware/openapi/README.md)
- [client](./client/README.md)

### Best-Effort Consistency

Much of the handler and lifecycle layer is implemented over Kubernetes objects
rather than an ACID database. As a result, some invariants are enforced
strictly by service logic while others are only best-effort across multi-object
workflows.

This is most visible in:

- [handler](./handler/README.md)
- [handler/users](./handler/users/README.md)
- [handler/groups](./handler/groups/README.md)
- [handler/quotas](./handler/quotas/README.md)
- [handler/allocations](./handler/allocations/README.md)

### Deletion Coordination

The service aims to keep parent deletion as the visible coordination point for
descendant teardown. In older parts of the system that is implemented partly via
hierarchy-aware provisioners; in newer parts it is also supported by explicit
dependency registration.

See:

- [provisioners/organization](./provisioners/organization/README.md)
- [provisioners/project](./provisioners/project/README.md)
- [client](./client/README.md)
