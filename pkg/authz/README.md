# `pkg/authz`

This package carries the authorization decisions made while serving a request, so later
middleware can describe what happened without reconstructing it from the request's shape.

## Intent

Audit records have to say which organization and project an operation affected. That fact used to
be read out of the URL, because v1 APIs put it there:

```
/api/v1/organizations/{organizationID}/projects/{projectID}/networks/{networkID}
```

v2 APIs do not. Resources are addressed by ID alone, and tenancy is resolved from the resource's
own labels during the request. There is nothing in the path to read, so anything deriving scope
from the URL silently records nothing for every v2 operation.

The component that already knows is the authorizer. It cannot decide whether a caller may delete a
network without first resolving which project that network belongs to. This package is how that
answer is kept rather than discarded.

## Core model

A `Decision` is one authorization check: the endpoint, the access required, the scope it was
checked against, and the outcome. A `Recorder` accumulates them for one request and is carried in
the request context.

One request commonly produces several. Updating a group checks that the caller may update groups,
and then, for each role being added, that the caller may grant that role. Those are not separate
events — the second kind are preconditions of the first, and are the evidence for why it was
permitted. The recorder keeps them in the order they were made and leaves interpretation to the
consumer.

## Target

A `Target` says what a check was about: the resource type, the operation, the resource acted on,
and whether this is the operation the request is or a precondition of it.

`Operation` holds two facts rather than one, because they answer different questions. `Access` is
the permission required, which is what RBAC matches against. `Action` is what actually happened,
which is what an audit record needs. For plain CRUD they agree. They part company on an action
sub-resource: starting an instance and creating one are both `POST`, so the HTTP method cannot tell
them apart, and recording a start as "update" says nothing about what occurred. Keeping them
separate also forces a deliberate answer to what permission starting an instance should require,
rather than reusing whichever check happened to be nearest.

`Kind` separates the operation a request is from the checks it had to pass first. `Subordinate` is
the zero value deliberately: a decision whose kind was never stated must not be mistaken for the
request's own operation, because that would silently relabel a precondition as the event. A
mutating request that records no primary decision is a defect, and reporting that loudly is better
than emitting a wrong record quietly.

## Invariants

- Scope comes from the authorizer, never from the request path. The path is not a reliable source
  in v2 and is only accidentally one in v1.
- Identifiers are the typed ones from [`pkg/ids`](../ids/README.md), not strings. The point of
  those types is that the compiler refuses to interchange them, and a record of what happened is
  the last place to give that up.
- `Record` on a context with no recorder does nothing. Authorization also runs in controllers,
  tests and internal paths that never see the audit middleware, and a recording concern must never
  make those fail.
- `Decisions` returns a copy. A consumer describing the record must not be able to alter it.
- The recorder is append-only for the life of a request and safe to use concurrently, because
  per-item checks during a list may run in parallel.

## Caveats

- Only allowed decisions are recorded today. Refusals are representable, so the type will not have
  to change, but recording them has to wait until every service distinguishes a gate from a
  predicate. A predicate refusing is a resource filtered out of a list, which is routine; reporting
  it as a refusal would bury real refusals and make ordinary listing look like an attack. See the
  gates and predicates section of [`pkg/rbac`](../rbac/README.md).
- A decision made through one of the gates that predate the explicit form names no object and no
  action, and counts as a precondition rather than the request's own operation. Migrating the call
  site is what fills those in.

## Related Documentation

- [`pkg/rbac`](../rbac/README.md), which makes the decisions this package carries
- [`pkg/middleware/audit`](../middleware/audit/README.md), which is the intended consumer
