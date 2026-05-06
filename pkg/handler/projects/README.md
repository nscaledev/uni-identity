# `pkg/handler/projects`

This package handles organization-scoped project resources.

## Intent

Compared with the organization client, this package is much closer to the standard shape of an
identity handler client: it resolves the parent organization, operates in that organization's
namespace, and performs read/modify/write updates on the `Project` resource.

What makes it specific is not generic CRUD, but the fact that projects are the first child
tenancy layer beneath organizations and therefore:

- carry organization context into lower-level resources
- select which groups participate in project-scoped access
- expose deletion-blocking hooks for dependent services

## What Is Specific Here

### Organization-Scoped Child Resource

Projects live inside the namespace currently associated with their parent organization.

This package therefore depends on the organization handler client for namespace resolution and then
acts as the normal child-resource client beneath that tenancy root.

### Group Reference Validation

Projects may reference groups through `spec.groupIDs`.

This client validates that those group IDs exist inside the same organization namespace before
persisting the project. That keeps the project/group relationship locally coherent and avoids
storing obviously broken access-boundary references.

More importantly, those groups are not arbitrary tags. They are the already-established local
delegation units created elsewhere in the handler tree:

- users and service accounts become members of groups
- groups bind those members to roles
- projects then choose which of those groups apply at project scope

So `groupIDs` is the project-level selector over the organization's local delegation structure.

### External Reference Blocking

Projects provide explicit reference-add and reference-remove helpers.

These are used by higher-level services to register an external dependency on a project so that
project deletion is blocked until that dependency is released. The implementation uses Kubernetes
finalizers, but the package-level purpose is more important than the mechanism: this is the point
where project lifecycle is made visible to dependent services.

That makes projects the first handler client in the tree with an explicit "other services may hang
off this resource" contract.

## Invariants

- projects are always resolved relative to an organization
- project writes preserve organization context in metadata and labels
- referenced groups must exist in the same organization scope
- project deletion may be intentionally blocked while external dependents still hold references

## Caveats

- The package still depends on the current `v1` organization namespace handoff model through
  `pkg/handler/organizations`, even though the long-term API direction reduces the architectural
  importance of that routing pattern.
- Group linkage here is intentionally existence-based validation only. The deeper authority meaning
  of those groups belongs to `pkg/rbac` and `pkg/handler/groups`.

## TODO

- Make the reference add/remove paths follow the same explicit optimistic-locking read/modify/write
  discipline as the main update path.

## Related Documentation

- [`pkg/handler/organizations`](../organizations/README.md), which provides the parent
  organization metadata and current namespace handoff used here
- [`pkg/handler/groups`](../groups/README.md), which defines the local delegation units selected
  here for project-scoped access
- [`pkg/rbac`](../../rbac/README.md), which defines how project scope and group-derived authority
  are interpreted
- [`pkg/apis/unikorn/v1alpha1`](../../apis/unikorn/v1alpha1/README.md), which defines the stored
  `Project` resource and the broader `v1` to `v2` scoping transition
