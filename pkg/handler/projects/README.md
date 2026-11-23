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

### Group Link Guard

An update replaces the whole `spec`, including `spec.groupIDs`. A group link decides which groups
get project-scoped access, so `Update` checks that field separately from the project metadata.

The handler still checks `identity:projects` update at project scope. That check lets a caller edit
the name, the description and the tags. `Update` then adds a second check. It loads the project and
compares the stored and the requested group IDs as sets. Order and duplicate IDs do not count as a
change. A nil list and an empty list are the same set. `Update` then does one of these:

- If the sets are equal, `Update` makes no extra check.
- If the sets differ, the caller needs organization-level `identity:projects` update. Global
  authority also passes. A caller needs this permission to add a link, remove a link or clear the
  list. A removed link can take project access from members who have no other linked group.
- If the caller does not have this permission, `Update` returns a typed 403 and persists nothing.
  The error description does not repeat the requested group IDs.

Create and update store the linked groups as a sorted set without duplicates. The handler accepts a
request with a repeated ID, and the stored list holds the ID once.

The guard runs before group validation. A refused caller learns nothing about which group IDs exist.
A caller who passes the guard gets the usual validation, so an unknown group, or a group of another
organization, is still a 400.

The guard checks a permission, not a role name. A custom role that holds only project-scoped update
gets the same result as any other role that holds only that permission. The guard does not call
`rbac.AllowRole`. It decides who can manage group links. It does not check the roles that a linked
group carries. See [`pkg/rbac`](../../rbac/README.md) for how scope and grantability work.

PUT keeps its replacement meaning. The schema requires `groupIDs`, so a body without it gets a 400
before `Update` runs. An empty list clears the links. If the project has stored links, a caller with
project-only authority then gets a 403. A client that edits metadata must send back the `groupIDs`
that it read.

A stale client with project-only authority can also get a 403. If another caller changed the links after the client read the
project, the old list is now a different set. The client must reload the project and not repeat
the write. The optimistic lock is separate. It returns a 409 if the project changes between the
read in `Update` and the patch. It does not cover a read that the client made earlier.

When the guard allows a change, it records one precondition decision. The decision names
`identity:projects`, the action `link-groups` and the project ID. The decision uses the organization
scope. The audit record lists a grant only when the response status is below 400. If the request
succeeds, the record lists this decision as one grant. If the request fails later, for example on
group validation (400) or a lock conflict (409), the record has no grant. When the guard refuses, it
records no decision, because only the decision of the request itself keeps a refusal. The record
then shows the project update with status 403. See [`pkg/authz`](../../authz/README.md) and
[`pkg/middleware/audit`](../../middleware/audit/README.md).

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
- an update through this package that adds or removes a linked group needs organization-level
  `identity:projects` update
- deleting a group also removes it from the `groupIDs` of each project that lists it. The group
  delete handler checks organization-level `identity:groups` delete, and this removal does not run
  the group link guard
- a refused change to the linked groups persists nothing, and the refusal comes before group
  validation
- project deletion may be intentionally blocked while external dependents still hold references

## Caveats

- The package still depends on the current `v1` organization namespace handoff model through
  `pkg/handler/organizations`, even though the long-term API direction reduces the architectural
  importance of that routing pattern.
- Group validation here checks existence only. The guard above decides who can change the links.
  The deeper authority meaning of those groups belongs to `pkg/rbac` and `pkg/handler/groups`.
- A caller with organization-level `identity:projects` update can link any existing group of the
  organization. The guard does not check the roles that the group carries. Delegated link
  management by a project-only caller is not built.
- The organization list counts `projectsCount` by the organization label, in all namespaces.
  The per-organization list reads the namespace of the organization. Before the organization has
  a namespace, that read uses an empty namespace, which means all namespaces. The two counts also
  differ for an object whose label and namespace do not agree.

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
- [`pkg/authz`](../../authz/README.md), which keeps the decisions that the guard records
- [`pkg/middleware/audit`](../../middleware/audit/README.md), which turns those decisions into the
  audit record
- [`pkg/apis/unikorn/v1alpha1`](../../apis/unikorn/v1alpha1/README.md), which defines the stored
  `Project` resource and the broader `v1` to `v2` scoping transition
