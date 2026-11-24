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

An update replaces `spec.groupIDs` with the requested list. A group link decides which groups get
project-scoped access, so `Update` checks that field separately from the project metadata.

The handler still checks `identity:projects` update at project scope. That check lets a caller edit
the name, the description and the tags. `Update` then adds a second check. It loads the project and
compares the stored and the requested group IDs as sets. Order and duplicate IDs do not count as a
change. A nil list and an empty list are the same set. `Update` finds the added IDs and the removed
IDs. The caller needs organization-level `identity:projects` update in these cases:

- The request adds an ID.
- The request removes the ID of a group that exists in the organization namespace. A request that
  clears the list removes each stored ID.

Global authority also passes. A removed link to an existing group can take project access from
members who have no other linked group. A link to a group that no longer exists gives no access to
anyone. Thus a caller with project-scoped update can drop that link.

To find out if a removed group exists, `Update` reads the `Group` from the organization namespace.
If the read returns NotFound, the group no longer exists. If the read returns a different error,
`Update` returns that error and persists nothing.

If the caller needs the permission and does not have it, `Update` returns a typed 403 and persists
nothing. The error description does not repeat the requested group IDs.

Create and update store the linked groups as a sorted set without duplicates. The handler accepts a
request with a repeated ID, and the stored list holds the ID once.

The guard runs before group validation. It reads a group only for a stored ID that the request
removes. It never reads an added ID, so a refused caller learns nothing about which requested IDs
exist. A caller who passes the guard gets the usual validation, so an unknown group, or a group of
another organization, is still a 400. Validation reads each requested ID. Thus a request that keeps
the ID of a group that no longer exists gets a 400.

The guard checks a permission, not a role name. A custom role that holds only project-scoped update
gets the same result as any other role that holds only that permission. The guard does not call
`rbac.AllowRole`. It decides who can manage group links. It does not check the roles that a linked
group carries. See [`pkg/rbac`](../../rbac/README.md) for how scope and grantability work.

PUT keeps its replacement meaning. It replaces the name, the description, the tags and `groupIDs`
with the values in the request. If the request has no description or no tags, the PUT removes them.
The schema requires `groupIDs`, so a body without it gets a 400 before `Update` runs. An empty list
clears the links. If the project has stored links to existing groups, a caller with project-only
authority then gets a 403. A client that edits metadata must send back the `groupIDs` that it read.

PUT keeps `spec.pause`, which the API does not show. `Update` builds the labels and the annotations
again. It sets the name label, the organization label and the description annotation from the
request. It sets the modifier annotations to the caller and the modified-time annotation to the
current time. It keeps the creator annotations and the principal labels of the stored project. It
removes all other labels and annotations. Fields outside the labels, the annotations and `spec`,
such as the finalizers, do not change.

A stale client with project-only authority can also get a 403. If another caller changed the links after the client read the
project, the old list is now a different set. The client must reload the project and not repeat
the write. The optimistic lock is separate. It returns a 409 if the project changes between the
read in `Update` and the patch. It does not cover a read that the client made earlier.

When the guard checks the permission and allows the change, it records one precondition decision.
The decision names `identity:projects`, the action `link-groups` and the project ID. The decision
uses the organization scope. A request that only drops links to groups that no longer exist records
no decision. The audit record lists a grant only when the response status is below 400. If the request
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
- an update through this package that adds a group link, or removes the link to an existing group,
  needs organization-level `identity:projects` update. Dropping a link to a group that no longer
  exists does not
- deleting a group first lists the projects of the organization. In each project that lists the
  group ID, it removes the first copy of the ID. The group delete handler checks organization-level
  `identity:groups` delete, and this removal does not run the group link guard. A second copy of
  the ID stays, and so does a link that another request adds while the delete runs. A stored link
  to a deleted group gives no access
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
