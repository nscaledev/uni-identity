# Role controller

## Purpose

The role controller lets an organization admin hold, and so grant, service
roles such as `fleet-operator`, without changing the grant rule.

A service role opts in with a label. An aggregating role (for example
`administrator`) selects those labels. This controller collects the scopes of
every source role into the aggregating role's `status.effectiveScopes`. The
grant rule (`rbac.AllowRole`: you may grant only what you hold) then passes on
its own.

This is the model Kubernetes uses for `ClusterRole` aggregation
(`aggregate-to-admin`, `aggregate-to-edit`, `aggregate-to-view`). Design and
sign-off: ID-368 (Phase B) and ID-550.

The computation lives in [`pkg/aggregation`](../../aggregation/README.md). This
package only runs it and writes the result.

## Terms

- **Source role:** a role with an `identity.unikorn-cloud.org/aggregate-to-<role>: "true"` label.
- **Aggregating role:** a role with `spec.aggregationRule`.
- **Effective scopes:** what a role holds. `Role.EffectiveScopes()` returns
  `spec.scopes` for a normal role and `status.effectiveScopes` for an
  aggregating role. Every reader of a role's scopes uses it.

## Shape

```yaml
spec:
  aggregationRule:
    roleSelectors:              # label selectors, matched against Roles in the same namespace
      - matchLabels:
          identity.unikorn-cloud.org/aggregate-to-administrator: "true"
    roleRefs:                   # role IDs, always included
      - <administrator-base role ID>
    flattenToOrganization: true # copy source project scopes into organization
status:
  effectiveScopes: {...}        # written by this controller only
  aggregatedFrom:
    - id: <role ID>
      name: fleet-operator
      description: ...
      scopesHash: sha256:...
      scopes: {...}             # what this source contributed, no global
  conditions:
    - type: Available           # Aggregated | MissingRoleRef | Cycle | InvalidSelector
    - type: Grantable           # Grantable | NotGrantable
```

An aggregating role has no `spec.scopes`. If it has some, they are ignored and
logged, except while the role is stuck (see below), so converting a role
never empties it. The admission policy refuses `spec.scopes` on aggregating
roles. Its own hand-written scopes live in a protected base role that it
`roleRefs`.

## Scope rules

| Source scope | Into a role with `flattenToOrganization: true` | Into a role without it |
| --- | --- | --- |
| global | dropped | dropped |
| organization | organization | organization |
| project | organization | project |

- Operations on the same scope name are merged (union), and the result is
  sorted, so the same sources always give the same status.
- `flattenToOrganization` exists because a project scope on `administrator`
  only applies in projects linked to the admin's group. That is not enough to
  grant a project role across the organization.

## Which sources are used

- **Selector matches:** protected roles and roles with global scopes are
  skipped. Each skip is logged and named in the `Available` message. Global
  scopes in an organization role would hand out cross-organization authority.
- **`roleRefs`:** always used, and may name protected roles (the base roles).
  Global scopes are still dropped.
- **A role never selects itself.**
- **Selectors may only use `aggregate-to-*` match labels set to `"true"`.** An
  empty selector, a `matchExpressions` entry (such as `DoesNotExist`) or any
  other label is refused, because it could select every role.
- **A role being deleted** (deletion timestamp set) no longer counts as a
  source.
- **Protected scopes can still arrive in one hop:** a labelled aggregating
  role that `roleRefs` a protected role passes the protected role's scopes
  on. The chain (`reader`, `user`, `auditor` → their `*-base` roles) is
  exactly this shape. The admission policy (ID-555) is what stops anyone
  else doing it: it refuses a role that is both labelled and aggregating,
  except the chain role IDs.
- A source can itself be an aggregating role. Its effective scopes are used,
  which is how the chain works: `reader` → `auditor` and `user`; `auditor` and
  `user` → `administrator`.

## Failure behaviour

A bad aggregation must never empty an org's admin ACL, and must never keep a
scope from a source that is gone.

| Problem | Effective scopes | `Available` |
| --- | --- | --- |
| A `roleRef` names a missing role | that ref gives its last recorded scopes | `False`, `MissingRoleRef` |
| The role is in a cycle | each source in the cycle gives its last effective scopes | `False`, `Cycle` |
| A selector is not allowed | the roles it last selected that still exist | `False`, `InvalidSelector` |

- **A stuck role is computed from what is known.** Every live source (ref or
  selector match) gives its current scopes. Only the broken part falls back
  to a last value. `aggregatedFrom` lists exactly the sources used.
- **"Last recorded scopes"** are the `scopes` stored for that source in
  `status.aggregatedFrom`. A missing ref with none recorded gives nothing.
- **"Last effective scopes"** are the last status, without global scopes.
  Before the controller has ever written status, they are the role's own
  `spec.scopes` plus what its non-aggregating `roleRefs` hold.
- **While stuck the role's own `spec.scopes` are kept too**, so adding an
  `aggregationRule` never takes anything away, even with a bad ref. Once the
  role is `Available` they are dropped.
- **Cycles** are found with Tarjan's strongly connected components, so every
  role in a cycle is flagged, however it is reached.
- **A role above a broken one** is not itself broken: it takes the broken
  role's effective scopes, or a cycle member's last ones.
- **Turning False is loud:** a Warning Event and a log line, once per change of
  reason or message. The Event note is cut to 1000 bytes.

## Before the first reconcile

Two rules cover the time between a role becoming aggregating and the
controller writing its status:

- **Holders keep working.** The ACL build (`unikornv1.BootstrapRoles`, called
  from `pkg/rbac`) gives the role its own `spec.scopes` plus what its
  `roleRefs` hold. For a converted built-in role that is its base role, which
  holds exactly its old hand-written scopes. Without this, every org admin
  would hold nothing until the reconcile, and the one-minute ACL cache would
  keep that.
- **Nobody can grant it.** `rbac.AllowRole` refuses an aggregating role until
  `Role.AggregationReady()`: status written for the current generation
  (`Available` carries `observedGeneration`). Otherwise a caller holding
  nothing could grant a role that is about to hold far more. This window is
  the time to the first reconcile, normally seconds, and fails closed.
- **A stuck role can be granted against its kept scopes**, which are exactly
  what its holders hold, as long as they are not empty. So adding members to
  an admin group keeps working while it is stuck. A stuck role with no kept
  scopes cannot be granted.

Global scopes are never read from status, whoever wrote it.

## Grantable condition

`Grantable` runs the real grant check (`rbac.AllowRole`) from a holder of the
aggregating role's effective scopes against every non-protected role its
selectors match. It is `False`, naming each role it can't grant, if any fails.

A matched role that is used is held, so it passes, unless it is in a cycle
and gave its last scopes. The useful failure is a labelled role with global
scopes, which is skipped and which no org admin can ever grant.

The holder ACL puts project scopes in one linked project. A holder of a role
without `flattenToOrganization` whose group has no linked project can grant
less than the condition says.

The grant-tree unit test only sees the uni-identity chart. Roles also come
from k8s-deploy-unikorn and per-environment config, so this condition is the
check that runs against the real roles in each environment (NCP-0010 §5.5).

## Change record

When effective scopes change, the controller emits a Kubernetes Event
(`EffectiveScopesChanged`) and a log line. Each names the source that was
added, removed or changed, with its old and new scopes hash, plus the old and
new hash of the effective scopes. This is not an NCP audit record (it has no
grantor); see ID-641.

## Runtime

- **Watches:** every `Role` in the controller's own namespace (`POD_NAMESPACE`,
  set by the chart), so a second identity release in one cluster never touches
  this release's roles. A create or delete, or an update that changes the
  generation, labels or annotations, enqueues every aggregating role in the
  namespace. Labels are watched as well as generation because a label is how
  a role opts in, and labels do not bump the generation. Status changes are
  watched too: a stuck role reads its own and its cycle sources' last status,
  and a status someone else wrote must be put right. The controller's own
  writes wake it once and then compute to no change.
- **Each reconcile** lists every role, computes the whole graph, and writes
  only the reconciled role's status, through the status subresource. Helm and
  Argo never own `status`, so nothing fights the controller.
- **No write** when the computed status equals the current one.
- **No finalizer and no provisioning lifecycle.** The controller owns no
  backing state, so there is nothing to clean up when a role is deleted. That
  is why it does not use the shared provisioner reconciler. Errors (list
  failures, status write conflicts) retry at the fixed
  `DefaultYieldTimeout`.
- **A role that stops aggregating** has its status cleared, so nothing reads
  stale scopes from it.
- **Readers see changes within one ACL cache TTL**, not at once.

## Caveats

- **Removing a selector source shrinks admin at once.** For example, turning
  off a chart that ships labelled roles removes their scopes from every org
  admin at the next reconcile. Kubernetes behaves the same. A removed or
  deleted `roleRef` does not: it keeps its last recorded scopes
  (`MissingRoleRef`) until the ref is fixed.
- **A source that widens is not seen until the next reconcile.** Until then
  `AggregationReady` still passes on the old, smaller status, so a caller
  holding only the old set can grant the role. The window is the reconcile
  latency, or as long as the controller is down. Same class as the unpinned
  widening below.
- **A scope change on a labelled role widens every org admin** at the next
  reconcile, with no approval step. The admission allow-list (chart) and the
  change record keep this visible. It closes when grants pin bundle versions
  (NCP-0002 §15.15).
- **The project → organization fold gives admins organization-wide use**, not
  only grant. Accepted in ID-368. Look again if a labelled service gives its
  resources project scope.
