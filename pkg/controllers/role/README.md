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
      scopes: {...}             # what this source contributed, no global; a record only, never read back
  conditions:
    - type: Available           # Aggregated | MissingRoleRef | InvalidRoleRef | Cycle | InvalidSelector
    - type: Grantable           # Grantable | NotGrantable
```

An aggregating role has no `spec.scopes`. If it has some, the controller
ignores them and logs it. The only reader is the ACL build before the first
reconcile (see below). The admission policy refuses `spec.scopes` on
aggregating roles. Its own hand-written scopes live in a protected base role
that it `roleRefs`.

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
- **`roleRefs`:** always used. The only protected role a ref may name is the
  role's own base role: display name `<own display name>-base`, for example
  `administrator` → `administrator-base`, and the ID the chart gives that
  name (`ChartRoleID`, the same SHA-256 scheme as the chart's `resource.id`
  helper). Any other protected ref gives nothing (`InvalidRoleRef`), so
  copying the base role's name label onto another protected role does not
  work. Global scopes are still dropped.
- **Renaming an aggregating role locks it out of its base role**: the base
  role's ID comes from the old name. Rename the base role and its ID too.
- **The admission policy in the identity chart is the main guard** on
  protected refs. The base-role check here is defence in depth only.
- **A role used through `roleRefs`** is not also named as skipped when a
  selector matches it.
- **A role never selects itself.**
- **Selectors may only use `aggregate-to-*` match labels set to `"true"`.** An
  empty selector, a `matchExpressions` entry (such as `DoesNotExist`) or any
  other label is refused, because it could select every role. A key that is
  not a valid label key (such as a space, or a name part over 63 bytes) is
  refused the same way.
- **A role being deleted** (deletion timestamp set) no longer counts as a
  source.
- **Protected scopes can still arrive in one hop:** a labelled aggregating
  role that `roleRefs` a protected role passes the protected role's scopes
  on. The chain (`reader`, `user`, `auditor` → their `*-base` roles) is
  exactly this shape. The admission policy (ID-555) is what stops anyone
  else doing it: it refuses a role that is both labelled and aggregating,
  except the chain role IDs. The base-role rule above (name and ID) is a
  second guard: a role can only pass on its own base role.
- A source can itself be an aggregating role. Its effective scopes are used,
  which is how the chain works: `reader` → `auditor` and `user`; `auditor` and
  `user` → `administrator`.

## Failure behaviour

A broken part of an aggregation fails closed, like a role binding that names
a missing role. The computation never reads an aggregating role's status, so
a status someone else wrote is put right at the next reconcile, and a source
that goes away stops giving at once.

Holders get what `status.effectiveScopes` says, so write access to
`roles/status` sets what they hold until that reconcile. Only the role
controller's service account has it, through a namespaced `Role` in the
identity chart. Nothing else may be given `roles/status` write.

| Problem | Effective scopes | `Available` |
| --- | --- | --- |
| A `roleRef` names a missing or deleting role | that ref gives nothing | `False`, `MissingRoleRef` |
| A `roleRef` names a protected role that is not `<name>-base` with the chart's ID | that ref gives nothing | `False`, `InvalidRoleRef` |
| A selector is not allowed | the selectors give nothing, only `roleRefs` are used | `False`, `InvalidSelector` |
| The role is in a cycle | every role in the cycle holds what the sources outside the cycle give | `False`, `Cycle` |

- **A stuck role is computed from its working sources.** Every live,
  allowed source gives its current scopes. `aggregatedFrom` lists exactly the
  sources used.
- **Admins of a stuck role can lose scopes at once.** A typo in a base ref
  empties that part of every holder's ACL until it is fixed. The chart render
  guard catches typos in chart refs. The Warning Event and the condition say
  which ref is wrong.
- **The role's own `spec.scopes` are never used by the controller**, stuck
  or not.
- **Cycles** are found with Tarjan's strongly connected components, so every
  role in a cycle is flagged, however it is reached. Each role in the cycle
  holds the union of the current scopes of every source outside the cycle
  that any role in it uses, merged with its own `flattenToOrganization`. No
  role's status is read, so a scope dropped outside the cycle is gone from
  every role in it at once.
- **A cycle can hold less than the same roles without the cycle.** Each role
  in it gets only the outside sources, merged with its own
  `flattenToOrganization`. A role that would have taken a flattened source
  through another role in the cycle now gets that source's project scopes at
  project scope. This fails closed: fix the cycle.
- **A role in a cycle still names its other problems.** The `Cycle` message
  also lists missing and refused `roleRefs` and a bad selector, sorted.
- **A role above a broken one** is not itself broken: it takes the broken
  role's computed scopes.
- **`InvalidSelector` names every bad label**, sorted, so the message, and so
  the status, is the same on every reconcile.
- **Turning False is loud:** a Warning Event and a log line, once per change of
  reason or message. The Event note is cut to 1000 bytes.

## Before the first reconcile

Two rules cover the time between a role becoming aggregating and the
controller writing its status:

- **Holders keep working.** The ACL build (`unikornv1.BootstrapRoles`, called
  from `pkg/rbac`) gives the role its own `spec.scopes` plus what its
  non-aggregating `roleRefs` hold (`BootstrapScopes`, same protected-ref
  rule as above). For a converted built-in role that is its base role, which
  holds exactly its old hand-written scopes. Without this, every org admin
  would hold nothing until the reconcile, and the one-minute ACL cache would
  keep that.
- **Nobody can grant it.** `rbac.AllowRole` refuses an aggregating role until
  `Role.AggregationReady()`: status written for the current generation
  (`Available` carries `observedGeneration`). Otherwise a caller holding
  nothing could grant a role that is about to hold far more. This window is
  the time to the first reconcile, normally seconds, and fails closed.
- **A stuck role can be granted against its computed scopes**, which are
  exactly what its holders hold, as long as they are not empty. So adding
  members to an admin group keeps working while it is stuck. A stuck role
  with no scopes cannot be granted.

Global scopes are never read from status, whoever wrote it.

## Grantable condition

`Grantable` runs the real grant check (`rbac.AllowRole`) from a holder of the
aggregating role's effective scopes against every non-protected role its
selectors match. It is `False`, naming each role it can't grant, if any fails.

A matched role that is used is held, so it passes, unless it is in a cycle,
where it holds only what the cycle's outside sources give. The useful failure is a labelled role with global
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
  watched too: the computation never reads status, but a status someone else
  wrote must be put right. The controller's own
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

- **Removing a source shrinks admin at once.** For example, turning off a
  chart that ships labelled roles removes their scopes from every org admin
  at the next reconcile. Kubernetes behaves the same. A deleted `roleRef`
  does too (`MissingRoleRef`).
- **Status goes stale while the controller is down, with no bound.** Readers
  use `status.effectiveScopes` as written. A source that widens or narrows is
  not seen until the next reconcile, and `AggregationReady` checks only the
  role's own generation, so it still passes on the old status. A caller
  holding only the old set can grant the role, and holders keep scopes a
  source has dropped. The window is the reconcile latency while the
  controller runs, and unbounded while it is down. **The controller must be
  alerted on** (not running, or reconcile errors) before rollout. Same class
  as the unpinned widening below.
- **A scope change on a labelled role widens every org admin** at the next
  reconcile, with no approval step. The admission allow-list (chart) and the
  change record keep this visible. It closes when grants pin bundle versions
  (NCP-0002 §15.15).
- **The project → organization fold gives admins organization-wide use**, not
  only grant. Accepted in ID-368. Look again if a labelled service gives its
  resources project scope.

## Rollout

- **Alert on the controller before turning aggregation on.** While it is
  down, status is not updated and the stale window above has no bound. Alert
  when it is not running or its reconciles keep failing.
- **Check every aggregating role is `Available=True` after the apply.** A
  wrong `roleRef` fails closed: its holders lose that ref's scopes until it is
  fixed.
