# Role Aggregation Design

Linear: [ID-368](https://linear.app/nscale-workspace/issue/ID-368/clarify-permission-management-for-group-membership)
(root cause and acceptance criteria live on the ticket; overlaps
[ID-367](https://linear.app/nscale-workspace/issue/ID-367/nvidia-bug-revoke-elevated-access-after-role-downgrade)
for enforcement alignment)

## Problem

Org admins cannot manage groups containing third-party roles (e.g. radar). The grant rule
(`rbac.AllowRole`) requires the caller to hold every permission in a role before granting it,
and the built-in `administrator` role is a fixed endpoint list that knows nothing about roles
installed by third-party charts. Group edits re-validate the whole role list, so even
members-only changes fail. The API also hides ungrantable roles, so clients cannot explain the
failure and can silently revoke roles they cannot see.

## Solution overview

Mirror Kubernetes aggregated ClusterRoles: third-party roles opt in with a label, and a
controller folds their permissions into aggregating roles' **status**. Admins then genuinely
hold the permissions, so the grant rule and the platform's escalation invariant ("a caller may
only assign roles that contain permissions the caller already holds") are untouched.

Alongside the mechanism, this change fixes the read-side and enforcement gaps: ungrantable
roles become visible with a `grantable` flag, silent role revocation is closed, grant refusals
name the offending role, and enforcement is made consistent across the groups, users, and
service-account paths.

**Delivery is phased, per maintainer review (2026-07-28):**

- **Phase A — no CRD change, ships first:** delta-based grant validation on group updates
  (only roles being *added* are checked, so members-only edits on groups holding ungrantable
  roles succeed — the reported symptom), plus the `grantable` flag, silent-revocation guard,
  named errors, enforcement parity, and guard-test coverage of `additionalRoles`. None of this
  waits on upstream CRD agreement.
- **Phase B — aggregation:** the CRD, controller, and chart work, with four maintainer
  sign-off conditions folded in: aggregation across the whole grant lattice (not just
  `administrator`), the aggregate must expose what it holds (scopes + composed description),
  explicit `roleRefs` alongside selectors, and the project→org fold exercised with a mutating
  permission in the integration tests.

Delta validation and aggregation are complementary: delta fixes "can't manage members";
aggregation fixes "can't grant the third-party role at all".

## Design

### CRD changes (`pkg/apis/unikorn/v1alpha1`)

```yaml
apiVersion: identity.unikorn-cloud.org/v1alpha1
kind: Role
metadata:
  name: administrator
spec:
  aggregationRule:                 # NEW, optional; helm-owned
    roleRefs: []                   # pinned sources by name; optional
    roleSelectors:                 # label-matched sources; optional
    - matchLabels:
        rbac.unikorn-cloud.org/aggregate-to-administrator: "true"
  scopes:                          # unchanged, helm-owned
    organization: [...]
status:
  aggregatedScopes:                # NEW; controller-owned
    organization:
    - name: radar:things
      operations: [create, read, update, delete]
  aggregatedDescriptions:          # NEW; controller-owned
  - "Radar fleet management"
  missingRoleRefs: []              # NEW; controller-owned — roleRefs naming
                                   # no existing role (configuration error)
```

- `spec.aggregationRule` carries `roleRefs` ([]string, pinned sources) and `roleSelectors`
  ([]metav1.LabelSelector, opt-in sources); either or both; the source set is the union,
  deduplicated by name (maintainer condition 3: selectors for the extensible edges, pinning
  where determinism matters — Kubernetes got away with selector-only because it owns every
  source ClusterRole; we won't). A `roleRef` naming a missing role is a configuration error
  surfaced on the role's status; a vanished selector match just drops out on reconcile.
- `status.aggregatedScopes` reuses the existing `RoleScopes` shape. Only its `organization`
  block is ever populated (see fold rules).
- `status.aggregatedDescriptions` is the sorted, deduplicated list of the source roles'
  descriptions (from the `unikorn-cloud.org/description` annotation), written in the same
  reconcile pass as the scopes — the aggregate's documentation is a view over the aggregation,
  not a stale string beside it (maintainer condition 2).
- `Role` gains the `+kubebuilder:subresource:status` marker (it has none today; `RoleStatus`
  is currently empty, so this is additive).
- A role's **effective scopes** are `spec.scopes` unioned with `status.aggregatedScopes`,
  exposed as a helper on the Role type (e.g. `EffectiveScopes()`), used by every consumer of
  role permissions (see Consumers).

### Label convention — the whole lattice, not just administrator

`rbac.unikorn-cloud.org/aggregate-to-<role-name>: "true"`, mirroring Kubernetes'
`rbac.authorization.k8s.io/aggregate-to-admin` and the repo's `<subsystem>.unikorn-cloud.org/`
label style (cf. `resource.unikorn-cloud.org/kind`). The selectors are free-form; this is the
documented convention, not a hard-coded key.

Maintainer condition 1 (pushed hardest): a source role must opt into **every grant-lattice
position that should be able to grant it**, or the new mechanism reproduces the `application:*`
failure (`pkg/rbac/README.md:228-232`) on day one. The lattice is
`administrator ⊇ {auditor, user, reader}` and `auditor ⊇ {auditor, reader}`
(`grant_guard_test.go:176-177`). Concretely: a third party shipping `radar-reader` alongside
`radar` labels `radar` with `aggregate-to-administrator`, and `radar-reader` with **both**
`aggregate-to-auditor` and `aggregate-to-administrator` — otherwise `auditor` cannot grant
`radar-reader`, or worse, `auditor` can and `administrator` cannot. Both `administrator` and
`auditor` therefore carry aggregation rules in the chart, and the guard test asserts lattice
consistency **over aggregated roles**, not only chart roles: any source targeting a role must
also be grantable by every role above it in the lattice.

Trust note: nothing mechanically stops a write-capable role being labelled
`aggregate-to-auditor`; label discipline sits with the source owner, the same trust boundary
as admin aggregation. A per-rule operations filter would tighten this — explicitly future
work.

### Fold rules

For each source role in the union of `roleRefs` and `roleSelectors` matches:

1. The source's **organization** and **project** scope blocks are folded into the aggregate's
   **organization** block. Project scopes are deliberately promoted: org-scope authority
   satisfies project-scope grant checks (`allowGrantProjectScope`), and the aggregate target is
   an "anything within the organization" role. Like-for-like folding was rejected because
   admin's grant ability would then depend on the admin group being linked to a project.
2. The source's **global** block is never folded. Folding global permissions into an
   org-grantable role would hand out cross-organization authority.
3. `protected` source roles are never folded, even if labelled (defence in depth; the platform
   and service roles are all global-scoped anyway, so rule 2 already excludes most of them).
4. Sources contribute their **spec** scopes only — never their own `status.aggregatedScopes`.
   No transitive aggregation, so no cycles: labelling one aggregating role into another folds
   only the hand-written scopes.

The fold result is the deduplicated union (same merge semantics as the ACL builder's
`addScopesToEndpointList`), written to `status.aggregatedScopes` — together with
`status.aggregatedDescriptions` — only when it differs from the current value.

The project→org promotion grants org-wide **use**, not just grantability: an admin holds a
mutating project-scoped source permission (e.g. a radar create) in every project of the org,
including projects they are not attached to. Accepted for admin's "anything within the
organization" semantics, but per maintainer condition 4 the integration tests must exercise a
**mutating** project-scoped source permission so the consequence is observed rather than
assumed, and the outcome recorded here.

### Controller

A new controller following the existing layout: `cmd/unikorn-role-controller` binary,
`pkg/controllers/role` manager, deployed by the identity chart alongside the
organization/project/oauth2client controllers.

- Watches `Role` CRs in the identity namespace. Any role event enqueues every role that has an
  `aggregationRule` (fan-in mapping, like `handler.EnqueueRequestsFromMapFunc`).
- Reconcile: list roles, select sources by the aggregating role's selector, apply the fold
  rules, patch status if changed.
- The reconcile shape is fan-in (one output derived from many inputs), which does not fit the
  `coremanager` provisioner abstraction (per-object Provision/Deprovision); the reconciler is
  custom, but the binary/manager scaffolding matches the existing controllers.
- Controller RBAC: get/list/watch on roles, update/patch on `roles/status`. Nothing else.
- Removal is symmetric: deleting or unlabelling a source role removes its permissions from the
  aggregate on the next reconcile.

Ownership is clean by construction: helm owns `spec` (selector included), the controller owns
`status`. Helm upgrades never touch status; the controller never touches spec.

### Consumers of effective scopes

Every consumer of role permissions moves from `Spec.Scopes` to effective scopes:

- **ACL builder** (`pkg/rbac/rbac.go`: `accumulateGlobalPermissions`,
  `accumulateOrganizationPermissions`, `accumulateProjectPermissions`): members of a group
  holding `administrator` receive the aggregated permissions. Global stays spec-only in
  practice because `status.aggregatedScopes.global` is never populated.
- **Grant check** (`rbac.AllowRole`, `pkg/rbac/handler.go`): the target role's effective scopes
  are what the caller must hold. Granting `administrator` therefore requires holding the
  aggregated permissions too — which every admin does, keeping the grant lattice consistent.
- **Guard test** (`pkg/rbac/grant_guard_test.go`): extended to compute effective scopes and to
  cover aggregation (a labelled fixture role must become admin-grantable).

### Handler and API changes

0. **Delta-based grant validation** (Phase A, first): group **create** validates every role in
   the request via `AllowRole` (all are additions); group **update** validates only
   `added = requested − current`. Members-only edits and edits to groups carrying ungrantable
   roles no longer fail on roles that were already there — the reported symptom
   ("cannot add or remove radar members") is closed without any CRD change. Existence and
   `protected` checks still run over the full requested list. Accepted consequence, to be
   documented: a caller with `identity:groups` update may join (or add others to) an
   *existing* group whose roles they could not grant — organization-internal, admin-only
   today, and moot for aggregated roles once Phase B lands, since admins then hold those
   permissions outright.
1. **Roles list** (`pkg/handler/roles/client.go`): stop deleting ungrantable roles from the
   response; keep deleting `protected` ones — these are two different reasons for absence
   currently sharing one `DeleteFunc` (`roles/client.go:75-77`) and they must be split.
   `roleRead` gains a required `grantable: bool` (computed per caller via `AllowRole`).
   Clients can now resolve and display every role a group references.
1a. **Roles say what they hold** (Phase B, maintainer condition 2): `roleRead` gains `scopes`,
   reflecting the role's **effective** scopes — the data is already on the CR and simply
   dropped by `convert()` today. Without this, aggregation would be the first mechanism that
   changes what a role holds without changing anything a product user can see: the API's
   complete answer about `administrator` is currently the string "Organization administrator".
   The composed description (`status.aggregatedDescriptions`) is exposed alongside it.
2. **No silent revocation** (`pkg/handler/groups/client.go`): group update computes
   `removed = current roles − requested roles`; any removed role the caller cannot grant is
   rejected with a 403 naming the role. Today such a removal passes silently (only the
   requested list is validated) — that is the silent-revocation hole. Explicitly retaining was
   rejected: mutating the caller's requested spec is surprising; a named error is honest.
3. **Named errors**: `validateRoleIDs` includes the role name and ID in every grant-refusal
   error so the console can say which role is the blocker.
4. **Enforcement alignment** (ID-367 overlap) — **OPEN QUESTION, needs a maintainer ruling
   before this item is implemented.** The original design gated *any* membership change on
   grantability of all the group's roles ("changing membership grants the group's roles").
   Delta validation (item 0) takes the opposite position for the groups API: membership
   changes are administration, only role-*list* changes are grants. The two rules cannot both
   be "the same rule across all paths":
   - **Option 1 — membership ungated everywhere (consistent with delta):** users/service-account
     paths get no per-group grant check; parity holds because no path gates membership. The
     self-elevation window in item 0 exists on every path, documented and accepted until
     Phase B legitimises it for aggregated roles.
   - **Option 2 — membership gated everywhere by the group's roles:** closes the window, but
     re-blocks the reported symptom (admins cannot manage radar-group members until Phase B),
     contradicting the "do delta first" direction.
   Whichever wins, the mechanism is a shared helper both handlers call so the paths cannot
   drift again, and **principal deletion is exempt**: user/service-account delete strips group
   memberships as cleanup (`updateGroups` with an empty set); that is de-provisioning of a
   principal that ceases to exist, not a privilege change, and gating it would block admins
   from deleting principals that sit in groups with ungrantable roles — a new lockout of the
   same shape this design removes.

Behaviour intentionally kept: a group containing a role that is neither aggregated nor
otherwise grantable remains unmanageable by admins — but the failure is now visible (grantable
flag) and explained (named error). Delta-based member validation was considered and not chosen
(ticket, "Alternatives considered").

### Chart changes (`charts/identity`)

- `administrator` and `auditor` role templates gain `aggregationRule` entries
  (`aggregate-to-administrator` / `aggregate-to-auditor` selectors respectively) — both
  lattice positions aggregate, per maintainer condition 1. Hand-written scopes are unchanged.
- New deployment/RBAC for `unikorn-role-controller`, following the existing controller
  templates.
- Auditor read-only safety is label discipline on the source owner (ship a read-only role and
  label that one), not mechanism — see the trust note under the label convention.

### Third-party usage

A third-party chart makes its roles admin-manageable by adding one label:

```yaml
kind: Role
metadata:
  name: radar-operator
  labels:
    rbac.unikorn-cloud.org/aggregate-to-administrator: "true"
```

Documented in the top-level README ("3rd Party User RBAC") and `pkg/rbac/README.md`.

## Security considerations

- The escalation invariant is preserved: admins hold what they grant. No grant/hold split.
- No new trust boundary: installing a Role CR in the identity namespace is already
  root-equivalent (such an actor could create a role and group directly). The label only
  changes *which built-in role* picks the permissions up.
- Admins gain org-wide **use** of aggregated endpoints, not just grant rights. This is the
  intent ("an administrator can do anything within an organization") and matches the field
  expectation, but it is a real widening: a labelled role silently grows every org admin's
  authority. Operators control this by what they install; the docs must say so plainly.
- Global scopes never aggregate; protected roles never aggregate; no transitive aggregation.
- The membership rule closes the ID-367 gap where `PUT /users/{id}` changed group membership
  with no grant check at all.

## Compatibility and migration

- CRD changes are additive (optional spec field, new status field, status subresource). No
  migration for existing Role CRs; `make generate` regenerates CRDs and deepcopy.
- Deployments change behaviour only when roles carry the label. Radar (and friends) need a
  chart release adding the label — coordinate with those teams.
- `grantable` on `roleRead` is additive but the list now returns roles it previously hid —
  console must key "can I grant this" off the flag, not off presence. Needs a console heads-up.
- Group updates that previously silently dropped unseen roles now 403. Release-note this.

## Testing

Per the kind-integration-testing strategy (real HTTP, mTLS/system-account fixtures, BDD
structure in `test/api/`, `//go:build integration`):

- **Unit**: delta validation (create = all added; update = added only; members-only edit needs
  nothing); fold rules (promotion, global exclusion, protected exclusion, no transitivity,
  dedup, refs ∪ selectors, dangling-ref error); effective-scopes helper; description union;
  guard test extended over effective scopes, the chart's `additionalRoles` map (invisible to
  it today), and **lattice consistency over aggregated roles** — a source targeting `auditor`
  must also be grantable by `administrator`.
- **Integration, Phase A**: an org admin can add and remove members of a group carrying a role
  they cannot grant (unlabelled fixture role installed via the k8s client); dropping that role
  from the group is refused with the role named; the roles list shows it `grantable: false`.
- **Integration, Phase B**: install a labelled radar-shaped Role CR → controller folds it
  (status scopes + descriptions visible) → `ci-admin-sa` can grant it to a group and sees
  `grantable: true` and the role's scopes in the roles list; unlabel → permissions withdrawn,
  grants refused with the role named. **Mutating project-scoped source permission** case
  (maintainer condition 4): fold a create-verb project-scoped endpoint and observe/record the
  org-wide authority it confers. Auditor lattice case: a read-only source labelled for both
  auditor and administrator is grantable by both.
- Fixtures follow `hack/ci/fixtures` + `test/api` patterns (`CreateGroupWithCleanup` style,
  `DeferCleanup`, endpoints via `test/api.Endpoints`).

## Documentation updates

`pkg/rbac/README.md` (grant lattice caveat gains the aggregation story),
`pkg/handler/roles/README.md`, `pkg/handler/groups/README.md`, `pkg/controllers/README.md`,
`pkg/apis/unikorn/v1alpha1/README.md`, top-level `README.md` ("3rd Party User RBAC").

## Out of scope

- A per-rule operations filter (mechanically constraining e.g. auditor aggregation to reads).
- Default groups per enterprise org at onboarding (separate ticket).
- The nscale-side sync controller is **struck as a fallback** per maintainer review — if the
  upstream conversation gets sticky, escalate to the maintainer rather than building it.
