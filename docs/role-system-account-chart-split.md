# Role and System Account Chart Split

## Context

The Identity chart currently owns three different concerns:

- the Identity server, controllers, CRDs, and runtime configuration
- the platform role catalogue rendered as `Role` CRs
- deployment-time bindings from system account certificate CNs to role IDs

Those concerns need different ownership. The server chart should
deploy the Identity service. Role and system account definitions
should be installable and versionable as platform bootstrap data,
without requiring every service-specific permission change to modify
the Identity runtime chart. Likewise, charts for other services should
not include Identity-specific objects, but should rely on a
deploy-time API to instruct identity to create roles.

The platform architecture still applies:

- Identity owns `Role` and organization-bound `ServiceAccount` resources.
- System accounts are platform services authenticated by mTLS certificate CN.
- System account authority comes from a CN-to-role mapping configured at
  deployment time.
- Protected roles remain internal and must not be exposed through the public
  role list or group assignment path.

This is not a change to the actor model. It is a chart ownership and migration
change.

## Current State

The current chart layout is:

- `charts/identity/values.yaml`
  - `roles`: builtin role definitions
  - `additionalRoles`: optional extra role definitions
  - `systemAccounts`: CN to role-name mappings
  - `platformAdministrators.roles`: protected role names used for superuser ACLs
  - `platformAdministrators.subjects`: deployment-specific user subjects
- `charts/identity/templates/roles.yaml`
  - renders `Role` CRs from `.Values.roles` plus `.Values.additionalRoles`
- `charts/identity/templates/identity/deployment.yaml`
  - turns `platformAdministrators.roles` into
    `--platform-administrator-role-ids`
  - turns `systemAccounts` into `--system-account-roles-ids`

At runtime, `pkg/rbac` reads stored `Role` resources for permissions, but
system-account and platform-administrator role selection still comes from server
startup flags.

That startup-flag dependency is the main obstacle to a clean split. A separate
chart can create `Role` objects, but it cannot cleanly mutate the Identity
server arguments or trigger a restart without coupling itself back to the
runtime chart.

## Observed Deployment Use Cases

The live deployment shape spans this repository, `k8s-deploy-unikorn`, and
`k8s-cluster-nks`.

### Identity Chart

`charts/identity` currently provides the baseline role catalogue and runtime
flag surface:

- fixed platform roles: `platform-administrator`, `region-service`,
  `kubernetes-service`, `compute-service`, and `storage-service`
- fixed user-facing roles: `administrator`, `auditor`, `user`, and `reader`
- optional `additionalRoles`, rendered beside the builtin roles
- default system-account mappings for `unikorn-region`, `unikorn-kubernetes`,
  `unikorn-compute`, and `uni-storage`
- platform administrator subjects and role IDs as runtime server flags

This is the source of the current coupling: role definitions, role extension,
system-account bindings, and environment-specific administrator subjects all
enter through the same chart values.

### `k8s-deploy-unikorn`

`k8s-deploy-unikorn/charts/unikorn/templates/uni/identity.yaml` is the current
integration layer for NKS. It renders an Argo CD `Application` for the Identity
chart and writes inline Helm values into that child application.

Observed use cases:

- Pass global deployment settings through to Identity: hosts, image override,
  ingress, Auth0 token exchange, server resources, and server flags.
- Keep platform administrator subjects cluster-owned while forcing the role set
  to include `platform-administrator` and, when Reservation is enabled,
  `reservation-platform-administrator`.
- Map core system account CNs to roles:
  - `unikorn-kubernetes` -> `kubernetes-service`
  - `unikorn-compute` -> `compute-service`
  - `uni-storage-services` -> `storage-services`
- Map product and operations system account CNs to same-named roles:
  - `create-account-service`
  - `observability-metadata-resolver`
  - `fleet-operations-radar-ingestion-service`
  - `fleet-operations-compute-resolver`
- Conditionally map feature-specific system accounts:
  - `unikorn-reservation` -> `reservation-service` when
    `reservation.enabled=true`
  - `envir-resource-manager` -> `envir-resource-manager` when the AI Services
    Resource Manager UNI client is enabled
- Provide parent-chart default roles through `identity.additionalRoles`:
  - `fleet-operator`, an organization-scoped user-facing Radar role
  - `storage-services`, a protected global role used by the storage service CN
- Inject the Reservation role bundle when `reservation.enabled=true`:
  - `reservation-platform-administrator`, a protected global role included in
    the platform administrator role list
  - `reservation-service`, a protected global system-account role
  - user-facing Reservation roles for capacity, placement, and placement-server
    workflows
- Create at least one role directly outside the Identity child chart:
  `templates/uni/ai-services-resource-manager-uni-client.yaml` emits a
  protected `Role` plus the client certificate for `envir-resource-manager`.

The parent chart also omits `platformAdministrators` and `additionalRoles` from
the free-form Identity value pass-through before writing those sections itself.
That makes the parent chart the current owner of cross-service Identity policy,
even though the Identity chart renders the final `Role` objects.

### `k8s-cluster-nks`

The cluster repo owns environment facts and enables feature bundles; it does not
currently define arbitrary role specs or system-account maps for Identity.

Observed use cases:

- Select the `k8s-deploy-unikorn` revision and component versions per
  environment.
- Provide cluster identity data: cluster name, region, root FQDN, ingress,
  secret prefix, storage class, OTLP endpoint, and trace sampling.
- Configure Identity runtime values such as Auth0 token exchange, server
  resources, controller resources, and extra server flags.
- Provide the platform administrator subject list per environment.
- Enable Reservation in development, staging, and production, which causes the
  parent chart to inject Reservation roles and system-account bindings.
- Enable the AI Services Resource Manager UNI client in development, which
  causes the parent chart to create the Resource Manager role, certificate, and
  system-account binding.
- Carry product/Auth0 sync configuration that references role UUIDs directly;
  those references depend on stable rendered role IDs but are not themselves
  Identity chart role definitions.

### Design Implications

The split chart must support more than "move the builtin roles". The important
target is that every service owns its own role release:

- Identity instantiates `identity-roles` for Identity-owned API roles, including
  the platform administrator role marker.
- Region instantiates `identity-roles` for Region user-facing permissions and
  the `unikorn-region` system account binding.
- Kubernetes, Compute, Storage, Reservation, AI Services, and other services do
  the same for their own user-facing roles, protected service roles, and system
  account CNs.
- Environment-owned administrator subjects stay outside the role catalogue.
- Role names and rendered resource IDs must remain stable, because downstream
  configuration may refer to role UUIDs directly.

For NKS, the clean target is that `k8s-deploy-unikorn` renders one
`identity-roles` Argo CD `Application` per service or feature bundle, while
`charts/identity` receives only runtime values and administrator subjects.
`k8s-cluster-nks` should continue to select versions, enable service bundles,
and provide subject lists rather than carrying role specs or CN maps.

This also means there is no single global role catalogue owner after migration.
Any role object may be rendered by exactly one service-owned release. If the
current aggregate roles such as `administrator`, `auditor`, `user`, and
`reader` are kept for compatibility, one release must own each of those objects;
other services cannot safely patch scopes into the same `Role` object from
separate Helm releases. The migration therefore needs either service-specific
role names, or a short-lived compatibility owner for the aggregate roles.

## Proposed Target

Use the Identity runtime chart plus a reusable role chart:

- `charts/identity`
  - deploys Identity runtime, controllers, CRDs, ingress, certificates,
    OAuth2 providers, OAuth2 clients, quota metadata, and deployment-specific
    runtime options
  - keeps `platformAdministrators.subjects`, because that is environment
    assignment rather than role definition
  - does not define builtin roles or system-account bindings once migration is
    complete
- `charts/identity-roles`
  - is a generic chart instantiated by each service
  - renders only the roles supplied by that service's deployment chart
  - renders deployment-time metadata that binds that service's system account
    CNs to that service's protected roles
  - can mark service-owned platform-administrator roles, where relevant

Examples:

- Identity installs an `identity-roles` release for Identity API permissions and
  platform administrator bootstrap roles.
- Region installs an `identity-roles` release for Region endpoint permissions
  and the `unikorn-region` CN to `region-service` binding.
- Reservation installs an `identity-roles` release for Reservation user-facing
  roles, `reservation-service`, and `unikorn-reservation`.

### Ownership Constraint

Each core UNI service should define only the role objects and system-account
bindings for identities it owns.

Rules:

- A service owns its user-facing roles, protected service roles, and system
  account CN bindings.
- A role may include cross-service permissions only where the owning service's
  runtime code path actually needs those permissions.
- A service must not patch, extend, or partially own another service's role
  object.
- Each `Role` object must have exactly one chart/release owner.
- Environment-owned assignments, such as platform administrator subjects, stay
  outside service-owned role bundles.

This keeps review and rollback boundaries aligned with service behaviour. For
example, Region may own a `region-service` role that includes the Identity
permissions Region needs, but Identity should not own that role merely because
some of its scopes use `identity:*` endpoints.

### Aggregate Built-in Roles

The current Identity chart also defines aggregate built-in roles. These are
awkward for the service-owned model because each aggregate role is one `Role`
object whose permissions span several services.

`platform-administrator` is protected and global. It grants broad platform
administration across the current service set:

- Identity: organizations, OAuth2 providers, roles, service accounts, users,
  groups, projects, project references, quotas, and allocations
- Region: regions, flavors, images, external networks, identities, identity
  references, networks, network references, networks v2, network v2
  references, load balancers v2, security groups, security groups v2, servers,
  servers v2, file storage v2, file storage classes v2, and SSH certificate
  authorities v2
- Kubernetes: regions, flavors, images, cluster managers, clusters, and virtual
  clusters
- Compute: regions, flavors, images, instances, and clusters
- Storage: object storage classes, object storage endpoints, and object storage
  endpoint access keys

It is bound only through platform-administrator subject configuration and is not
returned through the user-facing role list.

The user-facing aggregate roles are:

- `administrator` is organization scoped. It grants broad organization
  administration: Identity organization read/update; Identity OAuth2 provider,
  service-account, user, role, group, and project CRUD; quota read; Region
  workload CRUD for networks v2, load balancers v2, file storage v2, security
  groups v2, and SSH CAs; Region catalogue reads; Region image
  read/create/delete; Storage endpoint and access-key CRUD; Kubernetes cluster
  and virtual-cluster CRUD; and Compute instance and cluster CRUD.
- `auditor` is organization scoped. It grants read-only access across the same
  aggregate surface as `administrator`: Identity administration resources,
  Region catalogue and workload resources, Storage classes/endpoints/access
  keys, Kubernetes catalogues/clusters, and Compute catalogues/workloads.
- `user` has both organization and project scopes. Its organization block is a
  discovery baseline: quota reads; Region, Kubernetes, and Compute catalogue
  reads; Storage object-storage-class reads; and Region image
  read/create/delete. Its project block grants workload authority: Identity
  project read; Region networks v2, load balancers v2, security groups v2, file
  storage v2, and SSH CAs; Storage endpoints and access keys; Kubernetes
  clusters and virtual clusters; and Compute instances and clusters.
- `reader` has both organization and project scopes. It is the read-only
  counterpart to `user`: organization-scope catalogue reads and project-scope
  workload reads across the same Region, Storage, Kubernetes, and Compute
  surfaces.

The grant lattice depends on those aggregate permissions:

```text
administrator -> auditor -> reader
administrator -> user -> reader
```

`administrator` can grant every user-facing aggregate role. `auditor` can grant
`reader` but not `user`, because `user` has write permissions. `user` can grant
`reader` but not `auditor`, because `auditor` includes Identity administration
reads that `user` does not hold. `reader` can grant only `reader`.

These roles are the main compatibility problem for service-owned role releases.
Multiple service releases cannot safely contribute scopes to the same
`administrator`, `auditor`, `user`, or `reader` object. The aggregate roles need
one owner each during migration, or they need to be replaced by service-specific
roles that group administrators can combine explicitly.

Do not introduce general aggregation into the user-facing aggregate roles. A
monotonic aggregation mechanism can preserve the lattice if it understands the
partial order and scope promotion rules, but that is more policy machinery than
this migration needs. The simpler conclusion is:

- Identity owns the built-in aggregate roles as a compatibility and platform UX
  exception.
- Core UNI service permissions can be represented in those built-ins through the
  Identity-owned aggregate role values.
- Non-core services define their own user-facing roles rather than extending
  `administrator`, `auditor`, `user`, or `reader`.
- Other services still instantiate their own `identity-roles` releases for
  service-owned protected roles and system account bindings.

A practical implementation is for `charts/identity` to depend on
`charts/identity-roles` and instantiate that subchart for the built-in aggregate
roles. Identity would own `platform-administrator`, `administrator`, `auditor`,
`user`, and `reader`, even though their scopes mention other services.

The only remaining aggregation exception is `platform-administrator`. It is
protected, global, and sits above the user-facing grant lattice. Adding a
service permission to `platform-administrator` cannot make
`administrator -> user`, `administrator -> auditor`, `auditor -> reader`, or
`user -> reader` invalid. This is useful for non-core service permissions that
platform administrators should hold without making those permissions part of the
built-in user-facing roles.

That exception still needs a single effective `platform-administrator` role at
runtime. Any platform-administrator aggregation must be rendered or reconciled
before RBAC resolves roles, and the final object should remain protected and
owned by the Identity aggregate-role release or an Identity-owned reconciler.

The test must change before making that chart split. `TestBuiltinRoleGrantability`
currently parses `charts/identity/values.yaml` directly. It should instead render
the Identity chart, extract the final built-in aggregate `Role` objects from the
rendered output, and run `AllowRole` against those rendered objects. That ensures
the guard covers the actual subchart values and templates that deployment uses.

### Role Data Location

Move fixed role definitions out of the Identity runtime chart. The reusable
`identity-roles` chart should only define the schema and templates for one
service-owned role bundle. Each service chart should provide its own role data
from service-owned chart files or templates, for example:

```text
charts/region/files/identity-roles.yaml
charts/reservation/files/identity-roles.yaml
```

The instantiated role chart values should be shaped around one owner:

```yaml
owner: region

systemAccounts:
  unikorn-region:
    role: region-service

roles:
  region-service:
    description: Region service
    protected: true
    scopes:
      global:
        identity:allocations: [create, read, update, delete]
        identity:projects: [read]
```

Cluster values should enable or version a service's role bundle, not carry the
role definitions themselves.

### Role Metadata Contract

Use metadata on protected `Role` resources to carry deployment-owned bindings:

```yaml
metadata:
  annotations:
    identity.unikorn-cloud.org/system-account-subjects: unikorn-region
    identity.unikorn-cloud.org/platform-administrator-role: "true"
```

Rules:

- `system-account-subjects` is a comma-separated list of authenticated system
  account subjects, usually certificate CNs.
- A subject must appear on at most one role. Duplicates are a consistency error
  and must fail closed.
- A system account role should be `protected: true`.
- System account ACL construction still uses only global scopes.
- `platform-administrator-role: "true"` identifies protected roles whose
  global scopes are used for platform administrators and internal super
  contexts.

This keeps the mapping configured by deployment-owned chart data, but lets RBAC
resolve it from Identity-owned stored state. It also removes the need for a
server restart when role bindings change, because `pkg/rbac` already loads
roles while constructing ACLs.

Do not model platform system accounts as the existing `ServiceAccount` CRD.
That resource is an organization-bound bearer-token actor. Reusing it for mTLS
system accounts would conflate two actor classes that the architecture keeps
separate.

## Migration Plan

### Phase 1: Add Dynamic RBAC Resolution

Update `pkg/rbac` to resolve these from stored `Role` objects:

- system account subject to protected role
- platform administrator role IDs

Keep the existing flags as compatibility fallback:

- `--system-account-roles-ids`
- `--platform-administrator-role-ids`

Precedence should be:

1. annotated roles, if any matching metadata exists
2. startup flags, for old charts and rollbacks

This phase does not move chart ownership yet. It makes the runtime capable of
surviving the later chart split.

Required tests:

- system account subject resolves through role annotation
- unknown system account still fails closed
- duplicate system account subject across roles fails closed
- platform administrator ACL can be built from annotated role metadata
- flag fallback still works during migration

### Phase 2: Introduce the Role Chart

Add `charts/identity-roles` as a reusable chart with no hardcoded service
catalogue. One release of the chart represents one service or feature bundle.

The reusable chart should render:

- service-supplied roles
- system-account binding annotations
- platform-administrator role annotations

Then instantiate it separately for each service owner. The first set should
cover at least:

- Identity-owned roles and platform administrator bootstrap role metadata
- Region-owned roles and the `unikorn-region` CN binding
- Kubernetes-owned roles and the `unikorn-kubernetes` CN binding
- Compute-owned roles and the `unikorn-compute` CN binding
- Storage-owned roles and the storage service CN binding
- Reservation-owned roles and the `unikorn-reservation` CN binding when
  Reservation is enabled
- feature-owned roles such as `envir-resource-manager` when the feature is
  enabled

Update local validation so both charts are checked:

- `helm lint --strict charts/identity`
- `helm lint --strict charts/identity-roles`
- `helm template identity-roles-region charts/identity-roles --namespace <identity namespace> -f <region role values>`

Move the builtin grantability guard away from
`charts/identity/values.yaml`. It should render the Identity chart, including
the `identity-roles` subchart values for the built-in aggregate roles, and
inspect the resulting `Role` specs. The guard must validate the rendered
Identity-owned aggregate roles; it should not assume every service contributes
to those same role objects.

### Phase 3: Support New Installs

For fresh deployments, install in this order:

1. apply Identity CRDs
2. install or upgrade `charts/identity` with legacy role rendering disabled
3. install or upgrade each service-owned `identity-roles` release into the
   Identity namespace
4. install service runtime charts that depend on those roles

The Identity server may start before roles exist, but ACL requests that depend
on roles will fail until the role chart has applied. In GitOps deployments, use
sync waves so all service-owned role applications are applied immediately after
CRDs and before dependent service runtimes.

`hack/ci/install` should install Identity's own role release. Test-only system
accounts should be additional role-chart instances or values on the relevant
test role release. The current CI override:

```yaml
systemAccounts:
  ci-fixtures: platform-administrator
```

should move from the Identity runtime values file to the role chart values.

### Phase 4: Adopt Existing Live Roles

Live clusters have `Role` objects owned by the existing Identity Helm release.
Moving each object to a service-owned role release without an adoption step
risks deletion or Helm ownership conflicts.

Use an explicit handoff:

1. Release an Identity chart that still renders roles but annotates them with
   `helm.sh/resource-policy: keep`.
2. Decide the target owner release for every existing role object. The built-in
   aggregate roles should target the Identity aggregate-role release.
3. Verify each target service-owned `identity-roles` render matches the live
   role object it will adopt.
4. Patch existing `Role` objects to the target service-owned Helm ownership
   metadata, or use a validated Helm ownership-takeover flow if available in
   the deployed Helm version.
5. Install each service-owned `identity-roles` release with the same release
   namespace and verify it adopts existing objects without replacing their
   specs.
6. Ensure the Identity aggregate-role release adopts
   `platform-administrator`, `administrator`, `auditor`, `user`, and `reader`.
7. Upgrade `charts/identity` with legacy role rendering disabled.
8. Verify all role objects still exist and system account ACLs resolve from role
   metadata rather than startup flags.

The `keep` annotation is the guard against the old release deleting role
objects when its manifest stops containing them. Do not remove the old
`roles.yaml` template in the same change that introduces the new chart unless a
live adoption procedure has already been validated.

### Phase 5: Remove Compatibility Surface

After all deployments use the role chart:

- remove builtin role definitions from `charts/identity/values.yaml`
- remove `charts/identity/templates/roles.yaml`
- remove `.Values.systemAccounts` from the Identity runtime chart
- remove `.Values.platformAdministrators.roles` from the Identity runtime chart
- keep `.Values.platformAdministrators.subjects` in the Identity runtime chart
- remove parent-chart inline role bundles once the owning service chart renders
  its own `identity-roles` instance
- remove the RBAC startup flag fallbacks in a later cleanup release

## Validation Checklist

For implementation PRs, use the standard repository checklist plus targeted
checks:

```sh
helm lint --strict charts/identity
helm lint --strict charts/identity-roles
helm template identity charts/identity --namespace unikorn-identity --set roles.enabled=false
helm template identity-roles-identity charts/identity-roles --namespace unikorn-identity -f <identity role values>
helm template identity-roles-region charts/identity-roles --namespace unikorn-identity -f <region role values>
go test ./pkg/rbac
```

Before committing and pushing, still run the repository-required checks:

```sh
make touch
make license
make validate
make lint
make generate
git status --porcelain
make test-unit
```

If integration fixtures or CI install scripts change, also read and follow the
Integration Testing Strategy before editing those files.

## Open Questions

- Should system account annotations be comma-separated for simple Helm output,
  or JSON arrays for stricter parsing?
- Should RBAC reject a system-account annotation on an unprotected role, or log
  and ignore it as invalid deployment data?
- Should the `platform-administrator` aggregation exception be rendered by the
  Identity chart, or reconciled by an Identity-owned controller?
- Should the role chart provide an adoption helper script for the live Helm
  handoff, or should GitOps repositories own that one-time migration?
