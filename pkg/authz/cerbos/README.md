# Cerbos Authorization

## Purpose

This tree implements the Cerbos side of the authorization migration described
in [docs/authorization/cerbos-authorization-design.md](../../../docs/authorization/cerbos-authorization-design.md):
replacing homegrown access-decision evaluation in [rbac](../../rbac/README.md)
with policies evaluated by a central Cerbos PDP.

It contains:

- the package root — a thin gRPC [client](#the-client) for the PDP, which
  runs as a [sidecar](#the-sidecar) of the identity server.
- [generate](#the-generate-package) — a pure function converting `Role` custom
  resources into Cerbos policy documents.
- [controller](#the-policy-controller) — the reconciling policy controller
  publishing generated policies to the sidecar's policy store ConfigMap.

The decision layers built on top of this tree live in
[pkg/rbac](../../rbac/README.md).

## The Client

`New(options *Options)` constructs a client for the PDP sidecar
(`--cerbos-endpoint`, default `localhost:3593` — plaintext gRPC, since the
sidecar shares the pod's network namespace).  It validates static
configuration, wrapping failures in the `ErrOptions` sentinel (distinct from
the runtime `ErrUnavailable` taxonomy): endpoints whose host is not loopback
are refused (the PDP is an unauthenticated same-pod sidecar by design — a
remote PDP would need mTLS and revisits this), as are non-positive check
timeouts (a zero value would insta-deny every check while the sidecar looks
healthy).  Construction is otherwise lazy: the underlying gRPC channel
connects on first use, so `New` succeeding says nothing about sidecar
liveness — pod readiness gates on the sidecar's own health probe instead.

- `CheckResources(ctx, principal, batch)` passes the SDK types through
  verbatim (request construction — principals, resources, binding strings —
  is the request builder's job) and applies a per-call deadline
  (`--cerbos-check-timeout`, default 2s).
- `Healthy(ctx)` performs a `ServerInfo` round-trip, the cheapest
  connectivity probe the API offers.

**Fail-closed contract**: every failure to obtain a decision — connection
refused, deadline expiry, server error — returns an error wrapping the static
`ErrUnavailable` sentinel, never a response.  The client never fabricates an
allow or deny; the decision API that consumes this client maps the sentinel to
a deny-shaped unavailability error.  On the response side the SDK's `IsAllowed` returns
false for missing actions, missing resources and errored results, so an allow
is only reachable through an explicit `EFFECT_ALLOW`.  The decision
observability — audit records and metrics for every served outcome, timeouts
included — lives at the decision choke point in
[pkg/rbac](../../rbac/README.md), NOT here: a client decorator would miss the pre-PDP fail-closed denials, and
the client deliberately stays log-free.

The integration test (`make test-cerbos-client`, Docker-dependent like `make
validate-policies` and therefore not part of `test-unit`) runs the pinned
Cerbos image with a hand-written allow/deny policy under `testdata/` and pins
all of the above, including that the image works under the chart's security
constraints (non-root user, read-only root filesystem).

## The Sidecar

`charts/identity` runs Cerbos as an always-on sidecar of the identity server
pod, image pinned to `CERBOS_VERSION` in the Makefile:

- configuration comes from the `<release>-cerbos-config` ConfigMap: HTTP on
  3592 and gRPC on 3593 bound to loopback only (the PDP is unauthenticated
  and must never bind pod interfaces), disk storage watching `/policies`,
  telemetry disabled, and no admin API (M1 forbids it; the disk driver does
  not support it).  Cerbos reads this config only at startup, so a checksum
  annotation on the pod template rolls the pods on config changes; the
  policies ConfigMap is deliberately not annotated (it is live-watched).
- policies come from the `<release>-cerbos-policies` ConfigMap, mounted
  read-only at `/policies` as an `optional` volume.  The chart does not
  template the ConfigMap: the [policy controller](#the-policy-controller)
  owns, creates and publishes it at runtime, nothing else writes it.  Before
  the first publish the volume is an empty directory and Cerbos serves
  deny-by-default; the kubelet back-fills the volume once the ConfigMap
  appears.
- readiness and liveness exec the in-image `cerbos healthcheck` binary
  against the mounted config (the loopback binding puts the HTTP endpoint out
  of the kubelet's reach), so the pod only becomes Ready once the PDP is
  serving.  Unit tests pin the integration-test fixtures to the chart: the
  test config must match the chart's except the listen addresses (docker
  port-publishing cannot reach container-loopback) and the test execs the
  chart's exact probe command.

## The generate Package

`generate.Generate(roles []unikornv1.Role) (*Output, error)` converts Role CRs
into two document shapes, exposed both as typed documents and as serialized
files (`Output.Files()`, relative path → YAML) for the policy controller to
publish:

- **One shared derived-roles document** (`uni_roles`): one definition per
  (Role CR, non-empty scope bucket), named `role_<roleID>_<bucket>` with
  bucket ∈ `global|org|project`.  The `role_` prefix guards against role IDs
  starting with a digit, which Cerbos rejects in identifiers.
- **One resource policy per endpoint name**: `resource` is the endpoint name
  **verbatim** (endpoint names are opaque open-vocabulary tokens — the
  generator never parses or allowlists them, only rejects names the pinned
  Cerbos version (`CERBOS_VERSION` in the Makefile) would refuse to load;
  `:` and `/` are accepted in resource kinds).  Each policy has one
  `EFFECT_ALLOW` rule per
  (role, bucket) granting on that endpoint, with the bucket's operations as
  actions (`create|read|update|delete`, verbatim).

Output is deterministic: roles sort by CR name, endpoints and actions
lexicographically, and YAML field order is fixed, so the emitted bytes are
byte-stable for a given input set.  File names are presentation only: any
character outside `[a-zA-Z0-9._-]` in an endpoint name becomes `_` (the
resource kind inside the document stays verbatim), and two endpoints mapping
to the same file name is a loud error, never a silent merge.

### The Binding-String Contract (cross-component invariant)

Derived-role conditions match principal bindings **byte-exactly**.  The
request builder in identity (which computes a principal's bindings from group
membership at request time) MUST produce these exact strings:

| Grant bucket | Binding string |
|---|---|
| global | `<roleID>#global` |
| organization | `<roleID>#org#<organizationID>` |
| project | `<roleID>#project#<organizationID>#<projectID>` |

`<roleID>` is the Role CR `metadata.name` (a UUID, treated as opaque).  `#` is
a safe delimiter because role IDs are UUIDs and organization/project IDs are
Kubernetes resource names, neither of which can contain `#`; the generator
enforces the Kubernetes-name charset on role IDs so they embed into binding
strings and CEL literals without escaping.

There is no read-clamped global bucket.  A global binding grants everything in
the role's global scope block, so a grant that must be narrowed to read-only
cannot be expressed as a binding: it needs a narrower role, or a fourth bucket
here.  This is why `pkg/rbac` fails closed on a matched wildcard subject
binding, which the legacy ACL path clamps to read — see
[pkg/rbac](../../rbac/README.md#global-role-bindings).

Flow-down is expressed entirely in these conditions (matching the
one-directional semantics of `pkg/rbac`):

- a **global** binding activates on any resource;
- an **org** binding activates when the resource's `organization` attribute
  matches the binding;
- a **project** binding activates only when BOTH `organization` and `project`
  attributes match — a resource without a `project` attribute (an "org-level"
  resource) can never activate it, so nothing flows upward.

### Why the Root Policy Is an OVERRIDE Grantor

Every resource policy is emitted at the root (`""`) scope with
`scopePermissions: SCOPE_PERMISSIONS_OVERRIDE_PARENT`.  A composition spike
verified that a consent-mode policy cannot *originate* a grant: an all-consent
chain denies everything.  The top of the scope chain must therefore be a grantor
that sets the RBAC ceiling.  This is the M1 boundary: **root-only grantor
policies here; org/project CONSENT overlay scopes (tenant-authored narrowing)
are M2** and must not appear in this generator's output.  Wherever overlay
scopes exist later, the chain must have no gaps — which is why a root policy
exists for every resource kind.

### Why `Spec.Protected` Is Ignored

`Protected` governs role *grantability and visibility* (who may see or assign
a role), which stays in Go handler logic — it is not an access-decision input,
so it has no representation in policy output.

### Testing

- Golden-file unit tests pin the byte-exact output for the fixture roles
  under `generate/testdata/store/` (regenerate with
  `go test ./pkg/authz/cerbos/generate/... -update`).
- That directory is itself a valid Cerbos policy store: `make
  validate-policies` compiles it with the pinned Cerbos image and runs the
  hand-written behavioural suite under `generate/testdata/store/tests/`,
  which encodes flow-down, no flow-up, tenant isolation, exact-operation
  matching, additive union, and open-vocabulary endpoints.

## The Policy Controller

`controller` is the domain logic behind the `unikorn-policy-controller`
binary (thin factory in `pkg/controllers/policy`; see
[pkg/controllers](../../controllers/README.md)).  It handles GitOps-applied
*and* manually-applied `Role` CRs identically: any Role create, spec update
or delete collapses into one synthetic reconcile request that regenerates the
whole store.

Each reconcile:

1. lists the `Role` CRs in the identity namespace (`--namespace`) and runs
   [generate](#the-generate-package) over them — the store is always rebuilt
   from source, never patched;
2. skips out immediately if the existing ConfigMap already holds exactly the
   generated content (the hash-suffixed key set encodes content, so this is
   cheap);
3. otherwise materializes the candidate store in `/tmp` and runs the
   **compile gate**: it exec's the vendored pinned `cerbos compile` binary
   (`--cerbos-binary`, baked into the controller image by
   `docker/unikorn-policy-controller/Dockerfile` from the same pinned image
   the sidecar runs — the `validate-cerbos-version` guard covers the pin);
4. publishes to the ConfigMap named by `--cerbos-policies-configmap` only on
   exit 0.

**Compile-gate semantics (fail-closed)**: exit 3 (compile failure) and exit 4
(policy test failure) are classified into distinct error sentinels
(`ErrCompileFailed`, `ErrTestsFailed`); those, any other non-zero exit, any
gate I/O error, and any generation error all REFUSE publication — the
ConfigMap is left untouched so the sidecar keeps serving the last-good store,
a warning event (`PolicyStoreRejected`) is emitted on the ConfigMap, and the
error is logged and returned for retry with backoff.  There is no code path
that publishes an unvetted store.  The gate never passes `--skip-tests`.

### The Single-ConfigMap Size Ceiling (caveat)

The whole generated store is published into **one** ConfigMap, which the
Kubernetes API server caps at ~1 MiB (the etcd request-size limit enforced by
`ValidateConfigMap`).  A candidate store whose key+value bytes would exceed the
ceiling is refused by a **pre-publish size gate** that runs *before* the compile
gate (cheap-first — do not compile a store that cannot be published):
`--cerbos-max-policy-store-bytes` (default 1 MiB, `defaultMaxPolicyStoreBytes`)
sets the limit.  The refusal mirrors the compile gate exactly — the ConfigMap is
left untouched so the sidecar keeps serving the last-good store, a warning event
(`PolicyStoreTooLarge`) is emitted on it, and an `ErrPolicyStoreTooLarge`
reconcile error is returned for backoff.  Without this gate an over-cap store
fails the opaque `CreateOrUpdate` publish and silently freezes at last-good with
no dedicated signal — the gate turns that silent freeze into a legible refusal.
Sharding the store across multiple ConfigMaps, or moving to a non-ConfigMap
Cerbos store (blob/git/DB), is **M2**.

### The Hash-Suffixed Key Scheme (load-bearing)

Every generated file `<base>.yaml` is published under the ConfigMap key
`<base>-<sha256[:8]>.yaml` (first 8 hex characters of the content hash).
This is mandatory, not cosmetic: the kubelet updates ConfigMap volumes by
atomically swapping a hidden `..data` symlink (kubernetes
`pkg/volume/util/atomic_writer.go`), and Cerbos's disk watcher drops
hidden-name events and only reloads the exact visible paths in an event batch
(cerbos@v0.53.0 `internal/storage/disk/dirwatch.go`) — so a content update
under an unchanged key is **never** reloaded.  With hash-suffixed keys,
changed content swaps keys, which the kubelet surfaces as visible symlink
delete+create events the watcher does reload; deletions are processed before
creations, so a key swap has no duplicate-definition window.  Unchanged files
keep byte-identical keys: no events, no reload needed.

**Publish latency**: a published change reaches the PDP after the kubelet's
volume sync (~1 minute by default) plus Cerbos's 2s reload cooldown.  Fine
for M1's role-edit cadence; revisit if policy changes ever need to be
near-instant.

### ConfigMap Ownership (operational notes)

The controller owns the policy store ConfigMap outright and marks it
`app.kubernetes.io/managed-by: unikorn-policy-controller` (repo convention is
labels, not ownerReferences).  Consequences:

- a missing or tampered ConfigMap (the one-time `helm upgrade` deleting
  the previously chart-templated one, rollbacks, GitOps pruning, or an
  out-of-band edit) is self-healing: the controller watches the ConfigMap
  itself, so a delete (it is an `optional` volume — while it is gone Cerbos
  serves deny-by-default) or a data mutation triggers a reconcile that re-gates
  and republishes from the Roles.  The watch uses a **namespace-scoped**
  informer, not the manager's cluster-wide cache, because the ConfigMap RBAC is
  a namespaced `Role` (there is no ClusterRole for configmaps) — the same
  reason the reconciler's ConfigMap reads go through an uncached client.  A
  bounded periodic requeue (`resyncPeriod`) re-verifies the store as a
  belt-and-suspenders backstop for any missed event, far tighter than the
  informer cache's ~10h resync;
- `helm uninstall` does **not** delete it — labels give no garbage
  collection, so the orphaned ConfigMap must be removed manually if the
  release is gone for good;
- the chart's RBAC scopes writes to this single object (the effective
  authorization policy — least privilege), and only the controller's
  ServiceAccount holds them.

### Controller Testing

- Fake-client unit tests pin the reconcile contract: byte-exact publishes
  under hash-suffixed keys, unchanged-content no-ops, gate refusals keeping
  last-good, Role deletion shrinking the store (the watch predicate passing
  delete events is itself pinned by a unit test in `pkg/controllers/policy`),
  NotFound recreation, out-of-band data-mutation restoration, and the periodic
  safety-net requeue.  The ConfigMap watch's own predicate (matching only the
  managed store, on create/update/delete) and its fan-in enqueue are pinned by
  unit tests in `pkg/controllers/policy` alongside the Role ones.
- `make test-cerbos-controller` (Docker-dependent like `make
  validate-policies`, so not part of `test-unit`) extracts the pinned binary
  from the image via `docker create`/`docker cp` and runs the real gate:
  a generated store compiles (exit 0), a broken policy is classified as exit
  3, and the hash-key scheme emits stable, valid ConfigMap keys.  On
  non-Linux hosts the Linux binary cannot exec, so the same gate code drives
  the pinned image via `docker run` instead; CI always tests the direct-exec
  path production uses.
