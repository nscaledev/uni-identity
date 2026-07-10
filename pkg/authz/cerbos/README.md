# Cerbos Authorization

## Purpose

This tree implements the Cerbos side of the authorization migration described
in [docs/cerbos-authorization-migration-design.md](../../../docs/cerbos-authorization-migration-design.md):
replacing homegrown access-decision evaluation in [rbac](../rbac/README.md)
with policies evaluated by a central Cerbos PDP.

It contains:

- the package root — a thin gRPC [client](#the-client) for the PDP, which
  runs as a [sidecar](#the-sidecar) of the identity server.
- [generate](#the-generate-package) — a pure function converting `Role` custom
  resources into Cerbos policy documents.
- [controller](#the-policy-controller) — the reconciling policy controller
  publishing generated policies to the sidecar's policy store ConfigMap.

The layers built on top of this tree live in [pkg/rbac](../rbac/README.md):
the bindings resolver (`ResolveBindings`) that turns group memberships into
the [request builder](#the-request-builder)'s `RoleBinding` values, and the
decision API (`Check`/`CheckMany`) that sends requests through the client and
maps responses to allow/deny.

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
  is the A4 request builder's job) and applies a per-call deadline
  (`--cerbos-check-timeout`, default 2s).
- `Healthy(ctx)` performs a `ServerInfo` round-trip, the cheapest
  connectivity probe the API offers.

**Fail-closed contract**: every failure to obtain a decision — connection
refused, deadline expiry, server error — returns an error wrapping the static
`ErrUnavailable` sentinel, never a response.  The client never fabricates an
allow or deny; the decision API (`rbac.Check`/`CheckMany`, see
[pkg/rbac](../rbac/README.md)) maps the sentinel to its deny-shaped
`ErrDecisionUnavailable`.  On the response side the SDK's `IsAllowed` returns
false for missing actions, missing resources and errored results, so an allow
is only reachable through an explicit `EFFECT_ALLOW`.  Explicit timeout→deny
metrics and decision audit logging arrive with A10.

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
`scopePermissions: SCOPE_PERMISSIONS_OVERRIDE_PARENT`.  The A13 spike
(see design doc §3.3) verified that a consent-mode policy cannot *originate* a
grant: an all-consent chain denies everything.  The top of the scope chain
must therefore be a grantor that sets the RBAC ceiling.  This is the M1
boundary: **root-only grantor policies here; org/project CONSENT overlay
scopes (tenant-authored narrowing) are M2** and must not appear in this
generator's output.  Wherever overlay scopes exist later, the chain must have
no gaps — which is why a root policy exists for every resource kind.

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

- a missing ConfigMap (including the one-time A1→A3 `helm upgrade` deleting
  the previously chart-templated one, rollbacks, or GitOps pruning) is
  self-healing: the next reconcile re-gates and recreates it from the Roles;
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
  and NotFound recreation.
- `make test-cerbos-controller` (Docker-dependent like `make
  validate-policies`, so not part of `test-unit`) extracts the pinned binary
  from the image via `docker create`/`docker cp` and runs the real gate:
  a generated store compiles (exit 0), a broken policy is classified as exit
  3, and the hash-key scheme emits stable, valid ConfigMap keys.  On
  non-Linux hosts the Linux binary cannot exec, so the same gate code drives
  the pinned image via `docker run` instead; CI always tests the direct-exec
  path production uses.
- The end-to-end "apply a Role, watch a decision flip" assertion needs the
  kind stack to reach the loopback PDP, which no harness supports yet: it is
  deliberately deferred to the kind-parity migration task (A11).

## The Request Builder

`request.go` is the pure half of request construction: resolved bindings +
resource + actions → the SDK types `CheckResources` sends.  It is
deliberately ONLY that — the Kubernetes-reading resolver that turns group
memberships into `RoleBinding` values is `rbac.ResolveBindings`, and the
decision API that maps responses (and `ErrUnavailable`) to allow/deny is
`rbac.Check`/`rbac.CheckMany` (both documented in
[pkg/rbac](../rbac/README.md)); the impersonation dual-check is A14 — until
it lands the decision API refuses impersonated requests outright with
`ErrImpersonationNotSupported`, so **A7's shadow comparator must exclude or
annotate impersonated requests**; and the `AllowProjectScopeCreate`
orchestration follows with A9.  The builder is actor-class-agnostic: it
renders whatever bindings it is given, and the actor-class shapes (user,
platform admin, service account, system account) are pinned as table tests
which the resolver's own tests mirror.

`BuildPrincipal(subjectID, bindings)` renders the [binding-string
contract](#the-binding-string-contract-cross-component-invariant) into the
principal's `bindings` attribute — **list form**, which the committed policy
fixtures pin (a map keyed by binding for O(1) CEL lookup is a possible M2
performance change, but it is a wire-shape change: the fixtures and every
generated CEL condition must move together).  Bindings are deduplicated and
sorted, so semantically identical inputs yield byte-identical requests
(caching and logging determinism).  The static parent role `principal` is
MANDATORY: every generated derived role declares `parentRoles: [principal]`,
so a request without it denies everything.

`BuildResource(kind, id, organizationID, projectID)` encodes scope by
attribute **absence**, never by empty values:

| Check level | `organization` attr | `project` attr |
|---|---|---|
| global | absent | absent |
| org | present | **absent** |
| project | present | present |

**Warning**: the `project` attribute on an org-level check must be ABSENT,
not empty — a present-and-matching value would let project bindings activate
(flow-up).  The no-flow-up invariant depends on this absence.  A project
check activates global + matching-org + matching-project bindings in one
request: the Go three-level cascade collapses into a single Cerbos check.

An empty resource id becomes `CoarseResourceID` (`"*"`): the engine proto
requires a non-empty id (`min_len 1`), and the constant is pinned because it
is part of the future A15 decision-cache key.  `BuildBatch` fails loudly
where the SDK's `ResourceBatch.Add` silently no-ops (nil resources, empty
action lists) — a silently empty batch would be an authorization request that
checks nothing.  Actions are `openapi.AclOperation` values passed through
verbatim, deduplicated and sorted.

The fixtures-parity tests (`request_parity_test.go`) parse the committed
policy-suite fixtures under `generate/testdata/store/tests/testdata/` and
prove the builder reproduces every fixture principal and resource
byte-for-byte — including attribute-key absence — so the builder and the
CI-validated policy suite cannot drift apart silently.
