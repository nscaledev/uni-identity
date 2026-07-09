# Cerbos Authorization

## Purpose

This tree implements the Cerbos side of the authorization migration described
in [docs/cerbos-authorization-migration-design.md](../../../docs/cerbos-authorization-migration-design.md):
replacing homegrown access-decision evaluation in [rbac](../rbac/README.md)
with policies evaluated by a central Cerbos PDP.

Currently it contains one package:

- [generate](#the-generate-package) — a pure function converting `Role` custom
  resources into Cerbos policy documents.

The Cerbos client and the controller that reconciles generated policies into
the PDP arrive with later migration tasks.

## The generate Package

`generate.Generate(roles []unikornv1.Role) (*Output, error)` converts Role CRs
into two document shapes, exposed both as typed documents and as serialized
files (`Output.Files()`, relative path → YAML) for the future policy
controller to write:

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
