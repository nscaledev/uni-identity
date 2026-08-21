# Cerbos Policy Generator

`generate.Generate(roles []unikornv1.Role) (*Output, error)` is a **pure, offline** transform: it
converts identity `Role` custom resources into a Cerbos policy store. No I/O, no Kubernetes client,
no side effects — it reads Role specs and returns typed documents plus their serialized files
(`Output.Files()`, relative path → YAML) for the policy controller to publish. See the
[design note](../../../../docs/cerbos-authorization-design.md) for where this fits in the broader
Cerbos authorization proof of concept — richer policies (ABAC), policy-as-config, and decoupled
authN/authZ over today's role model.

## Output

Two document shapes:

- **One shared derived-roles document** (`uni_roles`): one definition per (Role, non-empty scope
  bucket), named `role_<roleID>_<bucket>` with bucket ∈ `global | org | project`. The `role_` prefix
  guards against role IDs starting with a digit (Cerbos rejects those in identifiers).
- **One resource policy per endpoint name**: `resource` is the endpoint name **verbatim** (endpoint
  names are opaque open-vocabulary tokens — the generator never parses or allowlists them, only
  rejects names the pinned Cerbos version would refuse to load). Each policy has one `EFFECT_ALLOW`
  rule per (role, bucket) on that endpoint, with the bucket's operations as actions
  (`create | read | update | delete`, verbatim).

## The binding-string contract (cross-component invariant)

Derived-role conditions match a principal's bindings **byte-exactly**. The request builder — which
computes a principal's bindings from group membership at request time — MUST emit these exact
strings:

| Grant bucket | Binding string |
|---|---|
| global | `<roleID>#global` |
| organization | `<roleID>#org#<organizationID>` |
| project | `<roleID>#project#<organizationID>#<projectID>` |

`<roleID>` is the Role `metadata.name`, treated as opaque. `#` is a safe delimiter because role IDs
are UUIDs and organization/project IDs are Kubernetes resource names — none can contain `#`. The
generator enforces the Kubernetes-name charset on role IDs so they embed into binding strings and CEL
literals without escaping.

## Scope flow-down

Flow-down lives entirely in the derived-role CEL conditions (matching the one-directional semantics of
`pkg/rbac`):

- a **global** binding activates on any resource;
- an **org** binding activates when the resource's `organization` attribute matches the binding;
- a **project** binding activates only when BOTH `organization` and `project` attributes match — an
  org-level resource (no `project` attribute) can never activate it, so nothing flows upward.

## Why the root policy is an OVERRIDE grantor

Every resource policy is emitted at the root (`""`) scope with
`scopePermissions: SCOPE_PERMISSIONS_OVERRIDE_PARENT`. A composition spike showed that a consent-mode
policy cannot *originate* a grant (an all-consent chain denies everything), so the top of the scope
chain must be a grantor that sets the RBAC ceiling. That is the boundary of this first cut:
**root-only grantor policies here; the org/project consent-overlay scopes — tenant-authored narrowing,
and the ABAC condition predicates this PoC is proving the ground for — come later** and must not
appear in this generator's output.

## Determinism

Output is byte-stable for a given input set: roles sort by CR name, endpoints and actions sort
lexicographically, and YAML field order is fixed. File names are presentation-only — any character
outside `[a-zA-Z0-9._-]` in an endpoint name becomes `_`; the resource kind inside the document stays
verbatim, and two endpoints colliding on one file name is a loud error, never a silent merge.
Determinism is what lets the controller reconcile by content hash and lets the golden tests diff
byte-for-byte.

## Validation and fail-closed behaviour

- Role IDs are validated against the Kubernetes-name charset, so they embed into binding strings and
  CEL literals safely.
- Resource kinds are validated against what the pinned Cerbos version (`CERBOS_VERSION` in the
  Makefile) will load — an unloadable kind is rejected, never emitted.
- An **unknown scope bucket is a hard error** — fail-closed: it narrows to deny, never widens to a
  global grant.
- Duplicate output file names are a hard error.
- `Spec.Protected` is deliberately ignored: it governs a role's *grantability and visibility* (Go
  handler logic), not access decisions, so it has no representation in policy output.

## Testing

- Golden-file unit tests pin the byte-exact output for the fixture roles under `testdata/store/`
  (regenerate with `go test ./pkg/authz/cerbos/generate/... -update`).
- `testdata/store/` is itself a valid Cerbos store: `make validate-policies` compiles it with the
  pinned Cerbos image and runs the hand-written behavioural suite under `testdata/store/tests/`, which
  encodes flow-down, no flow-up, tenant isolation, exact-operation matching, additive union, and
  open-vocabulary endpoints.

## Fixtures and provenance

The fixture roles under `testdata/roles/` are transcribed by hand from the deployment's
`charts/identity/values.yaml` role definitions (each file records its source). Because this is a
public repository, the proprietary systems those roles reference are replaced by generic placeholder
endpoints (`example:*`, `sample:*`, `demo:*`, `blob:*`), so no internal service names appear in the
fixtures. They are **manually synchronized** — there is no automated check that they track the chart,
so when the chart's roles change these fixtures must be updated and the golden store regenerated. An
automated fixture-vs-chart consistency check is a candidate follow-up.
