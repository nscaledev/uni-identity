# `formal/` — a Lean 4 semantics for UNI RBAC

This directory contains an independent, machine-checked model of the pure,
security-critical core of [`pkg/rbac`](../pkg/rbac/README.md): the effective-authority engine. It is
a **proof artifact**, not part of the Go build — it lives outside the Go module on purpose, so
`make`, `go build ./...`, and CI never see it.

New to Lean? Read the files in the order below; each is heavily commented and
introduces the language features it uses, building on the previous one.

## Layout

| Module | Contents |
| --- | --- |
| [`UniRbac/Basic.lean`](./UniRbac/Basic.lean) | Core datatypes: `Op`, `Perm` (a permission set as a predicate), `Acl`. |
| [`UniRbac/Enforce.lean`](./UniRbac/Enforce.lean) | The `Allow*Scope` enforcement relation and downward scope flow. |
| [`UniRbac/Grant.lean`](./UniRbac/Grant.lean) | `Role`, `AllowRole`, and grant safety at global/organization scope. |
| [`UniRbac/ProjectCaveat.lean`](./UniRbac/ProjectCaveat.lean) | The counterexample: project-scope grant safety fails locally. |
| [`UniRbac/Intersect.lean`](./UniRbac/Intersect.lean) | `intersectACL` and confused-deputy soundness. |
| [`UniRbac/Accumulate.lean`](./UniRbac/Accumulate.lean) | ACL construction as union, and its monotonicity. |
| [`UniRbac/Exec.lean`](./UniRbac/Exec.lean) | Runnable `Bool` twins of the enforcement chain, proved equal to the `Prop` spec. |
| [`UniRbac/Vectors.lean`](./UniRbac/Vectors.lean) | The conformance-vector generator: scenario data, `evalAllowRole`, hand-written + generated cases, JSON. |
| [`Main.lean`](./Main.lean) | The `gen-vectors` executable entry point. |
| [`UniRbac.lean`](./UniRbac.lean) | Library root; imports everything above. |

## What is modelled

`pkg/rbac` splits into two halves:

1. **Enforcement** (`pkg/rbac/handler.go`) — the `Allow*Scope` fall-through chain
   with downward scope flow (global satisfies organization satisfies project),
   `AllowRole` / `allowGrantProjectScope`, and `intersectACL`. All are pure
   functions of the ACL, reproduced exactly.
2. **Construction** (`pkg/rbac/rbac.go`, `accumulate*`) — modelled abstractly as
   set union, since that is its whole authorization-relevant content.

An `Acl` is three permission tables keyed by scope; a `Perm` is a predicate over
`(endpoint, operation)` pairs, so union is `∨`, intersection is `∧`, and
membership is function application. This keeps the development **Mathlib-free** —
Lean core only.

## The theorems

| Lean name | Claim | README / handler.go anchor |
| --- | --- | --- |
| `inter_sound` | Impersonation intersection grants a permission only if **both** principal and service do — the service's *global* set gates every user scope. | "intersection = both sides"; confused-deputy invariant |
| `inter_no_escalation` | Intersection only ever *removes* authority. | least-privilege |
| `grant_global_safe`, `grant_org_safe` | At global/org scope, a grantable role confers only permissions the caller already holds. | "a caller may only grant a role if they already hold every permission it contains" |
| `project_grant_not_locally_subset` | **The "or otherwise":** at *project* scope that subset property is **false** locally — a caller holding a permission in project `A` can produce a grant that, applied to project `B`, confers authority they lack in `B`. | `handler.go:291-343` trust assumption |
| `global_grants_everywhere`, `org_grants_project` | Downward scope flow is monotone. | scope model |
| `accumulate_monotone` | ACL construction (union) only ever adds authority. | additivity of permissions |

### The interesting result

`project_grant_not_locally_subset` is not a bug report — it is the formal
statement of what `allowGrantProjectScope`'s doc comment says in prose: project-
scope grant safety rests on two **external** invariants (group create needs
org-scope `identity:groups` write; linking a group to a project needs project-
scope `identity:projects` update for *that* project). The local `AllowRole` check
alone does not imply a per-project subset relation. If either external invariant
is ever relaxed, project-scope granting becomes cross-project privilege
escalation. A natural next step is to encode those two invariants as explicit
hypotheses and prove the *conditional* project-scope soundness theorem.

The headline theorems in the `Prop` model are **axiom-free**: `#print axioms
<name>` reports no dependency, not even `Classical.choice`, so the proofs are
fully constructive. The executable-layer correspondence lemmas (`Exec.lean`'s
`..._iff`) additionally use `propext` — one of Lean's three standard, universally
accepted axioms — pulled in by `simp`'s iff rewriting.

## Conformance vectors — keeping the Go code in step

The model is not just proved; it is *run*, to generate the test data the real
`pkg/rbac` code is checked against. The pipeline:

```
UniRbac/Exec.lean     Bool decision procedure, proved equal to the Prop spec
UniRbac/Vectors.lean  scenarios + evalAllowRole (built on Exec) + JSON emitter
Main.lean  ──lake──▶  pkg/rbac/testdata/model_vectors.json   (the oracle)
                                    │
pkg/rbac/grant_model_test.go ◀──────┘  rebuilds each scenario, runs the real
                                       AllowRole, asserts it matches the model
```

- **The model is the oracle.** Every scenario's `expected` decision is computed
  by `evalAllowRole` (a transcription of `allowRole` onto the certified `bGrants*`
  combinators), never hand-typed on the Go side.
- **Two scenario sources.** A set of hand-written *base cases* — named scenarios
  that pin specific scope-flow outcomes — live in the vectors as `handwritten`
  entries, each carrying the outcome a human asserts (`humanExpect`); the
  generator refuses to emit unless the model reproduces every one. A 42-case
  oracle-`generated` matrix adds exhaustive scope-flow and operation-matching
  coverage.
- **No Lean needed for unit tests.** `model_vectors.json` is committed, so
  `make test-unit` runs `grant_model_test.go` with no toolchain. Only
  regeneration and the CI drift check need Lean.
- **Drift is caught, not assumed.** `.github/workflows/formal-model.yaml` rebuilds
  the proofs, regenerates the vectors, and fails if the committed JSON differs —
  so the Go code cannot silently diverge from the model.

To change the cases, edit the model and run `make regenerate-vectors`, then
commit the updated JSON.

## Building

```sh
cd formal
lake build
```

Requires the toolchain pinned in [`lean-toolchain`](./lean-toolchain)
(`leanprover/lean4:v4.32.2`); `elan` fetches it automatically. No other
dependencies.

To (re)generate the conformance vectors — run from the repository root, not here:

```sh
make regenerate-vectors      # writes pkg/rbac/testdata/model_vectors.json
```

To inspect the axiom footprint yourself:

```sh
echo 'import UniRbac
open UniRbac
#print axioms inter_sound
#print axioms project_grant_not_locally_subset' | lake env lean --stdin
```

## Fidelity caveats

- The model is the *abstract* ACL algebra. It does not model the Kubernetes read
  path (group/role/project listing), label selectors, or the platform-
  administrator issuer-matching fast-path — those are construction-side concerns
  whose authorization content is the union captured by `accumulate*`.
- `allowGrantProjectScope`'s "any accessible project" rule is modelled as the
  `∃ p` disjunct in `allowRole`; that is the exact source of the project-scope
  caveat above.
