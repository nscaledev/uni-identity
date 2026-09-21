/-
  UniRbac/Enforce.lean — the enforcement relation (pkg/rbac/handler.go).

  This models the three `Allow*Scope` helpers a handler calls to decide whether a
  request is permitted, and proves that their "downward scope flow" behaves as the
  README describes.
-/

/-
  `import` makes the names from another module available here. We need `Acl` and
  `Op` from Basic. Imports are transitive, so files that later import Enforce also
  get Basic for free.
-/
import UniRbac.Basic

namespace UniRbac

/-
  `def grantsGlobal ...` defines a function. Read the signature as: given an ACL
  `a`, an endpoint `e`, and an operation `o`, produce a `Prop` — the statement
  "`a` grants `o` on `e` at global scope". The body is just the membership check
  in the global permission set. This is `AllowGlobalScope`.
-/
def grantsGlobal (a : Acl) (e : String) (o : Op) : Prop :=
  a.global e o

/-
  `AllowOrganizationScope`: the Go code tries the global scope first and only then
  the organization's own endpoints. We encode "either one suffices" with `∨`
  ("or"). Because `grantsGlobal` is the left disjunct, a global grant
  automatically satisfies an organization check — this is the "downward scope
  flow" from the README, made literal.
-/
def grantsOrg (a : Acl) (org : String) (e : String) (o : Op) : Prop :=
  grantsGlobal a e o ∨ a.org org e o

/-
  `AllowProjectScope`: try organization scope (which itself already folds in
  global), then finally the specific project's endpoints.
-/
def grantsProj (a : Acl) (org proj : String) (e : String) (o : Op) : Prop :=
  grantsOrg a org e o ∨ a.proj org proj e o

/-
  Our first *theorem*. A theorem has a name, a statement (after the colon), and a
  proof (after `:=`). Here the statement is an implication `→`: IF `a` grants
  (e,o) globally, THEN it grants it at project scope.

  The proof is in *tactic mode*, opened by `by`. Tactics are step-by-step
  commands that transform the goal:
    * `intro h` — when the goal is `A → B`, assume `A` (naming it `h`) and leave
      `B` to prove.
    * `exact t` — finish by supplying a term `t` whose type is exactly the goal.

  `Or.inl` turns a proof of the left side of an `∨` into a proof of the whole
  `∨` (and `Or.inr` does the right side). `grantsProj` unfolds to
  `(grantsGlobal ∨ _) ∨ _`, so to reach the leftmost slot we wrap twice:
  `Or.inl (Or.inl h)`.
-/
theorem global_grants_everywhere (a : Acl) (org proj e o) :
    grantsGlobal a e o → grantsProj a org proj e o := by
  intro h
  exact Or.inl (Or.inl h)

/-- An organization grant is likewise usable at project scope: one `Or.inl` to
    reach the organization side of `grantsProj`. -/
theorem org_grants_project (a : Acl) (org proj e o) :
    grantsOrg a org e o → grantsProj a org proj e o := by
  intro h
  exact Or.inl h

end UniRbac
