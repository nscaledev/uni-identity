/-
  UniRbac/Basic.lean — the core data types.

  This file introduces the three building blocks everything else is phrased in
  terms of: operations (`Op`), permission sets (`Perm`), and the ACL record
  (`Acl`). It is the most Lean-syntax-dense file, so the comments are heavy on
  purpose — later files reuse these ideas with lighter commentary.
-/

/-
  `namespace UniRbac` opens a namespace. Every name defined below (e.g. `Op`)
  actually becomes `UniRbac.Op`. Any other file that `import`s this one and also
  writes `namespace UniRbac` can then use these names without the prefix. The
  matching `end UniRbac` at the bottom closes the namespace.
-/
namespace UniRbac

/-
  An *inductive type* is defined by listing its possible values, called
  "constructors". This is Lean's version of an enum. `Op` has exactly four
  values, matching the Go `unikornv1.Operation` constants Create/Read/Update/
  Delete.

  `deriving DecidableEq, Repr` asks Lean to auto-generate two helpers:
    * `DecidableEq Op` — an algorithm that decides whether two `Op`s are equal.
      This is what later lets the `decide` tactic settle `Op` (in)equalities.
    * `Repr Op` — a way to print an `Op`, handy if you ever `#eval` one.
-/
inductive Op where
  | create
  | read
  | update
  | delete
deriving DecidableEq, Repr

/-
  A *permission set* answers one yes/no question: "is operation `o` on endpoint
  `e` granted?" We represent it directly as a function from an endpoint name
  (`String`) and an `Op` to `Prop`.

  `Prop` is the type of logical propositions — statements that are true or false
  *as mathematics*, not as a runtime boolean you can branch on. So a `Perm` maps
  each (endpoint, operation) pair to the proposition "this pair is granted".

  `abbrev` (abbreviation) is like `def` but marked always-unfoldable, so Lean
  treats `Perm` and its right-hand side as freely interchangeable.

  Why a predicate rather than a `List` or a `Set`? It keeps us in Lean's core
  library with no Mathlib dependency: set membership becomes function
  application, union becomes logical "or" (`∨`), and intersection becomes logical
  "and" (`∧`).
-/
abbrev Perm := String → Op → Prop

/-
  The empty permission set: nothing is granted, so every query maps to `False`
  (the always-false proposition). `fun _ _ => False` is an anonymous function (a
  "lambda") that ignores both of its arguments — the `_` are throwaway names.
-/
def Perm.none : Perm := fun _ _ => False

/-
  Union of two permission sets. A pair is granted by the union exactly when `a`
  grants it OR `b` does; `∨` is logical "or". This mirrors how the Go helper
  `addScopesToEndpointList` merges role scopes into an ACL endpoint list.
-/
def Perm.union (a b : Perm) : Perm := fun e o => a e o ∨ b e o

/-
  A `structure` bundles several named fields into one record type, much like a Go
  struct. `Acl` mirrors `openapi.Acl`. The Go type stores organizations and
  projects as lists keyed by an `Id`; we instead key them by *function*:

    * `global`      : the platform-wide permission set (Go: `Acl.Global`)
    * `org id`      : permissions granted for organization `id`
    * `proj id pid` : permissions granted for project `pid` in organization `id`

  An organization or project that was never granted anything simply maps to a
  permission set where every query is `False` — the model's equivalent of being
  absent from the Go list.
-/
structure Acl where
  global : Perm
  org    : String → Perm
  proj   : String → String → Perm

end UniRbac
