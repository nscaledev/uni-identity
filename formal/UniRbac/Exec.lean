/-
  UniRbac/Exec.lean — an *executable* layer for the enforcement relation.

  The theorems in Enforce.lean are stated over `Prop` (logical truth), which is
  perfect for proving but cannot be *run* to compute a decision. To generate
  conformance vectors (concrete allow/deny answers the Go code is tested against)
  we need a version that evaluates to a `Bool`.

  So this file defines `Bool`-valued twins of the `grants*` relations and then
  PROVES each one agrees with its `Prop` counterpart (the `..._iff` theorems).
  That is what lets the generated vectors carry the authority of the proofs: the
  numbers we emit come from a decision procedure certified equal to the spec.
-/

import UniRbac.Enforce

namespace UniRbac

/-
  A `BPerm` is the runnable form of a permission set: instead of mapping each
  (endpoint, operation) to a `Prop` (a truth value you reason about), it maps to
  a `Bool` (a truth value you can compute with and print).
-/
abbrev BPerm := String → Op → Bool

/-
  To compare a `BPerm` with the spec's `Perm`, we read a `Bool` as the `Prop`
  "...equals `true`". `BPerm.toPerm p` is the proposition-valued view of `p`.
-/
def BPerm.toPerm (p : BPerm) : Perm := fun e o => p e o = true

/-- The runnable form of `Acl`: the same three scope tables, but `Bool`-valued. -/
structure BAcl where
  global : BPerm
  org    : String → BPerm
  proj   : String → String → BPerm

/-- View a runnable `BAcl` as a spec `Acl`, scope by scope. -/
def BAcl.toAcl (a : BAcl) : Acl :=
  { global := a.global.toPerm
    org    := fun o => (a.org o).toPerm
    proj   := fun o p => (a.proj o p).toPerm }

/-
  The `Bool` twins of the enforcement chain. Note these use `||` (Boolean "or")
  where the `Prop` versions in Enforce.lean use `∨` (logical "or"). They have the
  same fall-through shape: global, then organization, then project.
-/
def bGrantsGlobal (a : BAcl) (e : String) (o : Op) : Bool :=
  a.global e o

def bGrantsOrg (a : BAcl) (org : String) (e : String) (o : Op) : Bool :=
  bGrantsGlobal a e o || a.org org e o

def bGrantsProj (a : BAcl) (org proj : String) (e : String) (o : Op) : Bool :=
  bGrantsOrg a org e o || a.proj org proj e o

/-
  Correspondence proofs. Each says: the runnable answer is `true` exactly when
  the spec relation holds (of the same ACL, viewed through `toAcl`). `simp`
  unfolds both sides and uses `Bool.or_eq_true` — the fact that `x || y = true`
  iff `x = true ∨ y = true` — to line up `||` with `∨`.
-/
theorem bGrantsGlobal_iff (a : BAcl) (e o) :
    bGrantsGlobal a e o = true ↔ grantsGlobal a.toAcl e o := by
  simp [bGrantsGlobal, grantsGlobal, BAcl.toAcl, BPerm.toPerm]

theorem bGrantsOrg_iff (a : BAcl) (org e o) :
    bGrantsOrg a org e o = true ↔ grantsOrg a.toAcl org e o := by
  simp [bGrantsOrg, grantsOrg, bGrantsGlobal, grantsGlobal,
    BAcl.toAcl, BPerm.toPerm, Bool.or_eq_true]

theorem bGrantsProj_iff (a : BAcl) (org proj e o) :
    bGrantsProj a org proj e o = true ↔ grantsProj a.toAcl org proj e o := by
  simp [bGrantsProj, grantsProj, bGrantsOrg, grantsOrg, bGrantsGlobal, grantsGlobal,
    BAcl.toAcl, BPerm.toPerm, Bool.or_eq_true]

end UniRbac
