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
import UniRbac.Groups

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

/-!
  ## The runnable form of the membership gate

  Note what is *not* needed here. `Perm` required a `BPerm` twin because it is a
  function into `Prop` — there is nothing to compute with. A `GroupSpec` is plain
  data (lists of strings), so it needs no twin at all; it can be printed and
  compared as it stands. Only the *predicate over it* needs one.
-/

/-
  `bHasMemberByID` mirrors `hasMemberByID` from Groups.lean, translating each
  connective into its computable counterpart: `∨` becomes `||`, `∧` becomes `&&`,
  `≠` becomes `!=`, and the bounded existential `∃ s ∈ l, ...` becomes
  `l.any (fun s => ...)`.

  `List.any` is used for both arms rather than `List.contains` on the string one.
  The two are equivalent, but the core lemma bridging `contains` and `∈` has been
  renamed more than once across Lean versions, whereas `List.any_eq_true` has
  been stable. Since the whole value of this layer is that its correspondence
  proof goes through, that is worth the slight asymmetry with the Go, which uses
  `slices.Contains`.
-/
def bHasMemberByID (g : GroupSpec) (orgUserID subjectID : String) : Bool :=
  (orgUserID != "" && g.userIDs.any (fun u => u == orgUserID))
  || (subjectID != "" && g.subjects.any (fun s => s.id == subjectID))

/-
  The correspondence, in the same shape as the three above: the runnable answer is
  `true` exactly when the specification predicate holds.

  The `simp` set is again "every definition on both sides, plus the bridging
  lemmas". The new entries beyond the `Bool.or_eq_true` pattern already used are:
  `List.any_eq_true` (lining `l.any p` up with `∃ x ∈ l, p x`), `bne_iff_ne`
  (`a != b` with `a ≠ b`), and `beq_iff_eq` (`a == b` with `a = b`).

  With this proved, a vector emitted from `bHasMemberByID` carries the authority
  of `hasMemberByID_sound`: the decision procedure that produced it is certified
  equal to the predicate the theorem is about.
-/
theorem bHasMemberByID_iff (g : GroupSpec) (orgUserID subjectID : String) :
    bHasMemberByID g orgUserID subjectID = true ↔ g.hasMemberByID orgUserID subjectID := by
  simp [bHasMemberByID, GroupSpec.hasMemberByID, List.any_eq_true, Bool.or_eq_true,
    Bool.and_eq_true, bne_iff_ne, beq_iff_eq]

end UniRbac
