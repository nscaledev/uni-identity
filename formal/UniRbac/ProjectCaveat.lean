/-
  UniRbac/ProjectCaveat.lean — the "or otherwise".

  At *project* scope the subset property proved for global/org scope in Grant.lean
  FAILS as a local theorem. We prove that by exhibiting a concrete counterexample:
  a caller who is legitimately allowed to grant a project-scoped role, yet cannot
  themselves perform that permission in the project the grant may end up applied
  to.

  This is not a bug in the Go code. `allowGrantProjectScope` documents (handler.go
  lines 291-343) that project-scope grant safety rests on two EXTERNAL invariants:
  group create needs org-scope `identity:groups` write, and linking a group to a
  project needs project-scope `identity:projects` update for THAT project. The
  local `AllowRole` check alone does not imply a per-project subset relation —
  which is exactly what this file makes precise.
-/

import UniRbac.Grant

namespace UniRbac

/-
  We build a tiny concrete world. `private def` means these helpers are visible
  only inside this file — they are scaffolding for the counterexample, not part
  of the model's public surface. `endptX` is a single endpoint name.
-/
private def endptX : String := "model:project"

/-
  The caller's authority: they hold `(endptX, create)` in exactly ONE project —
  project "A" of organization "O" — and nothing anywhere else.

  Each field is a function (a `Perm`, or an org-indexed family of them):
    * `global` is `Perm.none`, the empty set;
    * `org` ignores its arguments and returns `False` — no org-scope grants;
    * `proj o p e op` returns a conjunction of equalities that is true only when
      the org is "O", the project is "A", the endpoint is `endptX`, and the
      operation is `create`. For any other project (say "B") the conjunction is
      false, so nothing is granted there.
-/
private def callerAcl : Acl where
  global := Perm.none
  org    := fun _ _ _ => False
  proj   := fun o p e op => o = "O" ∧ p = "A" ∧ e = endptX ∧ op = Op.create

/-- A role that grants `(endptX, create)` purely at project scope. -/
private def projRole : Role where
  global := Perm.none
  org    := fun _ _ => False
  proj   := fun e op => e = endptX ∧ op = Op.create

/-
  First fact: the grant IS allowed. `allowRole callerAcl projRole "O"` holds
  because the caller holds the permission in project "A" (which is *some*
  project), satisfying the `∃ p` disjunct of `allowRole`'s project requirement.

  Proof walkthrough:
    * `refine ⟨?_, ?_, ?_⟩` — `allowRole` is a triple `∧`. `⟨_, _, _⟩` is the
      "anonymous constructor" that builds such a bundle; the `?_` leave three
      holes to prove as separate goals (the `·` bullets below tackle them).
    * Holes 1 and 2 are about `projRole`'s global and org blocks, which are empty.
      `intro _ _ h` assumes a membership `h`, but that membership reduces to
      `False`, and `False.elim h` proves any goal from a false hypothesis.
    * Hole 3: `intro _ _ h` gives `h : e = endptX ∧ o = Op.create`. We pick the
      right disjunct with `Or.inr` and supply witness project "A": `⟨"A", ...⟩`.
      The remaining `⟨rfl, rfl, h.1, h.2⟩` proves the four equalities that
      `callerAcl.proj "O" "A" e o` demands. `rfl` ("reflexivity") proves an
      equality whose two sides are literally the same ("O" = "O", "A" = "A");
      `h.1` and `h.2` are the two halves of the hypothesis `h`.
-/
theorem caller_may_grant : allowRole callerAcl projRole "O" := by
  refine ⟨?_, ?_, ?_⟩
  · intro _ _ h; exact False.elim h
  · intro _ _ h; exact False.elim h
  · intro _ _ h
    exact Or.inr ⟨"A", rfl, rfl, h.1, h.2⟩

/-
  Second fact: despite being allowed to grant, the caller CANNOT exercise that
  permission in project "B". We prove the negation `¬ grantsProj ... "B" ...`.
  In Lean `¬ P` is *defined as* `P → False`, so we `intro h` (assume the
  permission somehow holds in "B") and derive a contradiction.

  `match h with` case-splits `h` along the shape of `grantsProj`, which is
  `(global ∨ org) ∨ project`:
    * `Or.inl (Or.inl hg)` — a supposed global grant; but `callerAcl.global` is
      empty, so `hg` is really a proof of `False`, discharged by `False.elim hg`.
    * `Or.inl (Or.inr ho)` — a supposed org grant; also empty.
    * `Or.inr hp` — a supposed project grant in "B". Then `hp.2.1` is a proof
      that `"B" = "A"`, which is false. `by decide` computes `"B" ≠ "A"` (using
      the `DecidableEq` derived back in Basic.lean), and `absurd` turns a proof
      together with its negation into a proof of anything.
-/
theorem caller_cannot_act_in_B :
    ¬ grantsProj callerAcl "O" "B" endptX Op.create := by
  intro h
  match h with
  | Or.inl (Or.inl hg) => exact False.elim hg
  | Or.inl (Or.inr ho) => exact False.elim ho
  | Or.inr hp => exact absurd hp.2.1 (by decide)

/-
  Putting the two facts together: there EXISTS a situation — an ACL, a role, an
  organization, a target project, an endpoint, and an operation — where the grant
  is allowed, the role really contains the project permission, yet the caller
  cannot perform it in the target project.

  `∃ ... , ...` is existential quantification. We prove it by supplying concrete
  witnesses in an anonymous constructor, followed by the three required facts.
  `⟨rfl, rfl⟩` proves the middle fact `projRole.proj endptX Op.create` (the two
  equalities it unfolds to), and the two named theorems above supply the outer
  facts.

  Reading: project-scope granting is NOT a local subset property. The genuine
  guarantee is conditional on the external linking/group-write invariants
  documented at handler.go:291-343 — encoding those as explicit hypotheses and
  proving the conditional theorem is the natural next step.
-/
theorem project_grant_not_locally_subset :
    ∃ (a : Acl) (r : Role) (org p' e : String) (o : Op),
      allowRole a r org ∧ r.proj e o ∧ ¬ grantsProj a org p' e o :=
  ⟨callerAcl, projRole, "O", "B", endptX, Op.create,
   caller_may_grant, ⟨rfl, rfl⟩, caller_cannot_act_in_B⟩

end UniRbac
