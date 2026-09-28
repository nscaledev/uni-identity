/-
  UniRbac/Accumulate.lean — the construction side (accumulate*), modelled as set
  union, and its monotonicity.

  Everything so far reasoned about a finished ACL. This file models one step of
  how ACLs are *built* and proves the property enforcement quietly relies on:
  building never takes a permission away.
-/

import UniRbac.Enforce

namespace UniRbac

/-
  ACL construction in the Go code builds an organization's permission set as the
  UNION over the roles of the groups the subject belongs to
  (`addScopesToEndpointList` merges scopes by union). `accumulateOrg` models one
  such merge step: take ACL `a` and fold an extra permission set `add` into
  organization `org`.

  The `org` field uses `if ... then ... else ...`. For the targeted organization
  (`o = org`) we union in `add` with `... ∨ add e op`; every other organization
  is returned unchanged. `global` and `proj` are copied verbatim.
-/
def accumulateOrg (a : Acl) (org : String) (add : Perm) : Acl where
  global := a.global
  org    := fun o e op => if o = org then (a.org o e op ∨ add e op) else a.org o e op
  proj   := a.proj

/-
  Monotonicity: accumulation only ever ADDS authority. If `a` already grants
  (e,op) at org scope for organization `o`, then so does the accumulated ACL.
  Enforcement depends on this — merging in another group's role must never revoke
  a permission a different group already conferred.

  Proof:
    * `intro h`, then `match h` on `grantsOrg a o e op`, which is `global ∨ org`.
    * Left (`Or.inl hg`, a global grant): `accumulateOrg` copies `global`
      untouched, so the very same proof still works: `Or.inl hg`.
    * Right (`Or.inr ho`, an org grant): we must show the accumulated org field
      holds. `refine Or.inr ?_` targets it, and `show ...` restates that goal as
      the `if` expression the field unfolds to. `by_cases hEq : o = org` then
      splits on whether this is the organization we accumulated into:
        - if yes (`hEq : o = org`), `rw [if_pos hEq]` rewrites the `if` to its
          then-branch `a.org o e op ∨ add e op`; `Or.inl ho` supplies the old
          grant on the left of that union;
        - if no, `rw [if_neg hEq]` rewrites to the else-branch `a.org o e op`,
          which is exactly `ho`.
    (`if_pos` / `if_neg` are the core lemmas that reduce an `if` once you know the
    condition is true / false; `rw` rewrites the goal using an equation.)
-/
theorem accumulate_monotone (a : Acl) (org : String) (add : Perm) (o e op) :
    grantsOrg a o e op → grantsOrg (accumulateOrg a org add) o e op := by
  intro h
  match h with
  | Or.inl hg => exact Or.inl hg
  | Or.inr ho =>
      refine Or.inr ?_
      show (if o = org then (a.org o e op ∨ add e op) else a.org o e op)
      by_cases hEq : o = org
      · rw [if_pos hEq]; exact Or.inl ho
      · rw [if_neg hEq]; exact ho

end UniRbac
