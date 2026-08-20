/-
  UniRbac/Intersect.lean — impersonation intersection soundness (intersectACL).

  This is the confused-deputy guarantee: when a system service acts on behalf of
  an impersonated user, it must not be able to exercise — or hand onward — any
  permission that either side lacks.
-/

import UniRbac.Enforce

namespace UniRbac

/-
  `intersectACL`. When a system service impersonates a user, the effective ACL
  keeps a permission only if BOTH the user and the service have it. A subtlety
  faithfully reproduced here: the Go code filters *every* user scope against the
  service's GLOBAL set (`serviceACL.Global`), because system accounts only ever
  accumulate permissions at global scope.

  So `sg` below is that single service-global allow-set, and `interG u sg` ANDs
  it into each scope of the user's ACL `u`. `∧` is logical "and". Notice the
  service's global set gates the user's org- and project-scope grants too — that
  is why a service with global read implicitly permits a user's project read, but
  not the other way around.
-/
def interG (u : Acl) (sg : Perm) : Acl where
  global := fun e o => u.global e o ∧ sg e o
  org    := fun org e o => u.org org e o ∧ sg e o
  proj   := fun org p e o => u.proj org p e o ∧ sg e o

/-
  Soundness: anything the intersected ACL grants (taking project scope, the
  widest case, since it subsumes global and org) is BOTH granted by the user ACL
  AND present in the service's global allow-set. Neither side can gain, nor pass
  on, a permission it lacks.

  The proof is a term-mode function `fun h => match h with ...`. Here `h` proves
  `grantsProj (interG u sg) ...`, whose shape is `(global ∨ org) ∨ project`; and
  because `interG` ANDed `sg` into every scope, each branch's proof is itself an
  `∧` — the user's grant paired with `sg`. `hg.1` / `hg.2` split that pair. We
  rebuild `grantsProj u ...` on the left (re-wrapping with `Or.inl`/`Or.inr` to
  land in the same scope slot) and hand back the `sg` proof on the right. The
  outer `⟨_, _⟩` is the pair proving the goal `grantsProj u ... ∧ sg e o`.
-/
theorem inter_sound (u : Acl) (sg : Perm) (org proj e o) :
    grantsProj (interG u sg) org proj e o →
      grantsProj u org proj e o ∧ sg e o :=
  fun h =>
    match h with
    | Or.inl (Or.inl hg) => ⟨Or.inl (Or.inl hg.1), hg.2⟩
    | Or.inl (Or.inr ho) => ⟨Or.inl (Or.inr ho.1), ho.2⟩
    | Or.inr hp => ⟨Or.inr hp.1, hp.2⟩

/-- A corollary: intersection only ever REMOVES authority, never invents it. We
    reuse `inter_sound` and keep just its left half with `.1`. (Applying a proved
    theorem to arguments is how Lean lets you build proofs from earlier proofs.) -/
theorem inter_no_escalation (u : Acl) (sg : Perm) (org proj e o) :
    grantsProj (interG u sg) org proj e o → grantsProj u org proj e o :=
  fun h => (inter_sound u sg org proj e o h).1

end UniRbac
