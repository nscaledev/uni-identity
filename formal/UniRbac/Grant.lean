/-
  UniRbac/Grant.lean — roles, grantability (AllowRole), and grant safety at
  global and organization scope.

  The security question here is privilege escalation: when may a caller hand out
  a role, and does doing so ever give away more than the caller already holds?
-/

import UniRbac.Enforce

namespace UniRbac

/-
  A role, mirroring `unikornv1.RoleScopes`: three permission sets, one per scope
  block. The real built-in roles (`administrator`, `user`, `reader`, ...) are
  values of exactly this shape.
-/
structure Role where
  global : Perm
  org    : Perm
  proj   : Perm

/-
  `allowRole` models `AllowRole` for a fixed organization `org`: may a caller
  whose effective authority is `a` grant the role `r`?

  The answer is a conjunction (`∧`, "and") of three requirements, one per scope
  block of the role. Each requirement is a *universally quantified* implication.
  `∀ e o, P e o → Q e o` reads "for every endpoint `e` and operation `o`, if the
  role contains (e,o) in this block, then the caller can satisfy it":

    * global block  — must be held at global scope (`grantsGlobal`);
    * org block     — held at global OR organization scope (`grantsOrg`);
    * project block — held at global/org scope, OR in *some* project the caller
      can access. That last option is the `∃ p, ...` ("there exists a project
      `p`"). It is the laxer `allowGrantProjectScope` rule, and it is the exact
      source of the caveat proved next door in ProjectCaveat.lean.
-/
def allowRole (a : Acl) (r : Role) (org : String) : Prop :=
  (∀ e o, r.global e o → grantsGlobal a e o) ∧
  (∀ e o, r.org e o    → grantsOrg a org e o) ∧
  (∀ e o, r.proj e o   → grantsOrg a org e o ∨ ∃ p, a.proj org p e o)

/-
  Grant safety at global scope. Statement: if the caller may grant `r` (that is
  the hypothesis `h : allowRole a r org`), then every permission in the role's
  global block is one the caller already holds globally — so granting cannot
  leak global authority the caller lacks.

  The proof is a single term written in *term mode* (no `by`). `allowRole` is a
  threefold `∧`, and `h.1` projects out its first component — which is *exactly*
  this statement. The theorem therefore holds essentially by definition, and
  that is the point: it pins the README's "a caller may only grant a role if they
  already hold every permission it contains", here for global scope.
-/
theorem grant_global_safe (a : Acl) (r : Role) (org : String)
    (h : allowRole a r org) :
    ∀ e o, r.global e o → grantsGlobal a e o :=
  h.1

/-- The same guarantee one scope down: org-block permissions are held at
    organization scope (or broader). `h.2.1` means "the second component of the
    conjunction, then its first" — the organization requirement. -/
theorem grant_org_safe (a : Acl) (r : Role) (org : String)
    (h : allowRole a r org) :
    ∀ e o, r.org e o → grantsOrg a org e o :=
  h.2.1

end UniRbac
