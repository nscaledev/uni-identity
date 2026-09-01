/-
  UniRbac/Groups.lean — group state, and who a group confers its roles on.

  Everything modelled so far has been about a caller's *effective* authority: an
  `Acl` is where authority has already landed. This file introduces the state it
  is computed FROM — the stored group record — and the question the group-update
  guards turn on: does this group already confer its roles on this principal?

  That question has two answers in the Go code, computed by two different
  functions in two different packages, and they are required to agree:

    * `pkg/rbac` decides it when it builds an ACL (`groupSubjectFilter`), and
    * `pkg/handler` decides it when a write asks to add a member
      (`GroupSpec.HasMemberByID`).

  Two review-caught bugs in the ID-368 stack were disagreements between them.
  Pinning their relationship is what this file exists for; the predicates arrive
  in the next commit, the state they range over here.
-/

namespace UniRbac

/-
  A stored subject record, mirroring `unikornv1.GroupSubject`.

  All three fields matter to the Go code, but for *different* questions, which is
  the subtlety this whole file is about:

    * `id`     — who the principal is at its issuer;
    * `issuer` — which identity provider authenticated it. Records written before
      issuers were captured carry an empty string here, and nothing upgrades
      them;
    * `email`  — display data only. Different writers populate it from different
      sources, so two records for the same principal can disagree on it.

  `deriving DecidableEq` gives us an algorithm for deciding whether two `Subject`s
  are equal, which is what lets the `decide` tactic settle concrete (in)equalities
  when we build counterexample witnesses later. `Repr` allows printing.
-/
structure Subject where
  id     : String
  issuer : String
  email  : String
deriving DecidableEq, Repr

/-
  The stored group record, mirroring `unikornv1.GroupSpec`.

  Note there are *three* membership representations and one authority payload:

    * `userIDs`           — deprecated; names `OrganizationUser` resources;
    * `subjects`          — the current representation;
    * `serviceAccountIDs` — service accounts, which have no subject;
    * `roleIDs`           — the roles every member of this group receives.

  A principal may be recorded in `userIDs`, or in `subjects`, or in both. RBAC
  resolves membership through either, which is why "add the missing half of a
  membership" must not read as granting anything.

  ## Why `List` here, when `Perm` is a predicate

  `Basic.lean` deliberately models a permission set as a *function* rather than a
  list, because nothing in `pkg/rbac` cares about the order or multiplicity of
  permissions — only membership — and a predicate keeps us free of Mathlib.

  The same trick would be actively wrong here. The Go code's behaviour depends on
  list structure in exactly the places its bugs live:

    * the empty string is a *sentinel*: `HasMemberByID` refuses to let a junk
      empty entry stand in for a principal, and one of the three call sites is
      missing that guard;
    * `groupSubjectFilter` branches on `len(UserIDs) > 0` — whether the list is
      empty is load-bearing, not just what is in it;
    * `principalUserIDs` filters empties out on the write path.

  Encoding membership as a predicate would silently erase all three. So the
  fields stay lists. What we keep from `Perm`'s example is the *discipline*: the
  propositions below are written with `∈` and logical connectives only, never
  with `Bool`-valued list functions, so proofs stay in Lean core.
-/
structure GroupSpec where
  userIDs           : List String
  subjects          : List Subject
  serviceAccountIDs : List String
  roleIDs           : List String
deriving Repr

/-
  A principal, as the membership question sees it.

  Unlike the enums met so far (`Op` has four bare values), these constructors
  carry *arguments* — data attached to the case. `Principal.user` takes two
  strings and `Principal.serviceAccount` takes one, so `.user "s1" "ou1"` and
  `.serviceAccount "sa1"` are both `Principal`s.

  A user is named by two identifiers at once, and this is not redundancy:

    * `subjectID` is what the principal presents when it authenticates, and what
      is matched against `GroupSpec.subjects`;
    * `orgUserID` is the `OrganizationUser` resource name matched against
      `GroupSpec.userIDs`. RBAC does not receive it — it re-derives it from the
      subject via `resolveOrganizationUserName`, which can fail. We model that
      failure as the empty string, because both sides treat "no organization user
      name" and "the empty string" identically.

  Service accounts have no subject and no organization user; they are matched by
  ID alone.
-/
inductive Principal where
  | user (subjectID orgUserID : String)
  | serviceAccount (id : String)

/-
  ## Membership, as RBAC computes it

  This is the ground truth: the definition of "this group confers its roles on
  this principal" that the whole authorization system actually runs on. It
  mirrors `groupSubjectFilter` (`pkg/rbac/rbac.go:271`) and
  `groupServiceAccountFilter` (`:304`).

  ### Two pieces of Lean notation

  `x ∈ l` is list membership. `∃ s ∈ g.subjects, s.id = sub` is *bounded*
  existential quantification — sugar for "there is some `s` such that `s` is in
  `g.subjects` and `s.id = sub`", i.e. a plain `∃` paired with a membership
  hypothesis. That pairing is exactly how the proofs consume it: given such a
  proof you get both the element and the evidence it came from the list.

  ### ⚠ The Go functions are INVERTED

  `groupSubjectFilter` returns a *deletion* predicate: `getGroups` calls
  `slices.DeleteFunc` with it, so returning `false` means "keep this group",
  which means the principal IS a member. Reading the Go and transcribing its
  `true`/`false` at face value gets this exactly backwards. The definition below
  is stated positively — `confersOn` is true when the principal is a member — so
  every `return false` in the Go corresponds to a satisfied disjunct here.

  ### The two arms, and one deliberate redundancy

  For a user, membership holds if either:

    * some stored subject has a matching ID. **The issuer is not consulted** —
      see the comment at `rbac.go:274-279`. Note there is no guard against an
      empty ID on this arm: a stored record with `id = ""` really does match a
      principal presenting `""`. That is the fact the incompleteness result below
      turns on.
    * or the deprecated `userIDs` fallback applies. Three conjuncts, mirroring
      the Go's nesting: the list is non-empty (`len(group.Spec.UserIDs) > 0`),
      the subject resolved to an organization-user name, and that name is in the
      list.

  `orgUser ≠ ""` is how we model "`resolveOrganizationUserName` returned no
  error". The Go skips the whole branch when resolution fails, so a failed
  resolution must not match even if the stored list happens to contain a junk
  empty entry — hence the conjunct.

  `g.userIDs ≠ []` is *logically redundant*: `orgUser ∈ g.userIDs` already
  implies the list is non-empty. It is kept because the Go has it as a separate
  branch condition, and because that redundancy is precisely what makes the
  soundness proof below go through without a side condition. Deleting it would
  not change the meaning; it would only hide why the theorem works.

  Service accounts are matched by plain ID membership, with no empty-ID guard —
  faithful to `groupServiceAccountFilter`, and a fact that matters later.
-/
def GroupSpec.confersOn (g : GroupSpec) : Principal → Prop
  | .user sub orgUser =>
      (∃ s ∈ g.subjects, s.id = sub)
      ∨ (g.userIDs ≠ [] ∧ orgUser ≠ "" ∧ orgUser ∈ g.userIDs)
  | .serviceAccount id => id ∈ g.serviceAccountIDs

/-
  ## Membership, as the write gates compute it

  `GroupSpec.HasMemberByID` (`pkg/apis/unikorn/v1alpha1/group_helpers.go:48`).
  This is the *other* answer to the same question — the one the group-update
  guards use to decide whether a write is adding a member or merely re-stating
  one. All three write paths call it.

  It is deliberately not the same expression as `confersOn`:

    * it takes the organization-user ID as an *argument*, because the handler has
      already resolved it, rather than re-deriving it;
    * both arms guard against the empty string. The doc comment at
      `group_helpers.go:45-47` gives the reason: membership lists are not
      validated against real records, so a junk empty entry must not stand in for
      a principal that has no record yet;
    * it does not test `userIDs ≠ []`, having no need of the Go's branch
      structure.

  Whether these two definitions agree is the question the next two theorems
  answer. They do not agree exactly — and the direction in which they differ is
  what determines whether that is a security problem or an inconvenience.
-/
def GroupSpec.hasMemberByID (g : GroupSpec) (orgUserID subjectID : String) : Prop :=
  (orgUserID ≠ "" ∧ orgUserID ∈ g.userIDs)
  ∨ (subjectID ≠ "" ∧ ∃ s ∈ g.subjects, s.id = subjectID)

/-
  ## The gate's shortcut is sound

  All three write paths short-circuit on `hasMemberByID`: if it holds, the write
  is not an addition and the grant check is skipped entirely. Whether that skip
  is safe is *exactly* this statement — whenever the gate declines to check, the
  group already conferred its roles on that principal, so the write hands over
  nothing new.

  There is no side condition. In particular the empty-string guards, which the
  two definitions treat differently, do not need one.

  ### Why this direction, and not the converse

  Soundness is what safety needs, and the reason is the *shape* of the two
  failure modes:

    * if the gate said "already a member" when RBAC disagreed, a write would skip
      the grant check and confer authority for free. That is an escalation, and
      it is what this theorem rules out.
    * if the gate said "not a member" when RBAC agreed it was, the write is
      merely checked when it need not have been, and a caller sees a refusal it
      did not deserve. Annoying, not dangerous.

  The converse therefore does not have to hold — and it does not; see below.

  ### Proof walkthrough

  `→` is implication, so `intro h` assumes the gate holds and leaves us to derive
  membership. `match h with` splits the two disjuncts of `hasMemberByID`, and the
  patterns `⟨hne, hmem⟩` destructure each `∧` into its two halves at the same
  time.

  * First case — the caller is in `userIDs`. We must land in `confersOn`'s
    *second* disjunct, so `Or.inr`, and it wants three facts. `refine` supplies
    the two we already have (`hne`, `hmem`) and leaves `?_` as a hole for the
    third: `g.userIDs ≠ []`.

    That is where the redundant conjunct is paid for. `≠` unfolds to
    "equality implies `False`", so `intro hnil` assumes `g.userIDs = []` and
    `rw [hnil] at hmem` rewrites our membership proof into a claim that
    `orgUser ∈ []`. No such proof can exist: `List.Mem` has exactly two
    constructors and both require a non-empty list. `nomatch hmem` says precisely
    that — "there is no case to consider" — and closes the goal.

  * Second case — a stored subject matches. We must land in `confersOn`'s *first*
    disjunct, and the existential we hold is already literally it, so `Or.inl hex`
    finishes. Note what happens to the `subjectID ≠ ""` guard: it is discarded
    (the `_` in the pattern). The gate *demands* more than RBAC does here, and a
    stronger hypothesis implies a weaker conclusion, so the extra guard can only
    ever narrow the gate — never widen it past RBAC.
-/
theorem hasMemberByID_sound (g : GroupSpec) (orgUser sub : String) :
    g.hasMemberByID orgUser sub → g.confersOn (.user sub orgUser) := by
  intro h
  match h with
  | Or.inl ⟨hne, hmem⟩ =>
      refine Or.inr ⟨?_, hne, hmem⟩
      intro hnil
      rw [hnil] at hmem
      nomatch hmem
  | Or.inr ⟨_, hex⟩ => exact Or.inl hex

/-
  ## ...and it is not complete

  The converse of `hasMemberByID_sound` fails. We show it the way
  `ProjectCaveat.lean` shows its result: build one concrete world, prove the two
  halves separately, then package them into the existential. `private def` keeps
  the witness out of the model's public surface — it is scaffolding.

  The world is a group holding a single junk subject record whose ID is the empty
  string, and the principal we probe with presents the empty string too.
-/
private def junkSubjectGroup : GroupSpec where
  userIDs           := []
  subjects          := [⟨"", "", ""⟩]
  serviceAccountIDs := []
  roleIDs           := []

/-
  RBAC says this principal IS a member. Its subject arm compares `s.ID == subject`
  with no guard whatsoever, and `"" = ""`.

  The proof is a term, not a tactic block. `Or.inl` picks the first disjunct;
  `∃ s ∈ l, p s` is sugar for `∃ s, s ∈ l ∧ p s`, so the anonymous constructor
  wants three things: the element, a proof it is in the list, and a proof of the
  property. `List.Mem.head []` is the constructor for "the element at the head of
  a list is in it", and `rfl` proves `"" = ""`.
-/
private theorem junkGroup_confers : junkSubjectGroup.confersOn (.user "" "") :=
  Or.inl ⟨⟨"", "", ""⟩, List.Mem.head [], rfl⟩

/-
  The gate says it is NOT a member. Both of its disjuncts open with a `≠ ""`
  guard, and our probe is `""` on both identifiers, so both are unreachable.

  `absurd rfl hne` is the idiom: `hne` is a proof that `"" ≠ ""`, `rfl` proves
  `"" = ""`, and `absurd` turns a fact together with its negation into a proof of
  anything.
-/
private theorem junkGroup_gate_refuses : ¬ junkSubjectGroup.hasMemberByID "" "" := by
  intro h
  match h with
  | Or.inl ⟨hne, _⟩ => exact absurd rfl hne
  | Or.inr ⟨hne, _⟩ => exact absurd rfl hne

/-
  So the two definitions genuinely differ.

  Read it in the safe direction: the gate is *stricter* than RBAC, refusing to
  let a junk empty entry stand in for a principal that has no record yet — which
  is exactly what `group_helpers.go:45-47` says it is for. The cost is a write
  refused where the roles were already conferred; the benefit is that an unwritten
  principal cannot inherit an accidental membership. By `hasMemberByID_sound` the
  difference can only ever lie in this direction.

  It follows that "make the gate agree with RBAC exactly" would be the wrong
  repair. If these ever need to converge, the empty-ID guard belongs on RBAC's
  side, not off the gate's.
-/
theorem hasMemberByID_not_complete :
    ∃ (g : GroupSpec) (orgUser sub : String),
      g.confersOn (.user sub orgUser) ∧ ¬ g.hasMemberByID orgUser sub :=
  ⟨junkSubjectGroup, "", "", junkGroup_confers, junkGroup_gate_refuses⟩

end UniRbac
