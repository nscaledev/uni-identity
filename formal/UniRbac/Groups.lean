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

end UniRbac
