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

end UniRbac
