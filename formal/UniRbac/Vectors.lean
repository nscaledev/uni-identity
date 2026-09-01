/-
  UniRbac/Vectors.lean — the conformance-vector generator.

  This turns the proven model into concrete test data. It defines:

    * a *data* representation of ACLs and roles (lists, so they can be printed
      and serialized to JSON), mirroring the `buildACL` / `buildRole` helpers on
      the Go side (pkg/rbac/grant_model_test.go);
    * `evalAllowRole`, the model's decision procedure, built on the certified
      `bGrants*` combinators from Exec.lean, so the decision it computes is the
      one the proofs are about;
    * a set of hand-written base cases as *named* scenarios, each carrying a
      human-asserted outcome the model must reproduce;
    * a generated matrix of additional scenarios the model decides on its own;
    * a small JSON serializer (hand-rolled to avoid any dependency).

  `Main.lean` calls into here to emit `pkg/rbac/testdata/model_vectors.json`. The
  model is the oracle: every `expected` field is computed here, never hand-typed
  on the Go side.
-/

import UniRbac.Exec

namespace UniRbac

/-! ## Data representation

These types mirror the JSON schema one-for-one, and mirror the `buildACL` /
`buildRole` builders on the Go side. A permission set is a list of endpoints,
each with the operations granted on it. -/

/-- One endpoint and the operations granted on it, e.g. `svc:resource` → [read]. -/
structure EndpointOps where
  name       : String
  operations : List Op
deriving Repr

/-- A permission set, as serializable data. -/
abbrev PermData := List EndpointOps

/-- One project's endpoints, keyed by project ID. -/
structure ProjectData where
  id        : String
  endpoints : PermData
deriving Repr

/-- An ACL as data. Like `modelACL`, this models a single organization with
    optional org-scope endpoints and a list of projects. -/
structure AclData where
  global         : PermData
  organizationId : String
  organization   : PermData
  projects       : List ProjectData
deriving Repr

/-- A role as data, mirroring `modelRole`: one permission set per scope block. -/
structure RoleData where
  global       : PermData
  organization : PermData
  project      : PermData
deriving Repr

/-- The possible outcomes of a scenario. `allow`/`deny` answer an authorization
    check; `member`/`notMember` answer a membership question, which is not an
    authorization decision and should not be dressed up as one. -/
inductive Decision where
  | allow
  | deny
  | member
  | notMember
deriving DecidableEq, Repr, BEq

/-- The kind of check a scenario exercises. The tag is what the Go harness
    switches on to pick which real function to call.

    `hasMemberByID` carries the stored group and the two identifiers the probe
    presents. It needs no ACL — membership does not depend on the caller — but
    the `Scenario` record supplies one anyway; see the note on
    `handwrittenMembership` below. -/
inductive Query where
  | allowRole (role : RoleData)
  | hasMemberByID (group : GroupSpec) (orgUserID subjectID : String)
deriving Repr

/-- A single conformance scenario. `humanExpect` is set only for hand-written
    base cases — a human-asserted outcome the generator checks the model
    agrees with. -/
structure Scenario where
  name        : String
  source      : String
  acl         : AclData
  query       : Query
  humanExpect : Option Decision

/-! ## The model's decision procedure

`evalAllowRole` is a faithful transcription of `allowRole` (Grant.lean) built on
the certified `bGrants*` combinators (Exec.lean). Reading a data permission set
as a `BPerm` is just membership in the list. -/

/-- Decide membership of `(e, o)` in a data permission set. -/
def evalPerm (p : PermData) (e : String) (o : Op) : Bool :=
  p.any fun ep => ep.name == e && ep.operations.contains o

/-- View an `AclData` as a runnable `BAcl` (from Exec.lean). Absent
    organizations/projects map to the empty permission set. -/
def AclData.toBAcl (a : AclData) : BAcl where
  global := evalPerm a.global
  org := fun o => if o == a.organizationId then evalPerm a.organization else fun _ _ => false
  proj := fun o p =>
    if o == a.organizationId then
      match a.projects.find? (fun pr => pr.id == p) with
      | some pr => evalPerm pr.endpoints
      | none    => fun _ _ => false
    else
      fun _ _ => false

/-- "Every (endpoint, operation) in `p` satisfies `f`." Models the `∀ e o, …`
    checks inside `allowRole`. -/
def permForall (p : PermData) (f : String → Op → Bool) : Bool :=
  p.all fun ep => ep.operations.all fun o => f ep.name o

/-- "Some accessible project grants `(e, o)`." Models the `∃ p, a.proj org p e o`
    disjunct — `allowGrantProjectScope`'s "any accessible project" rule. -/
def existsProject (a : AclData) (e : String) (o : Op) : Bool :=
  a.projects.any fun pr => evalPerm pr.endpoints e o

/-- The model's `AllowRole` decision, scoped to the ACL's own organization. A
    direct Bool transcription of `allowRole` in Grant.lean. -/
def evalAllowRole (a : AclData) (r : RoleData) : Bool :=
  let ba := a.toBAcl
  let org := a.organizationId
  permForall r.global (fun e o => bGrantsGlobal ba e o)
    && permForall r.organization (fun e o => bGrantsOrg ba org e o)
    && permForall r.project (fun e o => bGrantsOrg ba org e o || existsProject a e o)

/-- The model's decision for a whole scenario.

    The membership branch calls `bHasMemberByID` directly, which — unlike
    `evalAllowRole` — *is* certified equal to its `Prop` counterpart by
    `bHasMemberByID_iff`. So a membership vector's expected outcome is backed by
    a proof all the way down, not by an unproved transcription. -/
def evalDecision (s : Scenario) : Decision :=
  match s.query with
  | .allowRole r => if evalAllowRole s.acl r then .allow else .deny
  | .hasMemberByID g ou sub => if bHasMemberByID g ou sub then .member else .notMember

/-! ## Hand-written base cases

Named cases that pin specific scope-flow outcomes. Each has a descriptive name
and a human-asserted outcome (`humanExpect`); the generator checks the model
reproduces it. -/

/-- Endpoint names used by the base cases. -/
def orgEndpoint : String := "model:organization"
def projEndpoint : String := "model:project"
def globalEndpoint : String := "model:global"

/-- Organization and project IDs for the base cases. They must be valid UUIDs so
    the Go harness can parse them. -/
def organizationID : String := "f47ac10b-58cc-4372-a567-0e02b2c3d479"
def projectID : String := "550e8400-e29b-41d4-a716-446655440000"

/-- Build a one-endpoint permission set. -/
def perm1 (name : String) (ops : List Op) : PermData := [⟨name, ops⟩]

/-- Assemble an `AclData` for the single test organization. -/
def mkAcl (global org : PermData) (projects : List ProjectData) : AclData :=
  { global := global, organizationId := organizationID, organization := org, projects := projects }

/-- A single-project list holding one endpoint. -/
def proj1 (name : String) (ops : List Op) : List ProjectData := [⟨projectID, perm1 name ops⟩]

def handwritten : List Scenario :=
  [ { name := "organization role does not require project access"
      source := "handwritten"
      acl := mkAcl [] (perm1 orgEndpoint [.read]) []
      query := .allowRole ⟨[], perm1 orgEndpoint [.read], []⟩
      humanExpect := some .allow }
  , { name := "project authority does not satisfy organization role"
      source := "handwritten"
      acl := mkAcl [] [] (proj1 orgEndpoint [.read])
      query := .allowRole ⟨[], perm1 orgEndpoint [.read], []⟩
      humanExpect := some .deny }
  , { name := "project role is grantable from one accessible project"
      source := "handwritten"
      acl := mkAcl [] [] (proj1 projEndpoint [.create])
      query := .allowRole ⟨[], [], perm1 projEndpoint [.create]⟩
      humanExpect := some .allow }
  , { name := "project role is grantable from organization authority"
      source := "handwritten"
      acl := mkAcl [] (perm1 projEndpoint [.create]) []
      query := .allowRole ⟨[], [], perm1 projEndpoint [.create]⟩
      humanExpect := some .allow }
  , { name := "project role is not grantable without project or broader authority"
      source := "handwritten"
      acl := mkAcl [] (perm1 orgEndpoint [.read]) []
      query := .allowRole ⟨[], [], perm1 projEndpoint [.create]⟩
      humanExpect := some .deny }
  , { name := "mixed role needs both organization and project grantability"
      source := "handwritten"
      acl := mkAcl [] (perm1 orgEndpoint [.read]) []
      query := .allowRole ⟨[], perm1 orgEndpoint [.read], perm1 projEndpoint [.create]⟩
      humanExpect := some .deny }
  , { name := "global role is not grantable from organization authority"
      source := "handwritten"
      acl := mkAcl [] (perm1 globalEndpoint [.read]) []
      query := .allowRole ⟨perm1 globalEndpoint [.read], [], []⟩
      humanExpect := some .deny }
  , { name := "global role is grantable from global authority"
      source := "handwritten"
      acl := mkAcl (perm1 globalEndpoint [.read]) [] []
      query := .allowRole ⟨perm1 globalEndpoint [.read], [], []⟩
      humanExpect := some .allow }
  ]

/-! ## Hand-written membership cases

These pin `GroupSpec.HasMemberByID` — the predicate all three write paths use to
decide whether a write adds a member or merely re-states one. Every case carries
a human-asserted outcome, so the generator refuses to emit if the model's answer
ever moves.

Membership does not depend on the caller, so these scenarios have no meaningful
ACL. They carry an empty one rather than making `Scenario.acl` optional: that
would change the JSON shape of every existing vector for no gain, and the Go
harness simply does not read the field for this query kind. -/

/-- A stored subject record. -/
def subj (id issuer email : String) : Subject := ⟨id, issuer, email⟩

/-- A group carrying only membership entries — no roles, which is all these cases
    need. -/
def mkGroup (userIDs : List String) (subjects : List Subject) : GroupSpec :=
  { userIDs := userIDs, subjects := subjects, serviceAccountIDs := [], roleIDs := [] }

/-- The issuer this deployment would write, and one that differs. -/
def thisIssuer : String := "https://identity.example.com"
def otherIssuer : String := "https://other.example.com"

def handwrittenMembership : List Scenario :=
  [ -- The ordinary case: a record written by this deployment.
    { name := "stored subject with matching ID is a member"
      source := "handwritten"
      acl := mkAcl [] [] []
      query := .hasMemberByID (mkGroup [] [subj "s1" thisIssuer "a@example.com"]) "" "s1"
      humanExpect := some .member }
    -- The ID-368 regression case.  A record written before subject issuers were
    -- captured carries an empty issuer and still confers the group's roles, so
    -- re-stating that membership must not read as an addition.  An
    -- issuer-qualified predicate answers notMember here and over-refuses.
  , { name := "legacy empty-issuer subject is a member"
      source := "handwritten"
      acl := mkAcl [] [] []
      query := .hasMemberByID (mkGroup [] [subj "s1" "" ""]) "" "s1"
      humanExpect := some .member }
    -- The same point from the other side: a record at a *different* issuer also
    -- matches, because the issuer takes no part at all.
  , { name := "subject at another issuer is still a member"
      source := "handwritten"
      acl := mkAcl [] [] []
      query := .hasMemberByID (mkGroup [] [subj "s1" otherIssuer "a@example.com"]) "" "s1"
      humanExpect := some .member }
    -- Email is display data and differs between writers; it must not matter.
  , { name := "stored email does not affect matching"
      source := "handwritten"
      acl := mkAcl [] [] []
      query := .hasMemberByID (mkGroup [] [subj "s1" thisIssuer "stale@example.com"]) "" "s1"
      humanExpect := some .member }
    -- A different principal is not a member.
  , { name := "different subject ID is not a member"
      source := "handwritten"
      acl := mkAcl [] [] []
      query := .hasMemberByID (mkGroup [] [subj "s2" thisIssuer "b@example.com"]) "" "s1"
      humanExpect := some .notMember }
    -- The deprecated representation confers membership on its own.
  , { name := "organization user ID alone is a member"
      source := "handwritten"
      acl := mkAcl [] [] []
      query := .hasMemberByID (mkGroup ["ou1"] []) "ou1" "s1"
      humanExpect := some .member }
    -- Either representation suffices, so completing the missing half grants
    -- nothing.
  , { name := "subject match suffices with an empty userIDs list"
      source := "handwritten"
      acl := mkAcl [] [] []
      query := .hasMemberByID (mkGroup [] [subj "s1" thisIssuer ""]) "ou1" "s1"
      humanExpect := some .member }
    -- The empty-string sentinel, both arms.  A junk empty entry must not stand
    -- in for a principal that has no record yet.  This is the case
    -- hasMemberByID_not_complete is built on: RBAC's own subject matching has no
    -- such guard and would answer member here.
  , { name := "empty subject ID matches no stored record"
      source := "handwritten"
      acl := mkAcl [] [] []
      query := .hasMemberByID (mkGroup [] [subj "" "" ""]) "" ""
      humanExpect := some .notMember }
  , { name := "empty organization user ID matches no stored entry"
      source := "handwritten"
      acl := mkAcl [] [] []
      query := .hasMemberByID (mkGroup [""] []) "" ""
      humanExpect := some .notMember }
    -- Nothing stored at all.
  , { name := "empty group has no members"
      source := "handwritten"
      acl := mkAcl [] [] []
      query := .hasMemberByID (mkGroup [] []) "ou1" "s1"
      humanExpect := some .notMember }
  ]

/-! ## Generated scenarios

An exhaustive small matrix the model decides on its own (no human assertion). We
vary where the role's single required permission sits, and where the ACL's single
grant sits (or absent), across the three scopes and two operations. This
systematically exercises the downward scope flow and operation matching that the
hand-written base cases only sample. -/

/-- A scope position for the generated matrix. -/
inductive GScope where
  | glob
  | org
  | proj
deriving Repr, BEq

def gscopeName : GScope → String
  | .glob => "global"
  | .org  => "organization"
  | .proj => "project"

def opName : Op → String
  | .create => "create"
  | .read   => "read"
  | .update => "update"
  | .delete => "delete"

def genEndpoint : String := "svc:resource"

/-- An ACL holding at most one grant, at the given scope and operation. -/
def genAcl : Option (GScope × Op) → AclData
  | none => mkAcl [] [] []
  | some (.glob, o) => mkAcl (perm1 genEndpoint [o]) [] []
  | some (.org, o)  => mkAcl [] (perm1 genEndpoint [o]) []
  | some (.proj, o) => mkAcl [] [] (proj1 genEndpoint [o])

/-- A role requiring exactly one permission, at the given scope and operation. -/
def genRole : GScope → Op → RoleData
  | .glob, o => ⟨perm1 genEndpoint [o], [], []⟩
  | .org, o  => ⟨[], perm1 genEndpoint [o], []⟩
  | .proj, o => ⟨[], [], perm1 genEndpoint [o]⟩

def gscopes : List GScope := [.glob, .org, .proj]
def gops : List Op := [.read, .create]

/-- All grant placements: absent, or one scope×operation. -/
def grantOptions : List (Option (GScope × Op)) :=
  none :: gscopes.flatMap fun s => gops.map fun o => some (s, o)

def grantName : Option (GScope × Op) → String
  | none => "none"
  | some (s, o) => s!"{gscopeName s}/{opName o}"

def generated : List Scenario :=
  gscopes.flatMap fun rs => gops.flatMap fun ro => grantOptions.map fun g =>
    { name := s!"gen req={gscopeName rs}/{opName ro} grant={grantName g}"
      source := "generated"
      acl := genAcl g
      query := .allowRole (genRole rs ro)
      humanExpect := none }

/-- Every scenario carrying a human assertion, whichever kind it exercises. -/
def handwrittenAll : List Scenario := handwritten ++ handwrittenMembership

/-- Hand-written cases first (stable, readable), then the generated matrix. -/
def allScenarios : List Scenario := handwrittenAll ++ generated

/-- Hand-written scenarios where the model disagrees with the human assertion.
    Empty is the healthy state; Main fails loudly otherwise. -/
def handwrittenMismatches : List String :=
  handwrittenAll.filterMap fun s =>
    match s.humanExpect with
    | some h => if evalDecision s == h then none else some s.name
    | none   => none

/-! ## JSON serialization (hand-rolled, dependency-free) -/

def jStr (s : String) : String :=
  let escaped := (s.replace "\\" "\\\\").replace "\"" "\\\""
  "\"" ++ escaped ++ "\""

def opJson (o : Op) : String := jStr (opName o)

def permJson (p : PermData) : String :=
  "[" ++ String.intercalate ", " (p.map fun ep =>
    "{\"name\": " ++ jStr ep.name ++ ", \"operations\": [" ++
      String.intercalate ", " (ep.operations.map opJson) ++ "]}") ++ "]"

def projectsJson (ps : List ProjectData) : String :=
  "[" ++ String.intercalate ", " (ps.map fun pr =>
    "{\"id\": " ++ jStr pr.id ++ ", \"endpoints\": " ++ permJson pr.endpoints ++ "}") ++ "]"

def aclJson (a : AclData) : String :=
  "{\"global\": " ++ permJson a.global
    ++ ", \"organization\": " ++ permJson a.organization
    ++ ", \"projects\": " ++ projectsJson a.projects ++ "}"

def roleJson (r : RoleData) : String :=
  "{\"global\": " ++ permJson r.global
    ++ ", \"organization\": " ++ permJson r.organization
    ++ ", \"project\": " ++ permJson r.project ++ "}"

def subjectsJson (ss : List Subject) : String :=
  "[" ++ String.intercalate ", " (ss.map fun s =>
    "{\"id\": " ++ jStr s.id ++ ", \"issuer\": " ++ jStr s.issuer
      ++ ", \"email\": " ++ jStr s.email ++ "}") ++ "]"

def stringsJson (xs : List String) : String :=
  "[" ++ String.intercalate ", " (xs.map jStr) ++ "]"

def groupJson (g : GroupSpec) : String :=
  "{\"userIDs\": " ++ stringsJson g.userIDs
    ++ ", \"subjects\": " ++ subjectsJson g.subjects
    ++ ", \"serviceAccountIDs\": " ++ stringsJson g.serviceAccountIDs
    ++ ", \"roleIDs\": " ++ stringsJson g.roleIDs ++ "}"

/-- Each constructor emits its own `kind` tag plus its own payload fields. The Go
    harness declares the payloads as pointers, so a field absent for one kind
    stays nil rather than reading as an empty value. -/
def queryJson : Query → String
  | .allowRole r => "{\"kind\": \"allowRole\", \"role\": " ++ roleJson r ++ "}"
  | .hasMemberByID g ou sub =>
      "{\"kind\": \"hasMemberByID\", \"group\": " ++ groupJson g
        ++ ", \"orgUserID\": " ++ jStr ou
        ++ ", \"subjectID\": " ++ jStr sub ++ "}"

def decJson (d : Decision) : String :=
  jStr (match d with
        | .allow => "allow"
        | .deny => "deny"
        | .member => "member"
        | .notMember => "notMember")

def optDecJson : Option Decision → String
  | none => "null"
  | some d => decJson d

def scenarioJson (s : Scenario) : String :=
  "    {\n"
    ++ "      \"name\": " ++ jStr s.name ++ ",\n"
    ++ "      \"source\": " ++ jStr s.source ++ ",\n"
    ++ "      \"organizationId\": " ++ jStr s.acl.organizationId ++ ",\n"
    ++ "      \"acl\": " ++ aclJson s.acl ++ ",\n"
    ++ "      \"query\": " ++ queryJson s.query ++ ",\n"
    ++ "      \"expected\": " ++ decJson (evalDecision s) ++ ",\n"
    ++ "      \"humanExpect\": " ++ optDecJson s.humanExpect ++ "\n"
    ++ "    }"

/-- The whole vector file. Regenerate with `make regenerate-vectors`. -/
def documentJson (ss : List Scenario) : String :=
  "{\n  \"scenarios\": [\n"
    ++ String.intercalate ",\n" (ss.map scenarioJson)
    ++ "\n  ]\n}\n"

end UniRbac
