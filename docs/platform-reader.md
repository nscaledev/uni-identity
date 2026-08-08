# The `platform-reader` Role

`platform-reader` is a **protected**, global-only, read-only role in the identity role catalogue.
It exists so staff support tooling can gain cross-organization read visibility without the
blast radius of `platform-administrator` (full CRUD everywhere). It is the first real wildcard
consumer of the generic global-role-binding mechanism landed by ID-398 (PR #533): every
wildcard-specific runtime behaviour — the render-time guard, the runtime read clamp, the
issuer-wide blast radius — goes live in production for the first time with this role.

The role's definition is the **read-projection of `platform-administrator`'s global scope block**,
minus an explicit, machine-checked exclusion list and a fail-closed omission list for scopes
nothing currently serves. That projection, the exclusion/omission classification, and the
role's read-only-ness are pinned by `pkg/rbac/platform_reader_contract_test.go`: any future PR
that changes `platform-administrator`'s global read surface fails that test until the change is
explicitly classified for `platform-reader`.

This document is the audit record produced by that classification, the revocation story for
principals granted this role, and the operational runbook for rolling it out.

## Read-surface audit record (point-in-time: 2026-08-07)

The audit examined, for every scope on `platform-administrator`'s global block that carries
`read`, what the corresponding downstream read endpoint actually returns, across the following
audited refs:

- uni-identity: PR #533 branch
- uni-region: `0663d38c`
- uni-kubernetes: `47f4b451`
- uni-compute: `aff93d82`
- uni-storage: `e3bf7f61`

This record is a snapshot at those SHAs, not a live guarantee — see Limitation below.

### Excluded scopes (credential- or control-equivalent reads)

| Scope | Reason |
| --- | --- |
| `region:identities` | Read returns live cloud credentials: base64 `clouds.yaml` application credential and SSH private key, on both list and get (`uni-region pkg/handler/identity/client.go:61-103`). |
| `region:servers` | `GET /api/v2/servers/{id}/sshkey` returns the SSH private key; console-session reads return a token-bearing VNC URL; v2 power actions (start/stop/reboot) are gated only by the read check. |
| `kubernetes:clusters` | Kubeconfig download shares scope+operation with listing and returns the admin kubeconfig verbatim (`uni-kubernetes pkg/server/handler/cluster/client.go:212`). |
| `kubernetes:virtualclusters` | Same pattern (`virtualcluster/client.go:205`). |
| `compute:instances` | Proxies the region sshkey endpoint (private key), console sessions, and read-gated power actions. |
| `storage:objectstorageendpoints/accesskeys` | Read returns only the access-key **ID**, never the secret half (`uni-storage accesskey.go:194-214`); exclusion is conservative judgment because the scope's entire subject is credentials, not because of a leak. Exclusion verified effective: every accesskey route gates on this exact sub-scope, not the included parent (`uni-storage accesskey.go:34,62,99` read; `:122` create; `:142` delete). |

### Omitted vacuous scopes (fail-closed)

Nothing serves a read on these today; omission fails closed so a future API landing forces a
deliberate re-audit before `platform-reader` gains the surface, instead of silently inheriting it.

| Scope | Why vacuous |
| --- | --- |
| `identity:projects/references` | Only PUT/DELETE endpoints, gated create/delete. |
| `region:identities/references` | Scope string absent from uni-region entirely. |
| `region:networks/references` | Scope string absent from uni-region entirely. |
| `region:networks:v2/references` | Only PUT/DELETE, gated create/delete. |
| `region:servers:v2` | No code checks it; v2 server endpoints check `region:servers`. |
| `region:volumes:v2` | Volumes API not shipped at audit time (storage model only). |
| `compute:clusters` | Zero matches in uni-compute; nothing serves it. |

### Included scopes

The 31 scopes below are the ones `platform-reader` actually carries, all at global scope with
`[read]` only. This table is the audit's condensed record of what each read surface actually
returns.

| Scope | Read surface (all metadata-only unless noted) | Evidence |
| --- | --- | --- |
| `identity:organizations` | Get + list-all-organizations branch; org metadata | `pkg/handler/handler.go:452`; `organizations/client.go:234` |
| `identity:oauth2providers` | Org-scoped list; `clientSecret` redacted by conversion (regression-tested) | `oauth2providers/client.go:66-88` |
| `identity:roles` | List; metadata-only, protected roles filtered | `roles/client.go:46-77` |
| `identity:serviceaccounts` | List only; `accessToken` emitted solely by create/rotate (regression-tested) | `serviceaccounts/client.go:80-113` |
| `identity:users` | Org user list; PII (names/emails), no credentials | `users/client.go:246-284` |
| `identity:groups` | List/get; membership data | `groups/client.go:59-97` |
| `identity:projects` | List/get; group IDs | `projects/client.go:57-70` |
| `identity:quotas` | Accounting quantities | `quotas/client.go:106-160` |
| `identity:allocations` | Allocation quantities | `allocations/client.go:74-105` |
| `region:regions` | Region metadata; kubeconfig lives only under separate `region:regions/detail` scope | uni-region `handler.go:96,112` |
| `region:flavors` / `region:images` / `region:externalnetworks` | Catalog data | uni-region `handler.go:144,128`; `handler_image.go:50` |
| `region:networks` | v1 list/get, no secret fields | uni-region `handler.go:230,267` |
| `region:networks:v2` | List/get, clean | uni-region `network/client_v2.go:156,177` |
| `region:loadbalancers:v2` | List/get, clean | uni-region `loadbalancer/client_v2.go:228,249` |
| `region:securitygroups` / `:v2` | Rules only | uni-region `handler.go:300,351`; `securitygroup/client_v2.go:161,182` |
| `region:volumeclasses:v2` | Storage catalog | uni-region `handler_v2_volumeclass.go:31` |
| `region:filestorage:v2` | Includes `mountSource`/NFS `mountOptions` — data-plane topology, not credentials (deliberately included) | uni-region `storage/client.go:320,354,151` |
| `region:filestorageclass:v2` | Catalog | uni-region `storage/client.go:746` |
| `region:sshcertificateauthorities:v2` | CA **public** key only; private material never stored/served | uni-region `sshcertificateauthority/client_v2.go:62-66` |
| `kubernetes:regions` / `flavors` / `images` | Catalog passthrough | uni-kubernetes `handler.go:112,131,150` |
| `kubernetes:clustermanagers` | Metadata-only | uni-kubernetes `handler.go:184` |
| `compute:regions` / `flavors` / `images` | Catalog | uni-compute `handler.go:90,109,128` |
| `storage:objectstorageclasses` | Class metadata | uni-storage `objectstorage.go:612`; `conversion.go:25-40` |
| `storage:objectstorageendpoints` | Endpoint metadata + identity policies (config, not credentials) | uni-storage `objectstorage.go:69,140`; `conversion.go:42-61` |

### Sensitivity taxonomy of INCLUDED scopes

The included scopes fall into four sensitivity classes:

- **Credential** — none, by construction. Every scope whose read surface returns credential or
  control-equivalent material is excluded above.
- **Data-plane topology** — `region:filestorage:v2` mount coordinates (`mountSource`, NFS
  `mountOptions`), networks, security-group rules, load-balancer members, and private IPs. This
  is infrastructure shape, not a credential, and is included deliberately because support tooling
  needs it.
- **PII / directory** — `identity:users` global read enables cross-organization
  user-to-organization lookup by email; this is deliberate, since that lookup is the point of
  support tooling. `identity:organizations` global read lists every organization on the platform.
- **Plain inventory** — catalogues, flavors, images, quotas, allocations, and storage/object
  classes: metadata with no PII or credential content.

### Limitation

The contract test ratchets the **identity role catalogue** only — it forces a classification
decision whenever `platform-administrator`'s global read-bearing scope set changes. It cannot see
a downstream service adding a new credential-returning GET route under a scope that is already
included here; that route-level semantics is owned by the downstream service. See Follow-ups.

## Revocation

IdP offboarding is the only revocation lever for a principal granted `platform-reader` through a
wildcard global role binding. No local compensating control is built for this role, deliberately:
introducing one would re-establish per-principal local state that the wildcard binding mechanism
exists to remove.

Concretely:

- **Organization-level suspension is a silent no-op for bound users.** A principal admitted with
  an empty `orgIds` slice (the normal case for a staff/support subject under
  `allowExternalIdentity: true`) has no organization membership to suspend, so removing them from
  an organization changes nothing about their access via the binding.
- **With `allowExternalIdentity: true`, there is usually no global `User` record to suspend
  either.** These subjects are typically never onboarded as ordinary UNI users in the first place
  — that is the case the flag exists for.
- **Worst-case revocation latency is not immediate.** It is bounded by the remaining lifetime of
  the external IdP's access token, plus the passport lifetime, plus the ACL cache TTL. Offboarding
  a subject at the IdP does not revoke a token already issued; it only prevents new tokens.
- **Best-effort break-glass:** if the subject does have an inactive global `User` record, the
  bearer path rejects it (`ErrUserInactive`) regardless of `allowExternalIdentity`. This is
  unreliable as a control today because the underlying lookup
  (`UserDatabase.GetUser`) is case-sensitive while the bearer path lower-cases the email claim
  first — a mixed-case record is treated as never-onboarded rather than inactive. See
  [docs/multi-issuer-token-contract.md#membership-resolution](multi-issuer-token-contract.md#membership-resolution)
  for the tracked gap. Until that gap is fixed, this path is documented as best-effort, not a
  relied-upon control.

## Runbook

### Blast radius

A global role binding that references an unresolvable role fails closed as a 500 for every user
of the issuer it is bound to. For an issuer-wide (wildcard) staff binding, that means every staff
user authenticating through that issuer, all at once. `protected: true` keeps `platform-reader`
out of the user-facing role list (`pkg/handler/roles/client.go:76`) and blocks it from being
granted through a group (`pkg/handler/groups/client.go:357`) — there is no role delete endpoint
in the API at all to guard against. Neither mechanism prevents chart or CRD drift: an operator can
still rename or remove the role at the Helm/CRD layer, leaving a binding that references it
unresolvable and failing closed exactly as above.

### Rollout

0. **Pre-upgrade check.** Confirm the target environment's values do not already define
   `additionalRoles.platform-reader`. Adding this built-in role reserves that name, and the chart
   render fails loudly on the collision. Remediation is to rename the custom role first, before
   upgrading.
1. Deploy the chart containing `platform-reader` with the global role binding absent.
2. Verify the live `Role` CRD for `platform-reader` and its contents (scopes, `protected: true`)
   before granting anything against it.
3. Enable the wildcard binding in the **deployment repo's** environment values — the binding
   itself is environment-specific deployment configuration, never a chart default, and is
   deliberately kept out of this repository.

Rollback reverses this order: disable the binding in deployment values first, then remove the
role from the chart if needed. This ordering is in addition to, not a replacement for, PR #533's
binary-before-flag ordering (deploy a server binary that understands
`--global-role-binding` before enabling any binding that relies on it).

Before enabling the binding in production, run a staging smoke test against the real staff
issuer, using its exact, verbatim `iss` value (including any trailing slash, as Auth0 emits).
Only the Auth0 applications and connections intended to represent staff should be able to mint
tokens for the trusted audience — this is an IdP-side configuration prerequisite, not something
this role or its binding enforces.

## Follow-ups

The audit surfaced seven follow-up items, recorded here. None block this change.

- **uni-kubernetes:** split kubeconfig retrieval out of `kubernetes:clusters` and
  `kubernetes:virtualclusters` read (for example, a `.../kubeconfig` sub-scope) so that listing
  clusters and virtual clusters can rejoin `platform-reader`.
- **uni-region:** split `GET /api/v2/servers/{id}/sshkey` and console-session reads out of
  `region:servers` read. This also carries a security defect found by the audit: v2 power actions
  (start/stop/reboot) are gated only by the read check, not an update check as v1 requires.
- **uni-compute:** the same split for `compute:instances` — it proxies the region sshkey
  endpoint, console sessions, and the same read-gated power actions.
- **uni-region:** `region:identities` read returns live credentials (`clouds.yaml` application
  credential and SSH private key) on both list and get; redact or split this scope before it can
  rejoin `platform-reader`.
- **Cross-service:** each service owning a scope included in `platform-reader` should adopt its
  own route-level "safe for platform-reader" classification, so a future read-surface change
  under an already-included scope cannot land unaudited. The identity-side contract test cannot
  see that class of change.
- **uni-identity (hygiene, optional):** clean up or annotate stale grants already present on
  `platform-administrator` — `region:servers:v2`, `compute:clusters`, and the unserved
  `/references` scopes — which the omission table above had to classify as vacuous.
- **uni-identity (hardening, optional):** the contract test pins the role as defined in this
  repository's `values.yaml`, but a deployment can still merge extra scopes into
  `.Values.roles.platform-reader`. Such an override defeats the audit while still satisfying the
  read-only render guard. No trust boundary is crossed — anyone able to set those values already
  controls the whole identity deployment — so this is an operator-drift concern (see Blast radius
  above) rather than a privilege-escalation path. A template-level equality check on the scope set
  of any wildcard-bound role would close it at render time.
