# Distributed PDP: serving authorization decisions inside each enclave

- **Date:** 2026-07-24
- **Status:** Proposed. Not yet approved.
- **Scope:** The deployment topology of identity's authorization decision path. It covers the
  enclave authorization unit that consumes replicated state. It does not cover the replication
  mechanism itself, which the distributed-control-plane program owns. This document describes the
  whole program. A file it names can arrive in a later change of the same series.

This design un-defers **Deployment B** of `cerbos-authorization-design.md`, and reshapes it.
B is no longer a Cerbos sidecar per service. It is a per-enclave identity authorization unit. A
later fan-out to per-service sidecars stays possible and is not designed here. The program in
`downstream-remote-authorization-design.md` does not change. This design layers on top of
it.

The driver is **Unikorn 3: Distributed Control Plane** (architecture vision deck, July 2026).
That deck puts a data plane and a control plane in each region, behind three global planes:
management, aggregation and configuration. This design touches the configuration plane's rule
and consumes what the management plane pushes. Authorization verdicts are data plane, so an enclave serves them locally and keeps serving
them through a partition. The configuration-plane rule is that policy is written once, centrally,
and pushed out. Enclaves never call home to read it.

## 1. The goal is to remove one bottleneck and one single point of failure

The drivers are **scale and single-point-of-failure removal only**. Latency is not a driver.
Compliance is not a driver.

The topology decision is a per-cluster regional PDP fleet first. Fan-out to per-service sidecars
happens only if it becomes necessary later.

### The four decisions that shape this design

| # | Decision | Choice |
|---|---|---|
| 1 | What fronts the enclave PDP | An **enclave-local identity authorization service** serving the existing `POST /authorization/check`. Consumers re-point through discovery. The `pkg/rbac` seam does not change. *(Rejected: consumers dial the PDP directly. That moves the trust semantics of `downstream-remote-authorization-design.md` section 4.3 into every consumer, adds mTLS surface, and fragments the audit trail.)* |
| 2 | Where bindings come from | A **replicated projection for every actor**, human and service account alike, so authorization state is available locally. *(Rejected: bindings carried in tokens for service accounts. That creates two resolution paths, ties staleness to token lifetime, and grows the passport claim surface. Bindings in tokens cannot work for humans at all, because humans keep broad Auth0 bearers.)* |
| 3 | How policy is distributed | **Replicate the source state and generate locally in each enclave** with the existing controller. Generation is compilation, not authoring, so policy is still written once, centrally. *(Rejected: signed bundles built centrally, which create a compatibility problem between policy shape and client version that local generation does not have. Rejected: Cerbos Hub, a paid external dependency on the decision path.)* |
| 4 | How this sequences against the central rollout | **The central rollout proceeds unchanged and the enclave layers on.** Mode (shadow or enforce) and endpoint (central or enclave) are independent knobs. *(Rejected: making the enclave a prerequisite for enforce, which gates real hardening on a future topology.)* |

## 2. The design stands on replicated identity state

**Replicated identity state.** The distributed-control-plane program replicates the
authorization-relevant identity state into the local etcd of each enclave, over the
management-plane push channel. That state is the `Role` CRDs plus the binding sources:
organizations, projects, groups and service accounts. **The replication mechanism is out of scope
here. This design consumes the replicated state.** If the state does not land as local CRDs, the
fallback is a policy-and-bindings bundle built centrally and signed, behind a small transport
seam. That fallback is noted here, not designed.

**Projections are read only.** An enclave copy is a projection. Every write goes to the centre.
This design adds the read-only guard on the consuming side (see section 5). The replication side
belongs to the replicated-state assumption.

**One cluster is the degenerate enclave.** The deck's enclave is a region, with its own etcd and
its own infrastructure root. Today's single-cluster deployment is the one-region case.
Everything here runs unchanged in one kind cluster, which is also how CI exercises it.

**The human path does not change.** Humans keep broad Auth0 bearer tokens, because the deck
rejected forcing them through an exchange. Their bindings always come from the projection, never
from tokens, and the same single resolution path serves service accounts. As a result, the line in
`cerbos-authorization-design.md` section 6 that says the passport carries the bindings a
distributed PDP needs is **superseded**. The passport carries actor identity only, verified
against `pkg/middleware/openapi`, where passports are consumed in process and never forwarded, and
RBAC is resolved separately.

That describes what the passport carries, not that the exchange survives. Both source documents
plan to remove the central exchange in its present form: the platform identity architecture
deletes the broker outright in favour of local validation, and the deck replaces it with a
two-exchange model whose second leg runs in the enclave. What this design relies on is the
narrower and durable half — the passport carries actor identity, and bindings come from the
projection.

## 3. One new deployment unit: the enclave authorization profile

The enclave authorization profile is the same image and chart family as identity, selected by Helm
values. It serves identity's **read-only authorization surface** and nothing else. That is wider
than the check endpoint alone: a consumer's middleware fetches an ACL on every uncached request,
so the surface is the check endpoint plus both ACL routes. Those three are exactly what the
consumer-side authorizer calls, which is why one endpoint moves all three.

One authorization call stays central: the untrusted project-ID verification behind a create. It
rides the consumer's other identity client, alongside quota and lifecycle calls that belong at the
centre, so relocating it would need a third client in every consumer. The residual is that this
narrow path fails under a partition. Folding the existence check into the decision itself removes
the call rather than relocating it, and that is the follow-up. Every write surface is absent.

It runs four things and nothing else:

- The `POST /authorization/check` surface, with its existing mTLS, certificate-relay,
  `X-Principal` and `X-Impersonate` middleware.
- The existing policy reconciliation controller, watching the *local* replicated `Role` CRDs,
  generating the Cerbos policy store and writing the ConfigMap, exactly as it does centrally
  today.
- The Cerbos PDP as a loopback-only, unauthenticated sidecar for each replica, unchanged from the
  `pkg/authz/cerbos` contract. The client's refusal of a non-loopback address stays.
- Binding resolution reading the *local* replicated state. It is the same code, pointed at the
  local API server.

N replicas of this pod behind a Service are the regional PDP fleet. Consumers keep the `pkg/rbac`
remote seam byte for byte and re-point their check endpoint for each enclave. That is Helm values
today and platform discovery when it lands. **Central identity stays the only authoring and
management authority** for roles, organizations and grants, and keeps serving checks itself.
Calling it "the first enclave" is convenient shorthand for the single-cluster case only: in the
deck the global planes stay structurally distinct from enclaves, and cross-region coordination
always routes through the centre.

Because generation is local, the policy shape in an enclave always matches the request-building
code in that same enclave. Both ship in one binary, guarded by the existing store-version check,
so there is no cross-version bundle compatibility to manage. The residual is transient
policy-behaviour skew between enclaves during a rollout. That is inherent to any distributed
rollout, and section 7 makes it observable through the store version and hash.

## 4. The hot path does not change, and the freshness path is asynchronous

**The check path stays synchronous and keeps today's semantics.** A consumer handler calls
`rbac.Allow*` or the batch form, which reaches the remote `CoarseEngine`, then `CheckMany`, then
`POST /authorization/check` at the *enclave* endpoint. The mTLS, certificate-relay and
impersonation semantics are exactly those of `downstream-remote-authorization-design.md`
section 4.3. The enclave authorization instance authenticates the caller, resolves the principal
and bindings from local replicated state, builds the Cerbos request, calls the loopback PDP and
returns the verdicts.

The consumer-side timeout, the fail-closed mapping and the circuit breaker all apply unchanged.
They now guard a call inside the enclave instead of one across regions. Nothing on this path
leaves the enclave.

**The freshness path is asynchronous.** Roles and bindings are mutated centrally. Replication
lands them in the etcd of the enclave. For roles, the controller regenerates the policy, writes
the ConfigMap, and the kubelet sync triggers a PDP hot reload through the existing store-version
machinery. For bindings, the next check reads the newer state. Decision freshness thus
equals replication lag, plus generation and kubelet sync for policy. **Grants and revocations
propagate at the same lag.** Section 7 makes that lag measurable. The numeric target belongs to
the platform program and is not invented here.

**A partition freezes authority. It does not remove it.** If replication stalls, the enclave keeps
serving the last known good policy and bindings, so decisions keep flowing. This is the
freeze-not-destroy rule from the deck: a re-check is a local edge decision against the last known
policy. Two failure classes stay strictly separate.

The deck's freeze carries two obligations beyond serving stale state: the affected resource is
marked loudly and queryably, and a two-person rebind is exposed. Neither is in this design.
Section 7 offers fleet-level freshness signals, which is not per-resource queryable marking, and
there is no rebind path here at all. Whether an authorization projection needs both is an open
question: the deck states them for a frozen *resource* under a stalled reconciler, and a stale
role binding is not a resource in that sense. Recorded rather than resolved.

| Failure class | Behaviour |
|---|---|
| **Staleness**, when replication lags or stalls | Serve the last known good state. Never fail closed. Observable through section 7. Accepted residual: an ACL served from the projection lags too, and consumers filter list responses with it, so a user can briefly see resources they have just lost or miss ones they have just gained. The lag is the replication lag plus the consumer's ACL cache TTL. |
| **Evaluation failure**, when the PDP is down, times out or the transport errors | Fail closed with `ErrDecisionUnavailable`, exactly as today. |

**The accepted residual, stated plainly.** A revocation made centrally does not reach a
partitioned enclave until it reconnects, so the revocation horizon equals the partition duration.

**It is a wider trade than the deck's token horizon, not the same one.** The deck derives its
service-account horizon from an availability budget: TGT expiry equals the centre's single-event
outage budget, roughly 5 minutes at five nines and 53 minutes at four nines. This design's horizon
has no cap at all, because it is the partition itself. The direction of the trade matches. The
bound does not. The deck also still lists the service-account partition trade as an open sign-off,
so it is not yet accepted there either.

Freeze-not-destroy does not bound this residual. It bounds *deletion*: reference sets are
enclave-local and deny deletion while dependents exist, independent of the RBAC check, so a
partition makes a delete hang visibly rather than complete wrongly. Stale authority is deliberately
preserved, not bounded, and a numeric bound for it is the open question in section 7.

## 5. No new trust surface is added

**The trust surfaces stay as they are.** The consumer-to-authorization hop is still mTLS plus
certificate relay, and the attributed-service-to-service and impersonation-intersection code does
not change. The PDP stays a loopback-only unauthenticated sidecar, so no network exposure is
added.

**Projections are read only in practice, not only by intent.** The authorization profile serves no
write surface. Omitting those routes from the profile is the primary guard. Kubernetes RBAC, read
only on the replicated resources, is the write guard rather than merely a backstop: route omission
makes the write handlers unreachable through the mux, and only the RBAC denies them if they are ever
reached. Every write goes to the centre.

**Policy authenticity rides the replication channel**, which is the platform's trusted management
artery. Signed state snapshots are optional hardening if that trust is later judged insufficient.
They are not a prerequisite.

**Trust domains stay aligned.** An enclave authorization instance serves only its own enclave.
There is no lateral enclave-to-enclave authorization, which matches the closed trust domains in
the deck. If one instance is compromised, the blast radius is read-only projected state and local
verdicts. It cannot mint grants, because it has no write path, and it cannot affect another
enclave. That is strictly smaller than a compromise of central identity today.

**Specification section 10.1 needs an amendment, and this design does not satisfy its letter
without one.** The section has three clauses, and an earlier version of this document argued
around the third:

> Single enforcement point — all access decisions are made against the ACL returned by the
> identity service. There is no local policy evaluation in individual services. Duplicating or
> caching access logic outside the ACL endpoint is a defect.

The first two clauses hold here. Consumers evaluate nothing locally, and decisions are still made
by *the identity service*, which becomes a distributed service. The third clause is the one this
design engages: replicating the source state and generating the policy store inside every enclave
duplicates access logic outside a single ACL endpoint, by that clause's plain reading. Claiming
the letter is preserved while section 10 requires an amendment cannot both be true, so this
document no longer claims it.

The amendment is still narrow: recognize that identity may serve decisions from enclave-local
instances that evaluate centrally-authored replicated state, with bounded and observable
staleness, and that the third clause forbids access logic authored or diverging outside identity
rather than identity's own policy compiled in more than one place. Authoring stays single and
central. **"Single policy authority" replaces the implicit "single instance", and the
enforcement-point rule is unchanged.** The original Deployment B, with a sidecar in every service,
would have broken the first two clauses as well. This design breaks none of them, and needs the
third reworded.

## 6. Rollout is per service, per enclave, and reversible

The central rollout continues unchanged, as `downstream-remote-authorization-design.md`
sections 4.4 and 4.5 describe. In a single cluster the central endpoint *is* the enclave
endpoint, so none of that work is repeated.

When clusters multiply, adoption happens service by service:

- For a service that does not enforce yet, point it at the enclave endpoint in `shadow` mode. The
  existing divergence gate then validates the whole enclave stack against the legacy walk:
  replication freshness, local generation and binding resolution. Flip it to `enforce` on zero
  divergence.
- For a service that already enforces against the centre, re-pointing to the enclave endpoint is a
  configuration change with a canary and an instant rollback to the central endpoint. Dropping
  back to `shadow` would regress enforcement during the soak, so it is not required. Both
  endpoints run identical code, and the freshness and store-hash signals in section 7 cover the
  delta of replication and generation. An optional comparator that dual-checks central against
  enclave is available as hardening. It is not built by default.

Rollback is always for one service in one enclave. Re-point the endpoint, or set the mode to `off`
for the full legacy fallback, as today.

## 7. Staleness must be measurable

- **Freshness for each enclave.** The age of the last applied replicated-state revision is the
  replication lag. The loaded policy store version and hash extend the existing store-version
  machinery. The controller also reports generation errors. These three signals are the
  operational form of the staleness contract in section 4. Alert thresholds are tunable for each
  deployment.
- **Decision logs stay enclave-local**, both identity's decision log and the PDP's own audit log,
  as today. The global rollup belongs to the aggregation plane and is out of scope here. A
  per-enclave sink satisfies the shared-sink intent of `cerbos-authorization-design.md`
  section 6 within each enclave.
- **Consumer-side telemetry does not change.** Latency, deny rate, error rate and breaker state
  now reflect calls inside the enclave.
- **Shadow-divergence logs are emitted for each enclave** during adoption, reusing the existing
  greppable format and the existing gate.

## 8. Testing follows the kind integration strategy

Unit tests cover the wiring of the authorization profile, so that only the check surface is served
and the write surfaces are absent. They cover the read-only guard. They cover controller behaviour
against replication-shaped `Role` fixtures, reusing the golden files in
`pkg/authz/cerbos/generate`.

Kind integration tests run in a single cluster, which is the degenerate one-enclave case. Deploy
the enclave authorization profile beside central identity. Simulate replication by applying
identity state into the namespace the profile reads. Run the two-principal RBAC matrix through the
*enclave* endpoint, with BDD structure, the typed client and `test/api.Endpoints`. Adapt the
divergence gate to the logs of the enclave. Three tests carry the load:

- **Staleness serves.** Stall the simulated replication and mutate central state. The enclave must
  keep serving the last known good verdict, and the freshness metric must reflect the lag.
  Staleness must never produce `ErrDecisionUnavailable`.
- **Evaluation failure fails closed.** Kill the enclave PDP. Checks must deny with
  `ErrDecisionUnavailable` inside the deadline, which is the unchanged semantics.
- **Hot reload works.** Change a replicated `Role`. Regeneration must produce a new store version
  and hash, and the verdict must change.

Multi-cluster end-to-end testing is out of scope for CI now. Revisit it with the test
infrastructure of the platform program.

## 9. Risks

| Risk | Mitigation |
|---|---|
| Replicated state does not land as local CRDs | The fallback seam: a policy-and-bindings bundle built centrally and signed, behind a transport interface. Noted in section 2, and a separate design if it triggers. |
| Replication lag delays grants and revocations | Freshness metrics and alerts (section 7). Accepted under the model in the deck, in the same class as a token-lifetime trade. |
| The revocation horizon equals the partition duration | Accepted residual (section 4), bounded on the platform side by freeze-not-destroy and reference-set deletion gating. |
| Policy behaviour skews between enclaves during a rollout | Local generation pins the policy shape to the binary of each enclave, guarded by the store version. The skew is transient and observable through the store hash for each enclave. |
| A misconfigured profile exposes write surfaces in an enclave | Route omission as the primary guard, Kubernetes RBAC as the backstop, and a unit test asserting the served route set. |
| An outage of the enclave authorization fleet takes down authorization for that enclave | This is not a new risk. It is the bounded residual of the SPOF in the central design, where the same outage, or merely losing the cross-region path to the centre, fails authorization closed across the whole platform. Distribution shrinks the blast radius to one enclave and removes the cross-region trigger. Inside an enclave the class is inherent to any remote decision point, and only the deferred per-service sidecar fan-out removes it. Mitigations are as today: N replicas with a PodDisruptionBudget, plus consumer fail-closed and the breaker. |

## 10. Specification impact

`nscaledev/uni-specifications` `SPECIFICATION.md` section 10.1 needs the amendment worded in
section 5: identity may serve decisions from enclave-local instances that evaluate
centrally-authored replicated state, with bounded and observable staleness. **This is an
external dependency.**

## 11. Out of scope

Three different things sit in this list, and reading one as another has already cost a round of
rework. **Owned elsewhere** means the platform expects the thing and another workstream builds
it, so this design must leave room for it. **Deferred** means it is wanted later. **Rejected**
means the platform has decided against it.

**Owned elsewhere.**

- **The replication mechanism.** The platform program owns it. This design consumes its output
  and asserts nothing about how the state arrives.
- **The enclave token-exchange and signing component.** Read this as ownership elsewhere, not
  prohibition. The vision deck's target has each enclave signing the service-account access
  tokens it issues with its own local key, and running the second service-account exchange
  locally with no central call. The load-bearing property the deck claims for that shape is that
  the long-lived credential never touches an enclave. So an enclave will hold signing keys and
  will serve an exchange. This design builds neither, and nothing here may preclude either.

  Two limits on that, because the deck is not claiming a fully closed domain. An enclave still
  verifies a TGT minted centrally, against key material the deck calls "warm, online,
  fleet-wide", and whose failure mode is still an open sign-off. Human Auth0 tokens stay broad
  and are verified everywhere. The sources name an owner only for the human path, the human-path
  team. The owner of the service-account exchange work is not named in them.
- **A rollup of decision logs across enclaves.** Decision logs stay enclave-local here
  (section 7). No source assigns the rollup an owner: the deck's aggregation plane is a
  transitional, read-only, assembled-on-demand cross-region view and explicitly never a write
  path, so it is not one.

**Deferred.**

- **Fan-out to per-service sidecars.** The enclave authorization unit can later run as a sidecar
  for each pod, still speaking `/check`, with no consumer change.
- **Multi-cluster CI.** Revisit with the test infrastructure of the platform program.

**Rejected by this design.** Neither source mentions Cerbos or policy bundles, so these are this
document's own choices, recorded in section 1, decision 3.

- **Cerbos Hub.** A paid external dependency on the decision path.
- **Centrally built signed policy bundles**, except as the fallback of last resort in section 2.
  Local generation avoids the compatibility problem between policy shape and client version.

## Open questions

- **The numeric staleness target.** The freshness alert threshold, and any formal objective,
  belong to the platform program. This design only makes staleness measurable.
- **How an endpoint is selected, and how many endpoints a consumer needs.** Helm values for each
  enclave today. The deck's end state is discovery replicated to every enclave and served over
  anycast BGP, returning a service-to-endpoint map that clients use to call the owning service
  directly, with no trusted terminating middlebox in the loop. So the configuration shape chosen
  now must not preclude a discovery lookup later. A consumer also needs its authorization
  endpoint separately from its identity host, because one host serves far more than
  authorization: the RFC 8693 token exchange on every bearer request, the quota allocation calls
  on every resource create, resize and delete, and the project reference calls on a reconcile.
  Only the authorization subset belongs in an enclave. That second endpoint does NOT collapse
  when the enclave gains local signing. It collapses only if quota and references are served
  locally too, which the deck foresees for quota through locally consumed leases and does not
  settle here.

- **Whether to co-locate with the enclave token-exchange component.** Still open, and the
  sources do not settle it. The deck decides that both functions exist in every enclave: the
  local signing key, and the second service-account exchange served locally. It says nothing
  about the authorization service and the signing component being ONE deployment unit, which is
  what this question asks. So the direction is clear and the packaging is not. Decide when that
  workstream is real, and until then keep the authorization profile shaped so co-location stays
  possible.
