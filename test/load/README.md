# Load test

A manually triggered GitHub Actions workflow, `.github/workflows/load-test.yaml` ("Load Test"),
that drives identity's hot paths in a throwaway kind cluster on the runner. It is not part of PR or
nightly CI.

It proves one thing: **on the hot paths, identity makes no API-server calls per request**. The
gate counts those calls exactly, from the kube-apiserver audit log. Latency, CPU and the
ceiling (the highest rate with no failed request) are reported, never gated.

## Run it

```sh
gh workflow run "Load Test" --ref <branch> \
  -f dataset=small -f rate=20 -f duration=60 -f ceiling=true -f ceiling_max=2000
```

Then open the run's job summary. The artifact `load-test-<run id>` holds the per-phase k6 summaries,
the counts and the phase windows (no tokens).

| Input | Default | Meaning |
|---|---|---|
| `dataset` | `small` | `small` or `large` (see below) |
| `rate` | `20` | requests per second per phase in the steady state (where the ceiling ramp starts) |
| `duration` | `60` | seconds per steady-state phase |
| `ceiling` | `true` | find each path's ceiling after the steady state (see The ceiling) |
| `ceiling_max` | `2000` | the top of the ceiling ramp, requests per second; must be above `rate` |

Run it on `main` as it is today and it **fails the count gate**, because identity still makes live
API calls per request. That failure is the proof the gate works. On a branch that serves these
paths from its informer cache it passes.

## What runs

1. A kind cluster with the kube-apiserver audit log on (`hack/ci/load-kind-config.yaml`,
   `hack/ci/load-audit-policy.yaml`: Metadata level, identity's server ServiceAccount only).
2. Infrastructure and identity, installed as the integration workflow does, plus
   `hack/ci/load-values.yaml`, which adds an `OAuth2Provider` with `bearerTrust` (CI only).
3. `hack/ci/loadfixtures`: creates the data through the identity API, generates an RSA key in
   memory, mints Auth0-shaped JWTs (issuer with a trailing slash, audience, email, authz and groups
   claims) and writes the tokens and the public key set. The private key is never written.
4. A stock nginx pod (`idp.yaml`, image pinned by digest) serves the public key set at
   `http://jwks.load-test-idp.svc.cluster.local/.well-known/jwks.json`, the provider's issuer.
5. `run-phases.sh`: a warm-up, a 60 second no-load baseline, then one steady-state k6 run per
   phase, then (when `ceiling` is on) `ceiling.sh`: the ceiling search for each phase.
6. `count-audit.sh`: the workflow copies the audit log out of the control-plane container, and the
   script counts identity's calls per phase window.
7. `report.sh`: the job summary.

### Datasets

| | small | large |
|---|---|---|
| organizations | 20 | 100 |
| groups per organization | 4 | 30 |
| projects per organization | 3 | 10 |
| users in 1 / 5 / 20 organizations | 10 / 6 / 3 | 200 / 80 / 40 |
| service accounts | 1 per organization | 1 per organization |
| distinct Auth0 tokens | 600 | 5000 |

Every token's email has a UNI user. Tokens are used in turn, so a long run reuses them. Identity
keeps no per-token cache for Auth0 tokens: it validates each one afresh, so their count only decides
how many users the run visits. Identity's own token cache (`--token-cache-size`, 8192 entries)
holds the decoded claims of tokens identity issued, that is service account tokens, one per
organization. The load tool calls identity directly, so a caller's passport cache (4096 entries in
`pkg/middleware/openapi/remote`) is not in play.

### Phases

Each phase is a k6 run with an open-model executor (`constant-arrival-rate` for the steady state
and the holds, `ramping-arrival-rate` for the ceiling ramp), so a slow server cannot slow the
offered load. Requests time out after 5 s, and a timeout is a failure like any non-200.

| Phase | Request |
|---|---|
| `auth0-bearer` | `GET /api/v1/organizations` with an Auth0 bearer token |
| `passport-exchange` | `POST /oauth2/v2/token`, RFC 8693 form as built by `pkg/middleware/openapi/remote`, scoped to an organization |
| `acl-heavy` | `GET /api/v1/organizations/{id}/acl` with an Auth0 token of a user in 5 or more organizations |
| `service-account` | `GET /oauth2/v2/userinfo` with a service account token |

The service account phase calls userinfo because its handler does no Kubernetes reads of its own and
still runs the service account token check: the handler passes the bearer to
`Authenticator.GetUserinfoFromBearer`, which verifies the token and, for a service account, reads
the organization and the service account to check the token is current. Any API call counted in that
phase therefore comes from the token check. An endpoint such as the organization's projects list
reads the API server in its handler on purpose, which would hide the token check's cost.

## The ceiling

`ceiling.sh` runs after the steady-state phases, once per phase. Report-only.

1. **Ramp.** One k6 `ramping-arrival-rate` stage from `rate` up to `ceiling_max` over 120 s. It
   stops (`abortOnFail`, at once) at the first failure: any non-200, a request still unanswered
   after 5 s, or k6 falling behind its schedule. R is the rate the ramp had reached when that
   failure started, not when it was seen, so a 5 s timeout is not credited with 5 s of extra
   ramp. If nothing fails, R is `ceiling_max` and the result says the top was reached.
2. **Holds.** 30 s at 0.9R. If it fails, 30 s at 0.7R; if that fails, at 0.5R; then stop. A hold
   fails when any request fails or k6 delivers under 95% of the target rate. The ceiling is the
   first hold that passes, so the highest. If all three fail there is no ceiling ("none held") and
   it is below 0.5R. Each hold is its own k6 run, with a CPU read either
   side after a quiet gap.
3. The phase's p95, CPU cores and failure rate are those of the ceiling hold. Each hold records
   its target and delivered rate and its dropped iterations (reported only).

**Dropped iterations.** k6 starts an iteration only when a VU is free; when none is, it drops the
iteration and does not fail it. A load generator that runs out of VUs against a slow server would
then show no failure at all and the ramp would report its top. So k6 gets VUs for every request in
flight at once, each running to its 5 s timeout, plus 20%: top rate x 5 s x 1.2, which is 12000 at
the default 2000 req/s (k6 starts them as needed, so a healthy server uses few), with 200 built
before the run. A drop alone is not a failure: k6 builds one more VU at a time and drops every
iteration that finds none free meanwhile, so a healthy server drops some whenever the pool grows
(VUs needed are about rate x latency; the pre-built 200 cover 2000 req/s up to 100 ms). Real VU
exhaustion shows as a lower delivered rate, so a hold fails below 95% of its rate, and a ramp
counts as failed from the point its started iterations fall more than 5% behind the schedule (and
by more than 2). The schedule is the area under the ramp's rate line, and k6 counts only started
iterations.

The holds stay at 30 s: a short hold would let a noisy 0.9R pass or fail by luck and reject good
changes. A 5xx or a timeout is a failure; so is any other non-200. The decisions above live in
`ceiling.jq` and are checked by `ceiling_test.sh` (run by `make lint`), which drives `ceiling.sh`
with a fake `k6` and `kubectl`; the lag rule inside `identity.js` is not covered there.

On a build that makes live API calls per request, the ceiling is the client limiter
(`kubernetesClientQPS`, a burst of `kubernetesClientBurst` then that many calls a second): the
requests queue in the limiter, latency climbs a few hundred milliseconds each second, and the first
failure is a request that has waited 5 s, well after the queue began (the ramp's R is where that
request started, so it still overstates where the queue began). The `client rate limiter Wait`
errors in identity's log name it. A build served from the informer cache has no such limit and
reaches the next one: CPU.

## The gate

The job fails if any of these hold:

- The audit log holds no events from identity's ServiceAccount at all. Identity's informers always
  log their startup list and watch, so an empty log means the probe is blind (wrong user, audit
  policy not applied), and a blind probe would otherwise count zero calls and pass. The gate passes
  only when identity audit events are present.- A phase's identity API-server calls per request, less the idle rate, exceed `0.05`. This allows
  stray background calls; a hot path should make none. A request here is a 200 response: a failed
  request does no cache-served work and would dilute the figure.
- A phase made no requests.
- In the steady state: any 5xx, any 401, any timeout or other non-200 on valid tokens. The last one
  stops a broken fixture passing the count gate with a request that never reached the code under
  test.

The ceiling has no gate: failed requests there are how it finds the ceiling.

## What the numbers mean

**Measured on this runner**

- Calls per request, by verb and resource: audit events from identity's ServiceAccount inside the
  phase window, less the idle rate measured in the baseline window, divided by the phase's
  requests. Events are deduplicated by audit ID (a watch logs two stages) and placed in a window at
  one-second resolution; the script leaves a quiet gap between windows.
- 5xx rate, 401 count, p95: from k6.
- CPU cores used: the server container's CPU seconds over the window (cadvisor reads either side
  of it, with a quiet gap, less the idle rate), divided by the window's length. The same read gives
  CPU seconds per request.
- Ceiling: see below.

**Modelled** (computed from the measured figures, not observed)

- Limiter ceiling per replica: the client's rate limit (`kubernetesClientQPS` in
  `cmd/unikorn-identity/main.go`) divided by calls per request. "No limiter ceiling" when the calls
  are zero.
- CPU ceiling per replica: the server container's CPU limit divided by CPU seconds per request.
  CPU comes from the kubelet's cadvisor counter for the server container, read before and after each
  phase with a quiet gap either side (cadvisor lags the cgroup), less the idle rate. A reading that
  cannot be taken stops the run; it is never recorded as zero.

**Absolute requests per second and p95 are for this runner only.** The load tool, the kind node,
the ingress and identity share its CPU. Call counts and CPU seconds per request transfer as a
shape; absolute figures do not.

## What a runner cannot represent

- Production object counts, etcd size and API-server load from other clients (priority and fairness
  contention).
- The real Auth0 round trip. Keys are served from a local pod.
- Real callers' replica counts and their passport caches.
- Failure injection (slow API server, informer relist, replica kill, retries, cold start). Not in
  this version.
- Several identity replicas: it runs one.

## Files

| File | Job |
|---|---|
| `identity.js` | k6 script: one phase per run |
| `run-phases.sh` | warm-up, baseline, steady-state phases; records windows and CPU; then the ceiling when asked |
| `ceiling.sh` | each phase's ceiling: the ramp to the first failure, then the 30 s holds |
| `ceiling.jq` | the ceiling's decisions: R from the ramp, hold rates, when a hold passes |
| `ceiling_test.sh` | checks `ceiling.sh` and `ceiling.jq` with a fake `k6` and `kubectl` (needs only bash and jq) |
| `lib.sh` | cadvisor reads, the phase list and the idle CPU read, shared by the scripts |
| `count-audit.sh`, `count-audit.jq` | counts identity's API-server calls per phase and applies the gate |
| `report.sh`, `report.jq` | job summary |
| `idp.yaml` | stand-in identity provider serving the public key set |

The cluster, namespace and release names are fixed (`unikorn-identity-load`, `identity-load`) so the
audit policy can name identity's ServiceAccount; the workflow and
`hack/ci/load-audit-policy.yaml` must agree.
