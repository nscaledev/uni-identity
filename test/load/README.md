# Load test

A manually triggered GitHub Actions workflow, `.github/workflows/load-test.yaml` ("Load Test"),
that drives identity's hot paths in a throwaway kind cluster on the runner. It is not part of PR or
nightly CI; a short version of its count gate runs on every PR (see Per-PR gate).

It proves one thing: **on the hot paths, identity makes no API-server calls per request**. The
gate counts those calls exactly, from the kube-apiserver audit log. Latency, CPU and the
ceiling (the highest rate with no failed request) are reported, never gated.

## Run it

```sh
gh workflow run "Load Test" --ref <branch> \
  -f dataset=small -f warmup_restarts=3 -f rate=20 -f duration=60 -f ceiling=true -f ceiling_max=2000
```

Then open the run's job summary. The artifact `load-test-<run id>` holds the per-phase k6 summaries,
the counts and the phase windows (no tokens).

| Input | Default | Meaning |
|---|---|---|
| `dataset` | `small` | `small`, `medium` or `web` (see below). Medium and web are built in direct mode |
| `warmup_restarts` | `3` | times to restart identity's server before the phases, recording each cold start (0 records the settings only) |
| `rate` | `20` | requests per second per phase in the steady state (where the ceiling ramp starts) |
| `duration` | `60` | seconds per steady-state phase |
| `compare` | `true` | also run a release and compare (see Comparing against a release) |
| `baseline` | empty | compare only: git ref to compare against (a tag, a commit, or `origin/<branch>`). Empty is the newest release tag with no pre-release suffix |
| `compare_margin_pct` | `25` | compare only: the margin, X |
| `ceiling` | `true` | find each path's ceiling after the steady state (see The ceiling); in compare mode, once for each build |
| `ceiling_max` | `2000` | the top of the ceiling ramp, requests per second; must be above `rate` when `ceiling` is on |

Run it on `main` as it is today and it **fails the count gate**, because identity still makes live
API calls per request. That failure is the proof the gate works. On a branch that serves these
paths from its informer cache it passes.

## What runs

1. A kind cluster with the kube-apiserver audit log on (`hack/ci/load-kind-config.yaml`,
   `hack/ci/load-audit-policy.yaml`: Metadata level, identity's server ServiceAccount only).
2. Infrastructure and identity, installed as the integration workflow does, plus
   `hack/ci/load-values.yaml`, which adds an `OAuth2Provider` with `bearerTrust` (CI only).
3. `hack/ci/loadfixtures`: creates the data (through the identity API for `small`, straight into
   the Kubernetes API for `medium` and `web`: see Direct mode), generates an RSA key in memory, mints Auth0-shaped JWTs (issuer with a trailing slash, audience, email, authz and groups
   claims) and writes the tokens and the public key set. The private key is never written.
4. A stock nginx pod (`idp.yaml`, image pinned by digest) serves the public key set at
   `http://jwks.load-test-idp.svc.cluster.local/.well-known/jwks.json`, the provider's issuer.
5. `warmup.sh`: restarts identity's server `warmup_restarts` times and records each cold start.
6. `run-phases.sh`: a short k6 warm-up, a 60 second no-load baseline, then one steady-state k6 run
   per phase, then (when `ceiling` is on) `ceiling.sh`: the ceiling search for each phase.
7. `count-audit.sh`: the workflow copies the audit log out of the control-plane container, and the
   script counts identity's calls per phase window.
8. `report.sh`: the job summary.

### Per-PR gate

`.github/workflows/integration.yaml` runs the same count gate in its "response validation off" leg
(the one that matches production), after the API tests, so an emergency fix cannot bring back
per-request API calls unseen. It uses that leg's cluster, images and install. Both legs build their cluster
from `hack/ci/load-kind-config.yaml` (audit log on, pinned node image and kind version) and
install identity with `hack/ci/load-values.yaml` (the stand-in provider's trust); the legs differ
only in response validation and the gate steps. The gate leg's suffix is `gate`, so the audit
policy can name its ServiceAccount. Then: the `small` fixtures (api mode), the stand-in provider, `run-phases.sh` for
all four phases (20 req/s for 20 s, no ceiling, no server restarts, 15 s baseline, 10 s settle, which is cadvisor's lag),
and `count-audit.sh`.

- Gated: at most 0.05 identity API-server calls per request in every phase, and no 5xx (nor 401 or
  other non-200; k6's thresholds). The step log and the job summary name the failed phase and its
  figure (`gate-summary.sh`).
- Reported only: latency and CPU.
- Modelled added time, about 6 minutes: warm-up and idle baseline about 65 s, four phases about
  43 s each (20 s of load, two 10 s settles, k6 start), fixtures and controllers settling about
  1 to 2 minutes, k6 install, stand-in provider and a second `go run` about 30 s. The phases and
  the fixtures dominate; the settles are needed so the CPU figures are right.
- `gate_test.sh` checks, with a hand-made audit log and a stub k6, `count-audit.sh` (the gate,
  repeated audit IDs, window edges, other users, a blind probe), `gate-summary.sh` and
  `run-phases.sh` failing when k6's thresholds fail; it runs in `make lint`.

### Datasets

| | small | medium | web |
|---|---|---|---|
| organizations | 20 | 2,000 | 20,000 |
| groups per organization | 4 | 2 | 2 |
| projects per organization | 3 | 3 | 3 |
| users | 19 | 2,000 | 20,000 |
| users in 1 / 2 / 3 / 5 / 20 organizations | 10 / 0 / 0 / 6 / 3 | 900 / 600 / 400 / 0 / 100 | 9,000 / 6,000 / 4,000 / 0 / 1,000 |
| service accounts | 1 per organization | 1 per organization | 1 per organization |
| distinct Auth0 tokens | 600 | 2,000 (one per user) | 20,000 (one per user) |

The first group of every organization holds the administrator role and its service account; the
others hold the user role and the members (each user joins up to three of them).

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

### Warm-up

`warmup.sh` runs before the phases. It restarts the server deployment `warmup_restarts` times, each
time waiting until the new pod serves and the old one is gone, and writes `warmup.json` (in the
artifact and the job summary). It records the deployment's readiness probe, `progressDeadlineSeconds`
and rollout strategy once, and per restart:

- seconds from the new pod's creation to Ready (Kubernetes timestamps, so 1 s resolution);
- the server container's memory working set, read from cadvisor once the pod is Ready. cadvisor
  publishes a new pod a few seconds late, so the record also holds how long after Ready it was read;
- whether the rollout surged: an old pod still serving while the new pod existed and was not yet
  Ready, and the seconds, at 1 s polls, in which no pod was serving.

It stops the run if a restart does not finish within `progressDeadlineSeconds` or no memory reading
appears. The restarts come before the baseline window, so their startup list and watch calls are not
counted against any phase. Like the phases it measures this runner only; the readiness and surge
settings are the part that transfers.

### Direct mode

`--mode direct` (the workflow's choice for `medium` and `web`) writes the identity records straight
to the Kubernetes API with controller-runtime: bounded parallelism (`errgroup` with a limit),
a raised client rate limit, and `retry.RetryOnConflict` on the writes that update an existing
record. Through the API, 20,000 organizations take hours; this takes minutes.

It writes, for each organization, what identity's request path reads:

- the `Organization` with the controller's finalizer and the status the organization controller
  sets (its namespace, `Available` and `Healthy` conditions), and that namespace, labelled as the
  controller labels it;
- in that namespace: `Group`s (with their members, as subjects and as organization user IDs, and
  the service account), `Project`s, the `ServiceAccount` (its token minted with identity's own
  signing key, read from the cluster) and the `OrganizationUser`s;
- in identity's namespace: the global `User`s.

Names follow #604: users and organization users take the names the users handler gives them (they
come from `v1alpha1.GlobalUserName` and `users.OrganizationUserName`); the rest are derived from the
dataset position, so a rerun converges on the same records, and replaces each service account's
token. Labels and annotations come from the same core builder the handlers use. A unit test
(`hack/ci/loadfixtures/direct_test.go`) applies a three organization dataset to a fake cluster
and reads it back through `pkg/userdb` and the group membership check.

It bypasses identity's controllers and handlers:

- **Identity's controllers must be scaled to 0 first** (the workflow does), or they race the status
  writes. The cluster's admission policies still run.
- None of the handlers' validation runs: group, role and membership checks, subject rules.
- Projects are written without status and without their own namespaces. Nothing identity's hot
  paths read depends on them; a controller started later creates the namespaces.
- It needs the signing key, so identity must be installed and its server running first.

### Run it locally

Use a new cluster, never an existing one; the install suffix must be `load` (the audit policy names
identity's ServiceAccount). Needs `kind`, `kubectl`, `helm`, `jq`, `yq`, `openssl`, Go, Docker and
k6 on the path. From the repository root, for `medium` (use `web` the same way):

```sh
kind create cluster --name load-test --config hack/ci/load-kind-config.yaml
KIND_CLUSTER=load-test make integration-infra
KIND_CLUSTER=load-test KIND_SUFFIX=load \
  INTEGRATION_EXTRA_VALUES="hack/ci/test-values-runtime-schema-validation-off.yaml hack/ci/load-values.yaml" \
  make integration-install

# Direct mode (medium, web): identity's controllers off.
for c in organization project oauth2client; do
  kubectl scale deployment -n unikorn-identity-load "identity-load-${c}-controller" --replicas=0
  kubectl wait --for=delete pod -n unikorn-identity-load -l "app=identity-load-${c}-controller" --timeout=120s
done

set -a; . test/.env.install; set +a
mkdir -p load-out /tmp/load
go run ./hack/ci/loadfixtures/... --dataset medium --mode direct \
  --base-url "${IDENTITY_BASE_URL}" --namespace "${IDENTITY_NAMESPACE}" \
  --issuer http://jwks.load-test-idp.svc.cluster.local/ --audience https://load-test.invalid/api \
  --out-dir /tmp/load
jq .counts /tmp/load/tokens.json > load-out/dataset.json

kubectl apply -f test/load/idp.yaml
kubectl create configmap jwks -n load-test-idp --from-file=jwks.json=/tmp/load/jwks.json
kubectl wait --for=condition=Ready pod/jwks -n load-test-idp --timeout=120s

export NAMESPACE=unikorn-identity-load SERVER_DEPLOYMENT=identity-load-server OUT_DIR=load-out
WARMUP_RESTARTS=3 test/load/warmup.sh
BASE_URL="${IDENTITY_BASE_URL}" TOKENS=/tmp/load/tokens.json \
  RATE=20 DURATION=60 CEILING=true CEILING_MAX=2000 test/load/run-phases.sh

docker exec load-test-control-plane cat /var/log/kubernetes/kube-apiserver-audit.log > /tmp/load/audit.log
IDENTITY_USER=system:serviceaccount:unikorn-identity-load:identity-load-server \
  test/load/count-audit.sh /tmp/load/audit.log load-out/phases.json load-out/counts.json
DATASET=medium RATE=20 DURATION=60 CEILING_MAX=2000 test/load/report.sh load-out

kind delete cluster --name load-test
```

## Comparing against a release

A single run cannot say better or worse: its figures belong to one runner on one day. With `compare`
on, the job runs the same phases against a release as well, on the same cluster and the same
dataset, and reports where the candidate (the commit the workflow runs on) stands. **It is
report-only: nothing in it can fail the job.** It becomes a gate only after X is set (see A/A runs).

How the job does it:

1. Resolves the baseline (`baseline`, else the newest `vX.Y.Z` tag) and checks it out beside the
   candidate. Builds both server images with distinct tags (`baseline-<sha>`, `candidate-<sha>`)
   and loads them into the cluster. `test/load/swap-build.sh` and `compare-turns.sh` take the
   tags as variables, so a local run can use its own and never overwrite `v0.0.0`.
2. Builds the fixtures once. Both builds read the same records.
3. Installs once, with the candidate's chart, CRDs and values. A switch changes only the server
   Deployment's image tag (`kubectl set image`) and always restarts it (`kubectl rollout restart`),
   so every turn, including the second candidate turn, starts on a fresh pod. The controllers and
   the fixtures are never touched. **Both builds run on the candidate's chart and CRDs**; the
   baseline's own chart is not used. If the baseline cannot start on them (an unknown flag, say),
   the rollout fails and the job fails, naming the build. One chart means one set of resource
   limits for every turn. A PR that adds a server flag the release doesn't know cannot be compared
   against that release: the baseline fails to start and the job fails.
4. Runs four turns: **baseline, candidate, candidate, baseline.** The mirrored order puts any
   drift in the runner (a noisy neighbour, thermal, cache state) on both builds equally. Each
   turn restarts and measures warm-up (`warmup.sh`) and runs the phases (`run-phases.sh`) into its
   own folder `turns/<n>-<build>/` in the artifact.
5. Counts API-server calls per turn from the one audit log (`count-turns.sh`).

If the baseline cannot become Ready on the candidate's chart or run its phases, the job fails
with a message naming the turn and the step. It never passes without the comparison.

**Absolute checks** are unchanged and apply to the candidate only: at most `0.05` API-server calls
per request, and no 5xx. A baseline's counts are reported, never gated: an old release is expected
to fail the count gate.

**The comparison rule** (`compare.jq`), per phase, for CPU seconds per request and for p95:

- worse: both candidate turns are more than X% above the worse of the two baseline turns;
- better: both candidate turns are more than X% below the better of the two baseline turns;
- same: anything else (one turn over the line and one not is "same").

X is `compare_margin_pct`. The summary prints one line per check, with the candidate's mean
against the baseline's mean, each candidate turn alone, and the **baseline spread**: the two
baseline turns' difference as a share of their mean. That spread is the job's own A/A noise; a
result inside it is not evidence. A turn with no CPU reading (below noise) gives "no reading", not
"same". The ceiling is not compared by this rule: it is reported per build, side by side.

**The ceiling in compare mode.** With `ceiling` on, after the four turns each build gets one ceiling search
(`ceiling.sh`, see The ceiling), baseline first, each on a fresh restart of the server. The summary
shows both builds' first failure, ceiling, p95, CPU cores and failure rate side by side. One search
per build is one sample: a difference between two ceilings is not evidence until the A/A runs have
shown how far two searches of the same build differ. Report-only. With `ceiling` off the turns
are all that runs. If a search stops part way, the summary still shows every phase that finished
for each build and says "not measured" for the rest.

Time, web dataset (modelled, not measured): about 15 minutes for the cluster and fixtures, 10 for
the two builds, and about 8 per turn (three restarts about 5, phases about 6 at the defaults),
so about 57 minutes before the ceilings (all there is with `ceiling` off). A ceiling search is a restart and warm-up (about 2
minutes) plus, per phase, from about 1.5 minutes (a build that fails early in the ramp, then holds
at 0.9R) to 4.8 minutes (a ramp that runs its 120 s, then three holds): 8 to 21 minutes a build, so
16 to 42 for both. The job takes about 73 to 99 minutes against the 120 minute limit. Raising
`duration`, `warmup_restarts` or `ceiling_max` raises it.

### A/A runs

Setting `baseline` to the same commit as the candidate (for example its SHA) is an A/A run: both
builds are the same code, so every result should be "same" and the baseline spread is the noise.
Run it about ten times:

```sh
gh workflow run "Load Test" --ref <branch> -f dataset=web -f baseline=$(git rev-parse HEAD)
```

X is fixed from those runs, above the noise they show, before the comparison becomes a gate. Until
then the default of 25 is a placeholder. No history is stored: each run stands alone.

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
  only when identity audit events are present.
- A phase's identity API-server calls per request, less the idle rate, exceed `0.05`. This allows
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
- Failure rate (any non-200, timeouts included), 5xx rate, 401 count, p95: from k6.
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
| `warmup.sh` | server restarts: cold start, memory, readiness settings, surge |
| `lib.sh` | cadvisor reads, the phase list and the idle CPU read, shared by the scripts |
| `run-phases.sh` | k6 warm-up, baseline, steady-state phases; records windows and CPU; then the ceiling when asked |
| `ceiling.sh` | each phase's ceiling: the ramp to the first failure, then the 30 s holds |
| `ceiling.jq` | the ceiling's decisions: R from the ramp, hold rates, when a hold passes |
| `ceiling_test.sh` | checks `ceiling.sh` and `ceiling.jq` with a fake `k6` and `kubectl` (needs only bash and jq) |
| `count-audit.sh`, `count-audit.jq` | counts identity's API-server calls per phase and applies the gate |
| `report.sh`, `report.jq` | job summary of one run |
| `metrics.jq` | the CPU figures, one copy: per-phase rows (`report.jq`, `compare.sh`), the idle rate (`lib.sh`) and a ceiling hold's cores (`ceiling.sh`) |
| `swap-build.sh` | compare: switch the server to one build's image and restart it |
| `compare-turns.sh` | compare: the four turns, each in its own folder, then each build's ceiling |
| `count-turns.sh` | compare: counts per turn; the gate on candidate turns only |
| `compare.sh`, `compare.jq` | compare: the job summary and the comparison rule |
| `compare_test.sh` | checks `compare.jq` with hand-made turns, `compare.sh` with a part-finished ceiling search, `compare-turns.sh`'s `ceiling` switch (stub steps) and the workflow's input check; needs `jq` and mikefarah `yq`; run by `make lint` |
| `gate-summary.sh` | names each phase that failed the count gate, with its figure, for the job summary |
| `gate_test.sh` | checks `count-audit.sh`, `gate-summary.sh` and `run-phases.sh`'s k6 failure with a hand-made audit log and a stub k6; run by `make lint` |
| `idp.yaml` | stand-in identity provider serving the public key set |

The cluster, namespace and release names are fixed (`unikorn-identity-load`, `identity-load`; the
per-PR gate uses `unikorn-identity-gate`, `identity-gate`) so the audit policy can name identity's
ServiceAccount; the workflows and `hack/ci/load-audit-policy.yaml` must agree.
