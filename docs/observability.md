# Identity observability design

## Context

This design gives the UNI `identity` service a clear observability ownership
boundary: the application chart emits and exports signals, while a separately
deployed observability chart (`charts/identity-observability`) owns Grafana
dashboards and datasource wiring.

Identity has a limited **producer** surface, so the starting point matters:

- **There is no Prometheus scrape endpoint anywhere in identity.** All metrics
  leave via **OTLP push**, and only when `--otlp-endpoint` is set (it is unset by
  default — the one telemetry knob in the chart, `otlpEndpoint`, is commented
  out). A shared telemetry setup is used by all four binaries. With no endpoint
  configured the MeterProvider has no reader and **nothing is exported at all**.
- **The first-party metric surface is two counters**, both OTel
  `Int64Counter` created via `otel.Meter(constants.Application)`:
  `unikorn_identity_bearer_tokens_unroutable{surface,reason}`
  (`pkg/oauth2/oauth2.go:174`, incremented in `pkg/oauth2/passport.go:262,272,279`)
  and `unikorn_identity_auth0_jwks_refreshes_throttled`
  (`pkg/oauth2/auth0/throttled_transport.go:72`).
- **HTTP RED middleware records the API surface.** The server middleware chain
  emits request count, duration, and in-flight metrics after OpenAPI route
  resolution. Labels use the templated route, method, and status class, never
  raw resource IDs. These metrics follow the existing OTLP push path.
- **The three controllers** (organization, project, oauth2client) register the
  controller-runtime built-ins (`controller_runtime_reconcile_*`, `workqueue_*`,
  `rest_client_*`, Go/process collectors) on the shared registry, bridged to OTLP
  via `prombridge`. **The API server runs no manager**, so it has none of these.
- **Each controller publishes build and readiness gauges.** Controller readiness
  follows cache sync and leader acquisition. The API server has no equivalent
  first-party lifecycle gauges today.
- **CRD lifecycle state is not exported by identity.** Three Kinds are reconciled
  and carry the shared core conditions — Organization, Project, OAuth2Client — but
  those conditions live only in CR status. Nothing in identity turns them into
  metrics.

The decision taken here (confirmed with the service owner) is **not** to add a
scrape endpoint to identity's binaries, and **not** to build a bespoke identity
state exporter. Instead:

- **Transport:** keep the OTLP-push posture and design around it. The
  observability chart owns **no ServiceMonitors**; identity's own series reach the
  backend through the existing OTLP collector pipeline. This is the identity-shaped
  equivalent of the reference's "document, don't harden" transport decision.
- **Object-state signals:** consume condition-based lifecycle metrics from a
  separately operated exporter once it covers Identity kinds. This keeps Identity
  from inventing a second state-export mechanism.
- **Breadth:** a focused, high-signal set of two dashboards plus an opt-in
  leader-election view, not the reference's much broader asset set.
- **Ownership:** a new `charts/identity-observability` chart owns dashboards and
  the datasource. Its central profile owns the complete dashboard suite.
  Its workload profile can render only dashboards, and only when that Grafana
  instance can query the central Identity metric store. Identity's existing
  single chart (`charts/identity`) is unchanged except for documenting the
  posture.

The gap this design closes is the dashboard side: there are no Identity dashboards,
datasource wiring, or render validation. What it cannot close on its own is the
producer gap on the API surface — that is called out explicitly rather than papered
over (see "Producer gaps").

## Producer inventory (what identity emits, and how it leaves)

All export is OTLP/HTTP push, gated on `--otlp-endpoint`, plain-HTTP
(`otlpmetrichttp.WithInsecure()`), no auth, no `/metrics` endpoint to protect.

**First-party application counters (API server only)** — `otel.Meter(constants.Application)`

- `unikorn_identity_bearer_tokens_unroutable` — `Int64Counter`, unit `{token}`.
  Labels (bounded, ~6 series): `surface` ∈ {`bearer`,`exchange`};
  `reason` ∈ {`unparseable_iss`,`unknown_issuer`, *absent*}.
  `pkg/oauth2/oauth2.go:174`, set in `pkg/oauth2/passport.go:262,272,279`.
- `unikorn_identity_auth0_jwks_refreshes_throttled` — `Int64Counter`, unit
  `{fetch}`, no labels. `pkg/oauth2/auth0/throttled_transport.go:72,96`.

**controller-runtime built-ins (the three controllers only, via OTLP bridge)** —
the default controller registry remains active and is bridged to OTLP.

- `controller_runtime_reconcile_total{controller,result}`,
  `controller_runtime_reconcile_errors_total{controller}`,
  `controller_runtime_reconcile_time_seconds{controller}`
- `workqueue_*{name}`, `rest_client_requests_total{code,method,host}`
- Go/process collectors (`go_*`, `process_*`), controller-runtime
  leader-election gauge
- `unikorn_identity_controller_build_info{controller,version,revision}` and
  `unikorn_identity_controller_ready{controller,version,revision}`. Readiness is
  `1` only after the manager cache has synced and the controller holds its leader
  lease; build info remains `1` for the process lifetime.

**API server** — no controller-runtime manager, so none of the controller metrics.
It emits the two counters and HTTP RED metrics.

**HTTP RED (API server only, via OTLP)** —
`unikorn_identity_http_requests_total{route,method,status_class}`,
`unikorn_identity_http_request_duration_seconds{route,method,status_class}`, and
`unikorn_identity_http_requests_in_flight{route,method}`. The metrics cover
OpenAPI-resolved routes; route-resolution failures have no stable route label and
are not included.

**State / kube-state exporter (in identity)** — **absent.**

**Build and readiness gauges** — each controller emits
`unikorn_identity_controller_build_info` and
`unikorn_identity_controller_ready`. API server build and readiness gauges are a
recommended producer gap, not part of the current metric contract.

### Optional lifecycle-state contract

Identity does not export CRD condition state itself. Lifecycle panels require an
independently operated exporter to cover Identity kinds and provide the following
contract:

- `uni_resource_error_reason{kind,namespace,name,reason,flavor_id}` — gauge set to
  `1` **only while a resource's `Available` condition is not `True`**. Healthy
  resources have **no series**, so recovery removes the series.
- `uni_resource_state_timestamp_seconds{kind,state,namespace,name}` — Unix
  timestamp of when the resource entered a tracked `state`; present only while in
  it. The states relevant to Identity are `Provisioning` and `Deprovisioning`.
  **`Errored` is not a tracked state**, so there is a provisioning/deprovisioning
  entry-time but no error entry-time.
- `uni_<kind>_provisioning_duration_seconds{outcome,...}` — per-kind histogram,
  Provisioning→terminal, buckets 1s…3600s. Emitted per controller, so identity
  kinds added to the exporter would each get one.

The exporter must also expose enough health information to distinguish absent
lifecycle series from an unavailable collection path.

## Adapting each operational purpose — adopt / adapt / rebut

Each reference theme is marked **ADOPT** (applies, keep), **ADAPT** (applies in
spirit, reshaped to identity), or **REBUT** (does not apply). The rebuts matter as
much as the adopts: they stop the design importing assets for subsystems identity
does not have.

| Reference theme | Verdict | Identity treatment |
| --- | --- | --- | --- |
| Lifecycle health | **ADAPT** | Lifecycle health = the `Available` condition of Organization/Project/OAuth2Client, observed through `uni_resource_error_reason` (present only while `Available != True`) when the external exporter covers Identity kinds. "Time stuck provisioning" uses `uni_resource_state_timestamp_seconds{state="Provisioning"}`. Healthy resources have no series. |
| Rollout & recovery safety | **REBUT** | Identity has no separate release or infrastructure-lifecycle subsystem. |
| Dependency health | **REBUT → ADAPT** | Identity depends on the **Kubernetes API** and **upstream OIDC/OAuth2 IdPs** (Google/Microsoft/GitHub federation + their JWKS). These surface on the API path: trust-cache-not-ready → HTTP 503, untrusted issuer → HTTP 401 (`pkg/oauth2/trustlist.go:52-60`), plus the `jwks_refreshes_throttled` and `bearer_tokens_unroutable` counters. HTTP RED distinguishes these API responses in the dashboard. |
| Endpoint & load-balancer path | **REBUT** | Identity serves one HTTP API behind the platform ingress; no LB/endpoint lifecycle. |
| Other platform-runtime concerns | **REBUT** | These components are outside Identity's scope. |
| Collection and resource safety | **ADAPT** | Self-observability of the collection path. Identity has two pipelines: an external condition-state exporter and the **OTLP export pipeline**, which emits nothing unless `--otlp-endpoint` is set. Include controller-runtime reconcile health and pod memory/OOM/restarts for the four workloads. |
| Security, PKI & audit | **REBUT → ADAPT** | Identity *is* the trust root/PKI. Metrics are plain HTTP, so there is no serving-cert expiry to watch. Token signing (ES512, two-key rotation) runs in the jose issuer's own leader-elected loop (`pkg/jose/jose.go`, a `coordination/v1` Lease) — **rotation failure is observable only in logs today**, a stated gap. Audit is the audit middleware (`pkg/middleware/audit/logging.go:145`) emitting structured log lines, not a metric or separate sink. |
| Snapshot & retention | **REBUT** | Identity takes no snapshots. |
| Capacity & platform hygiene | **ADAPT (light)** | Pod memory/OOM/FD/restarts for the four workloads from the controller-runtime process collectors (via OTLP). **Object-population counts are *not* available** from `uni_resource_error_reason` — it emits series only for *unhealthy* resources, so it cannot count healthy orgs/projects. Population counting would need a new `_info`-style family (out of scope). |
| Scrape plumbing | **REBUT → ADAPT** | Identity exposes no scrape targets, so there is **no identity `up` series and no ServiceMonitor target-membership check**. Identity binary liveness is inferred from its OTLP series arriving (and from Kubernetes pod state), not from `up`. |

Cross-cutting constraints: bounded, operationally-useful labels only (already true
— the two counters are bounded; the external lifecycle contract is bounded by
object count plus a reason enum, and carries **no external IDs**. The dashboards
make series absence explicit where it can otherwise be mistaken for a healthy
resource.

## Metric contract — adopt vs rebut the reference's metrics

The reference's metric families are rebutted where they belong to different
producers. The adopted contract for Identity is:

- **Adopt the two first-party counters** as the auth-path signal
  (`unikorn_identity_bearer_tokens_unroutable`,
  `unikorn_identity_auth0_jwks_refreshes_throttled`). Bounded, already discipline-clean.
- **Adopt the controller-runtime built-ins** for the three controllers as the
  reconcile-health and capacity signal. These arrive via the OTLP bridge, not a
  scrape.
- **Adopt the external `uni_resource_*` contract** for
  Organization/Project/OAuth2Client lifecycle — *conditional on the prerequisite
  below*. Query hazards to bake into dashboards:
  - **Healthy = absent series.** `uni_resource_error_reason` exists only while
    `Available != True`. A dashboard query must not interpret a missing series as
    `status="False"` (there is no `status` label). `absent(metric)` is ambiguous:
    every resource may be healthy, or the exporter may be down.
  - **Only the `Available` condition is exported.** The exporter reads `Available`
    and nothing else. Organization and Project *do* set a `Healthy` condition
    (`pkg/provisioners/{organization,project}/provisioner.go`) and OAuth2Client
    does not — but **none of them reach Prometheus**. Dashboard queries must key on
    `Available` reasons only; `Healthy`, `Active`, and `Ready` match nothing.
  - **The `reason` label uses the shared lifecycle vocabulary.** The `Available`
    reason is set outside Identity: `Provisioning`, `Provisioned`, `Errored` (generic message "an
    unexpected error occurred"), `Deprovisioning`, `Deprovisioned`, and the
    dependency reasons `DependencyNotReady`/`DependencyFailed`/`DependencyNotFound`
    (reached via the typed-error enrichment). So `Errored` alone cannot say *why* it
    errored, but the `Dependency*` reasons remain distinguishable. There is no
    `Cancelled` on the `Available` axis (a cancelled reconcile
    leaves the condition untouched). This is the identity analogue of the
    "collapsed reasons" trap: the per-reason richness that would need a new producer
    metric is the distinction *within* `Errored`, which identity does not expose.
  - **Label shape.** The lifecycle exporter emits bare `namespace`/`name`.
    Dashboard queries use that stored shape.

No new Identity producer metric is proposed as *required* here. The producer gaps
below are recommended follow-ups, not prerequisites of this assets work — except
the two pipeline prerequisites, which are what make any of these series exist.

### Producer gaps (recommended, not shipped here)

1. **Signing-key rotation signal.** The jose rotation loop is observable only in
   logs. A small bounded gauge (e.g. active signing-key count / next-rotation age)
   would expose stalled rotation before tokens fail verification.
2. **External lifecycle-exporter coverage of Identity kinds.** See prerequisites —
   this is what turns the lifecycle section from design into live series.
3. **API server lifecycle gauges.** Bounded build and listener-readiness gauges
   would add server lifecycle coverage without treating request traffic as a
   liveness signal.

## Prerequisites (cross-repo, with merge order)

Identity's suite depends on two changes *outside* this repository:

1. **A lifecycle exporter gains Identity coverage.** It must publish the
   `uni_resource_*` series to the metric store. Until this lands, lifecycle
   dashboard panels have no source series.
2. **Identity binaries get `--otlp-endpoint` set** in the deployment, pointing at
   the collector that relays to the backend the dashboards query. Until then the
   two counters and the controller-runtime built-ins are not exported.
3. **Then** deploy `charts/identity-observability` (this work).

The lifecycle-exporter series and the OTLP relay must land in the metric store that
Grafana queries. This must be verified in the deployment environment rather than
assumed.

## Ownership, deployment profiles & scrape path

New chart `charts/identity-observability` has its own `Chart.yaml` and label helpers.
One owner per asset class, rendered through two explicitly different profiles:

| Asset | Owner | Central observability profile | Workload profile |
| --- | --- | --- |
| Grafana dashboards | `identity-observability` | enabled; Grafana queries the store that receives Identity OTLP and lifecycle-exporter series | opt-in sidecar ConfigMaps only when its datasource can query that same store |
| Grafana Loki datasource | `identity-observability` | enabled for the Grafana instance | never rendered; a workload Grafana must use its separately owned datasource |
| ServiceMonitors | **none** | Identity pushes via OTLP; any lifecycle scrape target is owned externally | none |
| metrics-reader RBAC | **n/a** | this chart scrapes nothing | none |

`values-central.yaml` enables the datasource and dashboard provisioning.
`values-workload.yaml` may enable dashboards only after its Grafana datasource
contract is verified. A deployment without access to the required metrics is
misleading rather than useful and must remain disabled.

```text
Identity workloads                         Observability backend
------------------                         ---------------------
server / 3 controllers ── OTLP push ──▶ collector ──▶ metric store
  (application and runtime metrics)                         ▲
                                                            │
external lifecycle exporter ────────────────────────────────┘
  (condition-state metrics)                         Grafana dashboards + datasource
```

### Transport posture (documented, not hardened)

Identity serves no `/metrics`; the only listener is the API itself (`:6080`,
`pkg/server/options.go`). Metrics leave over OTLP/HTTP push, plain-text
(`WithInsecure`), reachable only as far as the collector endpoint it is pointed at.
The chart does not configure the externally operated lifecycle exporter. Transport
settings for that component are therefore outside this chart's scope. This posture
is stated in the chart README so an operator does not mistake the OTLP default-off
for a broken scrape.

## Dashboards (focused set, 2 + optional leadership)

Raw Grafana JSON under `charts/identity-observability/files/dashboards/*.json`.
The central profile provisions them for central Grafana; the workload profile
renders sidecar-labelled ConfigMaps (`grafana_dashboard: "1"`,
`grafana_folder: Identity`) only when a workload Grafana can query the central
metric store. They are otherwise absent from workload clusters.

Every dashboard has a top-level `cluster` selector and filters every panel on it.
The OTLP collector or scrape configuration must attach `cluster` before storage;
dashboard queries must not rely on Prometheus external labels, which are not
available to Grafana's local query path.

1. **Identity Operations** — resource lifecycle and controller health: count of
   Organization/Project/OAuth2Client with `Available != True` by `reason`
   (`uni_resource_error_reason`), time-in-provisioning from
   `uni_resource_state_timestamp_seconds{state="Provisioning"}`, per-kind
   provisioning-duration quantiles and outcomes
   (`uni_<kind>_provisioning_duration_seconds`), reconcile rate/error-rate/latency
   and workqueue depth per controller (controller-runtime, via OTLP), controller
   readiness and build revision for controllers, and pod memory/restarts for the
   four workloads. API server lifecycle gauges are not available yet.
2. **Identity Auth & Federation** — the auth
   path: `unikorn_identity_bearer_tokens_unroutable` by `surface`/`reason` and
   `unikorn_identity_auth0_jwks_refreshes_throttled` rate (the only first-party
   signals today), plus token-endpoint request rate by
   grant/route, the 401-untrusted-issuer vs 503-trust-cache-not-ready split, and
   latency quantiles. A logs panel (via the Loki datasource) scopes the audit and
   OAuth2 error lines alongside the metric panels.
3. **Identity Controller Leadership** *(opt-in)* — `leader_election_master_status`
   by lease name. It is rendered only when
   `grafana.dashboards.leaderElection.enabled=true`, because a dashboard without
   stored leader-election series is misleading.

Every panel query is checked against its producer contract (see Testing).

## Logs & tracing posture

- **Tracing:** identity installs a TracerProvider in all four binaries, but
  **export is off by default and there is no first-party instrumentation**. The
  batch exporter attaches only when `--otlp-endpoint` is set; the sampler defaults
  to `NeverSample`, so even with an endpoint configured **nothing is sampled until
  the ratio is raised above zero**. The only span producer is the HTTP server
  middleware (one server span per inbound request); identity's handlers, oauth2
  code, and reconcilers create no spans. Identity emits HTTP server-request spans
  **only when both `--otlp-endpoint` is set and the sampling ratio is greater than
  zero**, and it does not trace reconcile flows. This is **not** distributed
  tracing.
- **Metrics over OTLP:** the same setup installs a MeterProvider with a
  Prometheus→OTLP bridge over `ctrlmetrics.Registry`, plus the two `otel.Meter`
  counters. This is the **sole** metrics export path — gated on the endpoint only
  (no ratio gate), and emitting nothing when the endpoint is unset.
- **Logs:** `logr` over zap via controller-runtime; **console only**, no OTLP logs
  signal and no Loki client — identity ships no log-forwarding path. Trace-ID
  correlation is stamped into the request logger by the otel middleware. The audit
  middleware emits structured audit records as ordinary `Info("audit", ...)` log
  lines (`pkg/middleware/audit/logging.go:145`) — subject to the same console-only
  shipping, not a separate audit sink. The Loki datasource this chart adds wires
  Grafana to whatever Loki the cluster runs, so logs (including audit lines) are
  explorable alongside metrics; identity itself does not forward them.

## Implementation outline

Create `charts/identity-observability` (new chart, `unikorn-common` dependency):

1. `templates/grafana-dashboards.yaml` +
   `files/dashboards/{operations,auth,leader-election}.json` —
   ConfigMaps with the sidecar label, gated by `grafana.dashboards.enabled`. The
   leadership dashboard has its own opt-in gate.
2. `templates/grafana-loki-datasource.yaml` — datasource ConfigMap
   (`grafana_datasource: "1"`), gated by `lokiDatasource.enabled`.
3. `values.yaml` plus `values-central.yaml` and `values-workload.yaml` — the central
   profile enables the datasource and dashboard provisioning; the workload profile
   can enable only sidecar dashboards.
4. Chart `README.md` — the documented transport posture, the "healthy = absent
   series" and "`Available`-only / no `Healthy`" contract notes, the
   lifecycle-exporter availability caveat, the prerequisites and their order, and the
   logs/tracing posture.

No change to `charts/identity` except a short pointer in its README to this posture.

Patterns and sources to reuse:

- Metric names and labels: use Identity's metric producers and the documented
  external lifecycle-exporter contract.
- Condition/reason vocabulary: use the shared lifecycle contract's documented
  `Available` reasons, rather than inferring them from Identity type definitions.
- House style: use the chart's dashboard sidecar convention and datasource shape.

## Testing / verification

Identity validates its chart with a **bash** render harness
(`hack/check_chart_render.sh`, run by `make lint`):

1. **Rendered-chart checks** (extend `hack/check_chart_render.sh` or add a sibling):
   assert the dashboard and datasource ConfigMaps carry the expected labels; assert
   the workload profile has neither, workload dashboards remain opt-in, and **no
   ServiceMonitor is emitted** (identity owns none).
2. **Dashboard contract checks** — assert stable dashboard UIDs, one `cluster`
   selector per dashboard, and a cluster filter on every panel query. This prevents
   independent clusters from being combined in one view.
3. **End-to-end smoke** — with an external lifecycle exporter publishing
   `uni_resource_*` and Identity's `--otlp-endpoint` set in a development
   environment: confirm lifecycle, controller-runtime, and counter series arrive
   and that the two dashboards populate.
