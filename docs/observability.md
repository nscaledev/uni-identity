# Identity observability design

## Context

This design brings the UNI `identity` service to the same operational-observability
*standard* as the management plane, following its ownership model: the application
chart emits/exports signals and minimal access primitives; a separately deployed
observability chart (`charts/identity-observability`, new) owns recording rules,
alerts, Grafana dashboards, and datasource wiring. It ports the *standard and the
ownership split*, not the reference's metric names or its alert count.

Identity is a long way *behind* the management-plane and nks-core baseline on the
**producer** side, and in a different shape, so the honest starting point matters:

- **There is no Prometheus scrape endpoint anywhere in identity.** All metrics
  leave via **OTLP push**, and only when `--otlp-endpoint` is set (it is unset by
  default — the one telemetry knob in the chart, `otlpEndpoint`, is commented
  out). The export path is `core/pkg/options/options.go:SetupOpenTelemetry`,
  shared across all four binaries. With no endpoint configured the MeterProvider
  has no reader and **nothing is exported at all**.
- **The first-party metric surface is two counters**, both OTel
  `Int64Counter` created via `otel.Meter(constants.Application)`:
  `unikorn_identity_bearer_tokens_unroutable{surface,reason}`
  (`pkg/oauth2/oauth2.go:174`, incremented in `pkg/oauth2/passport.go:262,272,279`)
  and `unikorn_identity_auth0_jwks_refreshes_throttled`
  (`pkg/oauth2/auth0/throttled_transport.go:72`).
- **There is no HTTP RED middleware.** The server middleware chain
  (`pkg/server/server.go:110-124`) produces OpenTelemetry *spans* only; there is
  no request-count / duration / in-flight metric. Identity's primary job — the
  OAuth2/OIDC token surface — is therefore essentially unobservable in metrics
  today.
- **The three controllers** (organization, project, oauth2client) register the
  controller-runtime built-ins (`controller_runtime_reconcile_*`, `workqueue_*`,
  `rest_client_*`, Go/process collectors) on the shared registry, bridged to OTLP
  via `prombridge`. **The API server runs no manager**, so it has none of these —
  only the two counters.
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
- **Object-state signals:** adopt the platform's existing state exporter,
  `uni-state-metrics` (sibling repo `github.com/unikorn-cloud/uni-state-metrics`),
  as the source of condition-based lifecycle metrics — **after identity's kinds are
  added to it** (a named cross-repo prerequisite; see "Prerequisites"). This keeps
  identity on the platform-standard mechanism rather than inventing a new one.
- **Breadth:** a focused, high-signal set (3 dashboards, ~5 alert groups), not the
  reference's 7-dashboard / 160-plus-alert surface.
- **Ownership:** a new `charts/identity-observability` chart owns rules,
  dashboards, and the datasource. Identity's existing single chart
  (`charts/identity`) is unchanged except for documenting the posture.

The gap this design closes is the *assets* side: there is no PrometheusRule, no
recording rules, no dashboards, no datasource, and no render/promtool validation
for identity anywhere. What it cannot close on its own is the producer gap on the
API surface — that is called out explicitly rather than papered over (see "Producer
gaps").

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
`core/pkg/manager/manager.go` leaves `manager.Options.Metrics` at default, so the
default registry is active and bridged to OTLP by
`prombridge.NewMetricProducer(WithGatherer(ctrlmetrics.Registry))`
(`core/pkg/options/options.go:96-115`).

- `controller_runtime_reconcile_total{controller,result}`,
  `controller_runtime_reconcile_errors_total{controller}`,
  `controller_runtime_reconcile_time_seconds{controller}`
- `workqueue_*{name}`, `rest_client_requests_total{code,method,host}`
- Go/process collectors (`go_*`, `process_*`), controller-runtime
  leader-election gauge

**API server** — no controller-runtime manager, so **none** of the above; only the
two counters.

**HTTP RED** — **absent.** No request-count/duration/in-flight metric exists.

**State / kube-state exporter (in identity)** — **absent.**

**build_info / component_ready / readiness gauge** — **absent.**
`core/pkg/manager/readiness.go` only logs; it emits no metric.

### The object-state contract identity would inherit from `uni-state-metrics`

`uni-state-metrics` is a central, **single-replica, leaderless** controller-runtime
operator (`charts/state-metrics`, `replicas: 1`, no leader election) that serves a
**Prometheus scrape** endpoint on `:8080/metrics` (plain HTTP). It ships a
ServiceMonitor gated behind `prometheus.enabled` (default **false**) with
`honorLabels: true` and a `labeldrop` of `(container|endpoint|instance|job|pod|service)`.

It watches a **compiled-in** set of region/storage/reservation/compute kinds — there
is no GVK or condition config surface — and **covers none of identity's CRDs
today**. The contract it emits, which identity's lifecycle alerting would adopt once
identity kinds are added following the same pattern, is:

- `uni_resource_error_reason{kind,namespace,name,reason,flavor_id}` — gauge set to
  `1` **only while a resource's `Available` condition is not `True`**
  (`internal/metrics/resource.go:60-68`). `reason` is passed through verbatim from
  the condition (no allowlist, no collapse to `Other`); `flavor_id` is empty for
  identity kinds. Healthy resources have **no series**, and the reconciler `Clear`s
  the family each pass, so recovery *deletes* the series.
- `uni_resource_state_timestamp_seconds{kind,state,namespace,name}` — Unix
  timestamp of when the resource entered a tracked `state`; present only while in
  it. The `state` allowlist is `Provisioning` and `Deprovisioning` (plus
  compute-only `Active` reasons that do not apply to identity). **`Errored` is not
  a tracked state**, so there is a provisioning/deprovisioning entry-time but no
  error entry-time.
- `uni_<kind>_provisioning_duration_seconds{outcome,...}` — per-kind histogram,
  Provisioning→terminal, buckets 1s…3600s. Emitted per controller, so identity
  kinds added to the exporter would each get one.

There are **no** `_info`, `_created`, `_deletion_timestamp`, `_metadata_generation`,
`_status_observed_generation` families, and **no self-health metrics**
(`collection_success`, `last_success_timestamp`): the exporter's only
self-observability is the controller-runtime built-ins on its own registry.

## Adapting each operational purpose — adopt / adapt / rebut

Each reference theme is marked **ADOPT** (applies, keep), **ADAPT** (applies in
spirit, reshaped to identity), or **REBUT** (does not apply). The rebuts matter as
much as the adopts: they stop the design importing alerts for subsystems identity
does not have.

| Reference theme | Verdict | Identity treatment |
| --- | --- | --- |
| Management-plane health & lifecycle | **ADAPT** | Lifecycle health = the `Available` condition of Organization/Project/OAuth2Client, observed through `uni_resource_error_reason` (present only while `Available != True`) once identity is added to `uni-state-metrics`. "Time stuck provisioning" uses `uni_resource_state_timestamp_seconds{state="Provisioning"}`; "time errored" uses the rule `for:` window (there is no `Errored` state timestamp). Healthy = series absent, so alerts assert *presence*, not `status="False"`. |
| Rollout & recovery safety | **REBUT** | Identity has no release/rollout, etcd, host-image, or disruption-budget concept. |
| OpenStack dependency health | **REBUT → ADAPT** | Identity calls no OpenStack. Its runtime dependencies are the **Kubernetes API** (system of record) and **upstream OIDC/OAuth2 IdPs** (Google/Microsoft/GitHub federation + their JWKS). These surface on the API path: trust-cache-not-ready → HTTP 503, untrusted issuer → HTTP 401 (`pkg/oauth2/trustlist.go:52-60`), plus the `jwks_refreshes_throttled` and `bearer_tokens_unroutable` counters. The 401/503 split needs HTTP RED to be alertable (see "Producer gaps"); the two counters are available today. |
| Endpoint & load-balancer path | **REBUT** | Identity serves one HTTP API behind the platform ingress; no LB/endpoint lifecycle. |
| Host Runtime Service / MCPI / Canary | **REBUT** | None of these components exist in identity. |
| Collector & host resource safety | **ADAPT** | Self-observability of the collection path. Identity's analogue is two pipelines: (a) `uni-state-metrics`, a central **single-replica** exporter whose absence blanks *every* identity condition series — a first-class alert; (b) the **OTLP export pipeline**, which emits nothing unless `--otlp-endpoint` is set. Plus controller-runtime reconcile health and pod memory/OOM/restarts for the four workloads. |
| Security, PKI & audit | **REBUT → ADAPT** | Identity *is* the trust root/PKI. Metrics are plain HTTP, so there is no serving-cert expiry to watch. Token signing (ES512, two-key rotation) runs in the jose issuer's own leader-elected loop (`pkg/jose/jose.go`, a `coordination/v1` Lease) — **rotation failure is observable only in logs today**, a stated gap. Audit is the audit middleware (`pkg/middleware/audit/logging.go:145`) emitting structured log lines, not a metric or separate sink. |
| Snapshot & retention | **REBUT** | Identity takes no snapshots. |
| Capacity & platform hygiene | **ADAPT (light)** | Pod memory/OOM/FD/restarts for the four workloads from the controller-runtime process collectors (via OTLP). **Object-population counts are *not* available** from `uni_resource_error_reason` — it emits series only for *unhealthy* resources, so it cannot count healthy orgs/projects. Population counting would need a new `_info`-style family (out of scope). |
| Scrape plumbing | **REBUT → ADAPT** | Identity exposes no scrape targets, so there is **no identity `up` series and no ServiceMonitor target-membership check**. The only `up` in scope is `uni-state-metrics`' own. Identity binary liveness is inferred from its OTLP series arriving (and from Kubernetes pod state), not from `up`. |

Cross-cutting rules adopted: bounded, operationally-useful labels only (already true
— the two counters are bounded; the `uni-state-metrics` contract is bounded by
object count plus the core reason enum, and carries **no external IDs** —
`organization_id`/`project_id` do not appear, so its `/metrics` surface is far less
tenant-sensitive than nks-core's `_info` families). Also adopted: explicit
absence/vanished-target handling, the severity contract with runbooks, and
opt-in/heartbeat gating of any rule class whose underlying series are not always
present.

## Metric contract — adopt vs rebut the reference's metrics

The reference's own metric names (`nks_controller_manager_*`, MCPI/etcd/OpenStack
families) are all rebutted — they belong to different producers. The adopted
contract for identity is:

- **Adopt the two first-party counters** as the auth-path signal
  (`unikorn_identity_bearer_tokens_unroutable`,
  `unikorn_identity_auth0_jwks_refreshes_throttled`). Bounded, already discipline-clean.
- **Adopt the controller-runtime built-ins** for the three controllers as the
  reconcile-health and capacity signal. These arrive via the OTLP bridge, not a
  scrape.
- **Adopt the `uni-state-metrics` `uni_resource_*` contract** for
  Organization/Project/OAuth2Client lifecycle — *conditional on the prerequisite
  below*. Query hazards to bake into rules and dashboards:
  - **Healthy = absent series.** `uni_resource_error_reason` exists only while
    `Available != True`. Rules must assert the *presence* of the series for a `for:`
    window (optionally with a `reason` filter), never `== 0` or `status="False"`
    (there is no `status` label). Recovery is the series disappearing. Use
    `absent()` carefully: `absent(metric)` is true both when every resource is
    healthy **and** when the exporter is down — the two are told apart only by the
    exporter's own `up`.
  - **Only the `Available` condition is exported.** The exporter reads `Available`
    and nothing else. Organization and Project *do* set a `Healthy` condition
    (`pkg/provisioners/{organization,project}/provisioner.go`) and OAuth2Client
    does not — but **none of them reach Prometheus**. Alerts and dashboards must key
    on `Available` reasons only; a query keyed on `Healthy`, `Active`, or `Ready`
    matches nothing. Guard this with the query-vs-contract lint (see "Testing").
  - **The `reason` label is the generic core reason.** The `Available` reason is
    set generically by the core reconciler (`core/pkg/manager/reconcile.go`), not by
    identity: `Provisioning`, `Provisioned`, `Errored` (generic message "an
    unexpected error occurred"), `Deprovisioning`, `Deprovisioned`, and the
    dependency reasons `DependencyNotReady`/`DependencyFailed`/`DependencyNotFound`
    (reached via the typed-error enrichment). So `Errored` alone cannot say *why* it
    errored, but the `Dependency*` reasons *are* distinguishable and worth their own
    alert. There is no `Cancelled` on the `Available` axis (a cancelled reconcile
    leaves the condition untouched). This is the identity analogue of the
    "collapsed reasons" trap: the per-reason richness that would need a new producer
    metric is the distinction *within* `Errored`, which identity does not expose.
  - **Label shape.** `uni-state-metrics` emits bare `namespace`/`name`, and its own
    ServiceMonitor already sets `honorLabels: true` and drops `instance`/`pod`/etc.,
    so the `exported_namespace` collision does not arise — but that ServiceMonitor
    is owned by the `uni-state-metrics` chart, **not** by `identity-observability`.
    Rules group on `namespace`/`name`; fixtures use the bare-`namespace` stored
    shape.

No new identity producer metric is proposed as *required* here (unlike nks-core,
which needed a per-reason terminal gauge). The producer gaps below are flagged as
recommended follow-ups, not prerequisites of this assets work — except the two
pipeline prerequisites, which are what make any of these series exist at all.

### Producer gaps (recommended, not shipped here)

1. **HTTP RED on the API server.** Identity's core job (the OAuth2/token surface)
   has no request metrics. A bounded RED middleware on the server
   (`unikorn_identity_http_requests_total{route,method,status_class}` +
   a duration histogram, route templated from the OpenAPI path) would make the
   401/503 federation split, the token-endpoint error rate, and latency alertable.
   This is the single highest-value producer addition and is assumed by the
   `api-red` alert group and the Auth dashboard, both of which are therefore marked
   *conditional*.
2. **Signing-key rotation signal.** The jose rotation loop is observable only in
   logs. A small bounded gauge (e.g. active signing-key count / next-rotation age)
   would let a stalled rotation page before tokens fail verification.
3. **`uni-state-metrics` coverage of identity kinds.** See prerequisites — this is
   what turns the lifecycle section from design into live series.

## Prerequisites (cross-repo, with merge order)

Unlike the reference's single-repo chart split, identity's suite depends on two
changes *outside* this repo. Name them, and their order, explicitly:

1. **`uni-state-metrics` gains identity coverage.** Add the identity scheme import,
   per-kind controllers for Organization/Project/OAuth2Client (or a generic
   unstructured watcher), and the matching `identity.unikorn-cloud.org`/
   `unikorn-cloud.org` RBAC in its ClusterRole. Then its deployment must set
   `prometheus.enabled=true` so the Service + ServiceMonitor exist and the
   `uni_resource_*` series are scraped. **Until this lands, the entire
   resource-lifecycle and collection-path alert groups have no series and must be
   gated off** (`prometheusRules.stateMetrics.enabled`, default false).
2. **Identity binaries get `--otlp-endpoint` set** in the deployment, pointing at
   the collector that relays to the backend the rules/dashboards query. Until then
   the two counters and the controller-runtime built-ins are not exported, and the
   `reconcile-health` and `auth-path` groups have no series.
3. **Then** deploy `charts/identity-observability` (this work).

The alert-evaluation topology (which Prometheus/Mimir ruler evaluates the rules, and
whether the `uni-state-metrics` scrape and the OTLP relay land in the *same* store
the rules read) must be confirmed against the deployment repo before enabling the
rules — identity is a single central service, so this is expected to be one store,
but the design does not assume it. Recording rules consumed by central dashboards
must run wherever those dashboards query, exactly as in the nks-core topology.

## Ownership & scrape path

New chart `charts/identity-observability` (its own `Chart.yaml`, depending on
`unikorn-common` for the shared label helpers, mirroring `charts/identity`). One
owner per asset class:

| Asset | Owner | Consumed by |
| --- | --- | --- |
| PrometheusRule (recording + alerts) | `identity-observability` | the cluster Prometheus/Mimir ruler; Alertmanager routes alerts (`release:` label) |
| Grafana dashboards | `identity-observability` | Grafana dashboard sidecar (ConfigMaps, `grafana_dashboard: "1"`) |
| Grafana Loki datasource | `identity-observability` | Grafana datasource sidecar (`grafana_datasource: "1"`) |
| ServiceMonitors | **none** | identity pushes via OTLP; the only identity-related scrape target is owned by the `uni-state-metrics` chart |
| metrics-reader RBAC | **n/a** | this chart scrapes nothing |

```text
Identity workloads                              Observability backend
------------------                              ---------------------
server / 3 controllers  ── OTLP push (gated ──▶ collector ──▶ metric store
  (2 counters + CR         on --otlp-endpoint)                   ▲
   built-ins via bridge)                                         │
                                                                 │ scrape
uni-state-metrics :8080/metrics ── ServiceMonitor ──▶ Prometheus ┘
  (identity condition series,        (its own chart,        │
   once identity kinds added,         honorLabels:true)     └─ PrometheusRule (this chart)
   prometheus.enabled=true)                                    Grafana dashboards + datasource
```

### Transport posture (documented, not hardened)

Identity serves no `/metrics`; the only listener is the API itself (`:6080`,
`pkg/server/options.go`). Metrics leave over OTLP/HTTP push, plain-text
(`WithInsecure`), reachable only as far as the collector endpoint it is pointed at.
`uni-state-metrics` serves plain-HTTP `/metrics` on a cluster-internal port. The
reference's `insecureSkipVerify`/CA/per-instance-FQDN SAN knobs are therefore
**not applicable** and are deliberately absent. This posture is stated in the chart
README so an operator does not go looking for a TLS knob that should not exist, and
so no one mistakes the OTLP default-off for a broken scrape.

## Dashboards (focused set, 3)

Raw Grafana JSON under `charts/identity-observability/files/dashboards/*.json`, each
rendered into a sidecar-labelled ConfigMap (`grafana_dashboard: "1"`,
`grafana_folder: Identity`), gated by `grafana.dashboards.enabled`.

1. **Identity Operations** — resource lifecycle and controller health: count of
   Organization/Project/OAuth2Client with `Available != True` by `reason`
   (`uni_resource_error_reason`), time-in-provisioning from
   `uni_resource_state_timestamp_seconds{state="Provisioning"}`, per-kind
   provisioning-duration quantiles and outcomes
   (`uni_<kind>_provisioning_duration_seconds`), reconcile rate/error-rate/latency
   and workqueue depth per controller (controller-runtime, via OTLP), and pod
   memory/restarts for the four workloads. Active alerts panel.
2. **Identity Auth & Federation** *(partly conditional on HTTP RED)* — the auth
   path: `unikorn_identity_bearer_tokens_unroutable` by `surface`/`reason` and
   `unikorn_identity_auth0_jwks_refreshes_throttled` rate (the only first-party
   signals today), plus — once RED lands — token-endpoint request rate by
   grant/route, the 401-untrusted-issuer vs 503-trust-cache-not-ready split, and
   latency quantiles. A logs panel (via the Loki datasource) scoped to the audit
   and OAuth2 error lines fills the gap until RED exists. Panels with no producer
   yet are labelled as pending the RED addition, not left as silently empty graphs.
3. **Identity Collection & Pipeline Health** — the two collection pipelines:
   `uni-state-metrics` `up` and its `controller_runtime_reconcile_errors_total`
   (single-replica SPOF), whether identity's own OTLP series are arriving and fresh,
   controller-runtime leader-election state for the three controllers, and a clear
   "OTLP endpoint configured?" indicator derived from series presence. States the
   jose signing-key rotation as logs-only until a producer metric exists.

Every panel query is checked against its producer contract (see Testing).

## Alerts & recording rules (focused set)

One PrometheusRule gated on `prometheusRules.enabled`, adopted into the cluster
Prometheus via `prometheusRules.labels` (`release:`). House style adopted from the
reference: PascalCase `Identity`-prefixed alert names; every rule carries `severity`
(critical/warning/info) + `owner: identity`; annotations `summary`, `description`
(with a drill-down query), and `runbook_url` for pageable alerts pointing at
`docs/runbooks/*.md`; recording rules named `identity:<subsystem>:<metric>`. A header
comment states the severity contract (critical = page now; warning = working hours;
info = never paged) and the caveat that a rendered alert does not prove anyone is
paged — routing lives in the Alertmanager config outside this repo.

Groups whose series depend on a prerequisite are gated so they are **templated out
of the default render** until the prerequisite is met, rather than shipped firing or
vacuously silent:

- **collection-path** *(gated `stateMetrics.enabled`)* —
  `IdentityStateMetricsExporterDown` (`up{job=~".*state-metrics.*"} == 0`, plus an
  `absent(uni_resource_error_reason{...})` companion for the vanished-target case),
  and `IdentityStateMetricsReconcileStale`
  (`rate(controller_runtime_reconcile_errors_total[...])` on the state-metrics
  controllers, or no successful reconcile for too long). **Critical:** the exporter
  is a single leaderless replica, so while it is down every identity condition
  series is silently absent and the lifecycle group goes blind.
- **resource-lifecycle** *(gated `stateMetrics.enabled`)* —
  `IdentityResourceErrored`
  (`uni_resource_error_reason{kind=~"organization|project|oauth2client",reason="Errored"}`
  present for its `for:` window), `IdentityResourceDependencyUnmet`
  (`reason=~"DependencyFailed|DependencyNotFound"`, a distinct and separately
  actionable fault), and `IdentityResourceProvisioningStuck`
  (`reason="Provisioning"` **and** `time() - uni_resource_state_timestamp_seconds{state="Provisioning"}`
  over a threshold). All assert *presence* (healthy = absent); all exclude
  `Deprovisioning` churn. None key on `Healthy`/`Active`/`Ready` — those are not
  exported.
- **reconcile-health** *(gated `otlp.enabled`)* —
  `IdentityControllerReconcileErrorsHigh`
  (`rate(controller_runtime_reconcile_errors_total[...])` by `controller`) and
  `IdentityControllerWorkqueueBacklog` (sustained `workqueue_depth`). Covers the
  three identity controllers.
- **auth-path** *(gated `otlp.enabled`)* — `IdentityUnroutableTokensElevated`
  (`rate(unikorn_identity_bearer_tokens_unroutable[...])` by `surface`/`reason`) and
  `IdentityJWKSRefreshThrottledSustained`
  (`rate(unikorn_identity_auth0_jwks_refreshes_throttled[...])` — upstream IdP JWKS
  being hammered or unreachable). Warning/info: these are the only first-party API
  signals that exist today.
- **api-red** *(gated `httpRed.enabled`, default false — depends on the RED producer
  addition)* — `IdentityAPIHighErrorRate` (5xx ratio by route),
  `IdentityTrustCacheUnavailable` (sustained 503 on the auth routes), and
  `IdentityAPILatencyHigh`. These double as the UNI-federation-failure signal.
  Shipped disabled with the producer gap documented, so the group is ready the day
  RED lands rather than being forgotten.

Recording rules normalise the reconcile-error ratios and the unhealthy-resource
counts by `kind`/`reason` so alert expressions and dashboards share one definition;
the `api-red` ratios are defined the same way under the same gate.

Absence handling is explicit throughout (`absent()` / `up == 0` companions), with
the documented caveat that `absent(uni_resource_error_reason)` is ambiguous between
"all healthy" and "exporter down" and must be paired with the exporter `up`.

## Logs & tracing posture

- **Tracing:** identity installs a TracerProvider in all four binaries via the
  shared `core` setup, but **export is off by default and there is no first-party
  instrumentation**. The batch exporter attaches only when `--otlp-endpoint` is set;
  the sampler is independent and defaults to `NeverSample` (`--trace-sampling-ratio`
  default `0.0` → `trace.NeverSample()` in `core/pkg/options/options.go`), so even
  with an endpoint configured **nothing is sampled until the ratio is raised above
  zero**. The only span producer is the vendored HTTP server middleware (one server
  span per inbound request); identity's handlers, oauth2 code, and reconcilers
  create no spans, and context is propagated to downstream services. The honest
  statement: identity emits HTTP server-request spans **only when both
  `--otlp-endpoint` is set and the sampling ratio is greater than zero**, and it
  does not trace reconcile flows. This is **not** distributed tracing.
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

1. `templates/prometheus-rules.yaml` — one PrometheusRule, the groups above, gated
   by `prometheusRules.enabled`; the prerequisite-dependent groups
   (`stateMetrics.enabled`, `otlp.enabled`, `httpRed.enabled`) templated out of the
   default render until their series exist.
2. `templates/grafana-dashboards.yaml` +
   `files/dashboards/{operations,auth,collection-health}.json` — ConfigMaps with the
   sidecar label, gated by `grafana.dashboards.enabled`.
3. `templates/grafana-loki-datasource.yaml` — datasource ConfigMap
   (`grafana_datasource: "1"`), gated by `lokiDatasource.enabled`.
4. `values.yaml` — `prometheusRules.{enabled,labels}`, the three prerequisite gates,
   threshold knobs the rules reference (provisioning-stuck age, error-rate windows),
   `grafana.dashboards.{enabled,label,folder}`, `lokiDatasource.{enabled,url,...}`.
5. Chart `README.md` — the documented transport posture, the "healthy = absent
   series" and "`Available`-only / no `Healthy`" contract notes, the
   single-replica-SPOF caveat, the prerequisites and their order, and the
   logs/tracing posture.
6. `docs/runbooks/*.md` — one per pageable alert; the harness verifies each
   `runbook_url` resolves to a real file.

No change to `charts/identity` except a short pointer in its README to this posture.

Patterns and sources to reuse:

- Metric names/labels to target: `pkg/oauth2/oauth2.go`, `pkg/oauth2/passport.go`,
  `pkg/oauth2/auth0/throttled_transport.go`; controller-runtime families via the
  OTLP bridge; `uni-state-metrics` `internal/metrics/{resource,state_timestamp,provisioning}.go`.
- Condition/reason vocabulary for expressions: the core
  `ProvisioningConditionReason` enum in
  `core/pkg/apis/unikorn/v1alpha1/types.go` and the set-site
  `core/pkg/manager/reconcile.go` — **not** identity's own type files, which do not
  write the reason.
- House style (severity contract header, dashboard sidecar convention, datasource
  shape, two-render promtool harness): the reference
  `nks-management-plane-observability` chart and its
  `hack/test-observability-rules.sh`.

## Testing / verification

Identity currently validates its chart with a **bash** render harness
(`hack/check_chart_render.sh`, run by `make lint`); there is no Go chart test and
**promtool is not used anywhere**. Mirror the reference's two-surface harness,
scaled down, in the same bash idiom:

1. **Rendered-chart checks** (extend `hack/check_chart_render.sh` or add a sibling):
   assert the PrometheusRule renders when `prometheusRules.enabled` and is absent
   when disabled; assert the prerequisite-gated groups are **absent from the default
   render** and present only when their flag is set; assert the dashboard and
   datasource ConfigMaps carry the sidecar labels; assert **no ServiceMonitor is
   emitted** (identity owns none).
2. **promtool rule tests** — a new `hack/test-observability-rules.sh` +
   `make test-observability-rules` target and CI job: `helm template` twice
   (default and all-prerequisites-on), extract `spec.groups`, run
   `promtool check rules --lint-fatal`, then `promtool test rules` over
   `tests/*.test.yaml`. Each fixture's `input_series` uses the **real stored label
   shape** — bare `namespace`, the `uni_resource_error_reason` label set, value `1`.
   Edge fixtures that would catch the traps in this design:
   - a resource unhealthy only as generic `reason="Errored"` (no richer reason
     present) — `IdentityResourceErrored` fires, no per-reason claim made;
   - a resource that *recovers* mid-window (series disappears) — the lifecycle alert
     resolves, proving the presence-not-`status=False` logic;
   - a query keyed on a `Healthy`/`Active`/`Ready` condition — must match **no
     series** (the exporter emits only `Available`);
   - the exporter down: `up == 0` with `absent(uni_resource_error_reason)` — the
     collection-path alert fires and the lifecycle alert does **not** masquerade as
     "all healthy";
   - `reason="Provisioning"` with a fresh vs stale `uni_resource_state_timestamp_seconds`
     — `IdentityResourceProvisioningStuck` fires only past the age threshold;
   - a runbook-URL resolution check for every pageable alert.
3. **Query-vs-contract lint** — a step confirming every metric name **and**
   `reason` label value used in a rule or dashboard exists in the adopted contract
   (`uni_resource_*` with `Available`-only and the core reason enum; the two
   counters with their bounded labels; the controller-runtime families). This is the
   guard that keys on `Healthy` or an unexported family can never ship.
4. **End-to-end smoke** — with identity added to `uni-state-metrics`
   (`prometheus.enabled=true`) and identity's `--otlp-endpoint` set against a dev
   cluster: confirm the `uni_resource_*` series appear for a created
   Organization/Project, that the controller-runtime and counter series arrive over
   OTLP, that Prometheus loads the rules, and that the three dashboards populate.

promtool must be installed for the rule tests; if unavailable in a sandbox, report
it as unverified rather than passing.
