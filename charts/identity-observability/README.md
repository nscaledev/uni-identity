# Identity observability

This chart owns Identity's Grafana dashboards and nothing else: no datasources
and no ServiceMonitor. The platform-owned PodMonitor scrapes Identity.

The chart carries no deployment details; the deploying repository supplies
them. Set `grafana.dashboards.enabled` and choose a `provisioningMode`:

- `sidecar` (default) renders ConfigMaps labelled for the Grafana dashboard
  sidecar (`grafana.dashboards.label`).
- `operator` also renders a `GrafanaDashboard` per dashboard for
  grafana-operator. `grafana.dashboards.instanceSelector` is required, and
  rendering fails without it.

`grafana.dashboards.namespace` defaults to the release namespace.

Set `grafana.dashboards.leaderElection.enabled` only when the metric store receives
the controllers' leader-election metrics. It adds the optional leadership dashboard.

Dashboards are provisioned in the `UNI/Identity` Grafana folder.

Every dashboard filters on `cluster` and on `service="unikorn-identity"`, which
core sets in code on every series identity serves. Identity's metrics use
platform-generic names (the OTel HTTP server semantic conventions for the RED
families), so the label, not the metric name, selects identity. Core's
`docs/metrics.md` defines which labels dashboards can rely on.
