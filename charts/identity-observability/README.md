# Identity observability

This chart owns Identity dashboards and the central Loki datasource.
It owns no ServiceMonitor: the platform-owned PodMonitor scrapes Identity.

Use `values-central.yaml` in the central observability cluster. It renders dashboards
and the datasource. `values-workload.yaml` renders no datasource; enable its
dashboards only when workload Grafana queries the central Identity metric store.

Set `grafana.dashboards.leaderElection.enabled` only when the metric store receives
the controllers' leader-election metrics. It adds the optional leadership dashboard.

Dashboards are provisioned in the `UNI/Identity` Grafana folder.

Every dashboard filters on `cluster` and on `service="unikorn-identity"`, which
core sets in code on every series identity serves. Identity's metrics use
platform-generic names (the OTel HTTP server semantic conventions for the RED
families), so the label, not the metric name, selects identity. Core's
`docs/metrics.md` defines which labels dashboards can rely on.
