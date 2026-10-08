# Identity observability

This chart owns Identity dashboards and the central Loki datasource.
It owns no ServiceMonitor: Identity exports metrics through OTLP.

Use `values-central.yaml` in the central observability cluster. It renders dashboards
and the datasource. `values-workload.yaml` renders no datasource; enable its
dashboards only when workload Grafana queries the central Identity metric store.

Set `grafana.dashboards.leaderElection.enabled` only when the metric store receives
the controllers' leader-election metrics. It adds the optional leadership dashboard.

Dashboards are provisioned in the `UNI/Identity` Grafana folder.

Every dashboard filters on the required `cluster` and `job` labels. OTLP
collectors and scrape configurations must attach `cluster` and preserve the
Prometheus-convention OTLP mapping — `job` from the resource's `service.name`,
`instance` from `service.instance.id` — before metrics reach the store, so
local and central queries have the same label shape. (A pipeline that scrapes
a collector's Prometheus exporter needs `honorLabels: true`, or `job` arrives
renamed to `exported_job`.) Identity's metrics use platform-generic names (the
OTel HTTP server semantic conventions for the RED families), so
`job="unikorn-identity"` — set by the identity chart via `OTEL_SERVICE_NAME` —
is what scopes a query to Identity.
