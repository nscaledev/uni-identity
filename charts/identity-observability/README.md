# Identity observability

This chart owns Identity dashboards and the central Loki datasource.
It owns no ServiceMonitor: the platform-owned PodMonitor scrapes Identity.

Use `values-central.yaml` in the central observability cluster. It renders dashboards
and the datasource. `values-workload.yaml` renders no datasource; enable its
dashboards only when workload Grafana queries the central Identity metric store.

Set `grafana.dashboards.leaderElection.enabled` only when the metric store receives
the controllers' leader-election metrics. It adds the optional leadership dashboard.

Dashboards are provisioned in the `UNI/Identity` Grafana folder.

Every dashboard filters on the required `cluster` and `app` labels. The
platform PodMonitor must copy the pod `app` label to each target before metrics
reach the store. Identity's metrics use platform-generic names (the OTel HTTP
server semantic conventions for the RED families), so dashboard queries scope
the API to `app="unikorn-identity-server"` and controller metrics to
`app=~"unikorn-identity-.*"`. The scraper owns `job` and `instance`; neither
is a dashboard contract.
