#!/usr/bin/env bash
# Copyright 2026 Nscale.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

set -euo pipefail

chart=charts/identity-observability
central=$(helm template identity-observability "$chart" -f "$chart/values-central.yaml" --api-versions grafana.integreatly.org/v1beta1)
central_leadership=$(helm template identity-observability "$chart" -f "$chart/values-central.yaml" --set grafana.dashboards.leaderElection.enabled=true --api-versions grafana.integreatly.org/v1beta1)
workload=$(helm template identity-observability "$chart" -f "$chart/values-workload.yaml")

grep -q 'kind: GrafanaDashboard' <<<"$central"
grep -q 'grafana_datasource: "1"' <<<"$central"
grep -q 'grafana_folder: "UNI/Identity"' <<<"$central"
grep -q 'dashboard-auth' <<<"$central"

if grep -q 'dashboard-leader-election' <<<"$central"; then
	echo "leader-election dashboard must be opt-in" >&2
	exit 1
fi

if grep -qE 'dashboard-(collection-health|operations)' <<<"$central$central_leadership"; then
	echo "chart must render only complete dashboards" >&2
	exit 1
fi

grep -q 'dashboard-leader-election' <<<"$central_leadership"

if grep -qE 'GrafanaDashboard|grafana_datasource' <<<"$workload"; then
	echo "workload profile rendered a central-only asset" >&2
	exit 1
fi

if grep -qE 'PrometheusRule|ServiceMonitor' <<<"$central$workload"; then
	echo "identity observability must render dashboards and datasources only" >&2
	exit 1
fi

dashboard_uid_count=$(jq -r '.uid' "$chart"/files/dashboards/*.json | sort -u | wc -l | tr -d ' ')

if [[ "$dashboard_uid_count" -ne 2 ]]; then
	echo "identity dashboards must have two unique UIDs" >&2
	exit 1
fi

for dashboard in "$chart"/files/dashboards/*.json; do
	jq --exit-status '
		.id == null and
		(.uid | type == "string" and length > 0) and
		(.templating.list | length == 1) and
		.templating.list[0].name == "cluster" and
		.templating.list[0].type == "query" and
		(.panels | length > 0) and
		all(.panels[]; .id != null and .gridPos != null) and
		all(.panels[].targets[]; .expr | contains("cluster=~\"$cluster\""))
	' "$dashboard" >/dev/null
done

# The RED metric names are platform-generic (OTel HTTP server semantic
# conventions in their Prometheus-stored form), so every query must also be
# scoped to identity by job — the Prometheus-convention label the pipeline
# derives from the OTLP resource's service.name. The name alone no longer
# selects the service.
jq --exit-status '
	[.panels[].targets[].expr, .templating.list[0].query] as $expressions |
	all($expressions[]; contains("job=\"unikorn-identity\""))
' "$chart/files/dashboards/leader-election.json" >/dev/null

jq --exit-status '
	[.panels[].title] as $titles |
	all(
		"Request Rate",
		"5xx Error Rate",
		"4xx Error Rate",
		"p95 Latency",
		"Request Rate by Route",
		"Error Rate by Status Class",
		"5xx Rate by Route",
		"4xx Rate by Route",
		"p95 Latency by Route",
		"Latency Quantiles",
		"Active Requests by Route";
		. as $title | $titles | index($title)
	) and
	[.panels[].targets[].expr] as $expressions |
	any($expressions[]; contains("http_server_request_duration_seconds_count")) and
	any($expressions[]; contains("http_server_request_duration_seconds_bucket")) and
	any($expressions[]; contains("http_server_active_requests")) and
	all(($expressions + [.templating.list[0].query])[]; contains("job=\"unikorn-identity\""))
' "$chart/files/dashboards/auth.json" >/dev/null
