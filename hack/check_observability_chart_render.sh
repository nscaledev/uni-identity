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

render() {
	helm template identity-observability "$chart" --set grafana.dashboards.enabled=true "$@"
}

# Nightly builds package the chart with a long version; label values must
# still fit Kubernetes' 63 character limit.
package_dir=$(mktemp -d)
trap 'rm -rf "$package_dir"' EXIT
helm package "$chart" --version 0.0.0-20261109020146-f8762e84be7f -d "$package_dir" >/dev/null
nightly=$(helm template unikorn-identity-observability "$package_dir"/*.tgz --set grafana.dashboards.enabled=true)

if grep -E '^ +(helm\.sh/chart|app\.kubernetes\.io/[a-z-]+): ' <<<"$nightly" | awk '{ if (length($2) > 63) { print; bad = 1 } } END { exit !bad }' >&2; then
	echo "label values must be 63 characters or fewer" >&2
	exit 1
fi

# The selector is a placeholder: deployments supply their own.
operator_args=(--set grafana.dashboards.provisioningMode=operator --set grafana.dashboards.instanceSelector.matchLabels.example=identity)

defaults=$(helm template identity-observability "$chart")
sidecar=$(render)
operator=$(render "${operator_args[@]}")
operator_leadership=$(render "${operator_args[@]}" --set grafana.dashboards.leaderElection.enabled=true)
legacy_leadership=$(render "${operator_args[@]}" --set-json grafana.dashboards.leaderElection=null)

if [[ -n "$defaults" ]]; then
	echo "chart must render nothing unless dashboards are enabled" >&2
	exit 1
fi

grep -q 'grafana_dashboard: "1"' <<<"$sidecar"
if grep -q 'kind: GrafanaDashboard' <<<"$sidecar"; then
	echo "sidecar mode must not render GrafanaDashboard resources" >&2
	exit 1
fi

grep -q 'kind: GrafanaDashboard' <<<"$operator"
grep -q 'example: identity' <<<"$operator"
grep -q 'grafana_folder: "UNI/Identity"' <<<"$operator"
grep -q 'dashboard-uni-identity-api' <<<"$operator"
grep -q 'uni-identity-api.json' <<<"$operator"
grep -q 'dashboard-uni-identity-operations' <<<"$operator"
grep -q 'uni-identity-operations.json' <<<"$operator"
grep -q 'dashboard-uni-identity-leases' <<<"$operator"
grep -q 'uni-identity-leases.json' <<<"$operator"

# An empty selector would hand the dashboards to whichever Grafana
# instances the operator matches, so operator mode must name one.
if missing_selector=$(render --set grafana.dashboards.provisioningMode=operator 2>&1); then
	echo "operator mode must fail without an instanceSelector" >&2
	exit 1
fi
grep -q 'grafana.dashboards.instanceSelector is required' <<<"$missing_selector"

if grep -q 'dashboard-leader-election' <<<"$operator"; then
	echo "leader-election dashboard must be opt-in" >&2
	exit 1
fi

if grep -q 'dashboard-leader-election' <<<"$legacy_leadership"; then
	echo "legacy values must leave leader-election disabled" >&2
	exit 1
fi

if grep -q 'dashboard-collection-health' <<<"$operator$operator_leadership"; then
	echo "chart must not render the removed collection-health dashboard" >&2
	exit 1
fi
grep -q 'dashboard-leader-election' <<<"$operator_leadership"

if grep -qE 'PrometheusRule|ServiceMonitor|grafana_datasource' <<<"$sidecar$operator_leadership"; then
	echo "identity observability must render dashboards only" >&2
	exit 1
fi

dashboard_uid_count=$(jq -r '.uid' "$chart"/files/dashboards/*.json | sort -u | wc -l | tr -d ' ')

if [[ "$dashboard_uid_count" -ne 4 ]]; then
	echo "identity dashboards must have four unique UIDs" >&2
	exit 1
fi

for dashboard in "$chart"/files/dashboards/*.json; do
	jq --exit-status '
		.id == null and
		(.uid | type == "string" and length > 0) and
		([.templating.list[].name] == ["datasource", "cluster"]) and
		.templating.list[1].type == "query" and
		(.panels | length > 0) and
		all(.panels[]; .id != null and .gridPos != null) and
		all(.panels[].targets[]; .expr | contains("cluster=~\"$cluster\""))
	' "$dashboard" >/dev/null
done

# Each Grafana picks its own Prometheus through the datasource variable, so
# its regex and default stay empty, and every panel, target and query
# variable must use it rather than fall back to Grafana's default.
for dashboard in "$chart"/files/dashboards/*.json; do
	if ! jq --exit-status '
		(.templating.list[0] |
			.type == "datasource" and .query == "prometheus" and
			.regex == "" and .current == {}) and
		all(
			(.templating.list[] | select(.type == "query")),
			(.. | objects | select(has("targets") or has("expr")));
			.datasource == {"type": "prometheus", "uid": "${datasource}"}
		)
	' "$dashboard" >/dev/null; then
		echo "$dashboard: every query must use the generic \${datasource} variable" >&2
		exit 1
	fi
done

# The RED metric names are platform-generic, so dashboard queries select the
# service label core sets in code, not the release-named pod app label or the
# scraper-owned job label. The server's JOSE lease is unnamed, so name!=""
# keeps the leader-election panels to the controllers' leases.
jq --exit-status '
	[.panels[].targets[].expr, .templating.list[1].query] as $expressions |
	all($expressions[]; contains("service=\"unikorn-identity\", name!=\"\"")) and
	all($expressions[]; contains("app=") | not) and
	all($expressions[]; contains("job=") | not)
' "$chart/files/dashboards/leader-election.json" >/dev/null

jq --exit-status '
	.uid == "uni-identity-api" and
	.title == "Identity API" and
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
	all(($expressions + [.templating.list[1].query])[]; contains("service=\"unikorn-identity\"")) and
	all(($expressions + [.templating.list[1].query])[]; contains("app=") | not) and
	all(($expressions + [.templating.list[1].query])[]; contains("job=") | not)
' "$chart/files/dashboards/uni-identity-api.json" >/dev/null

# The Lease metric names are identity's own; a Go test checks them against the
# exporter. The API server's Lease series have one source per cluster, so only
# identity's own queries select the service.
jq --exit-status '
	.uid == "uni-identity-leases" and
	any(.panels[].targets[].expr; contains("apiserver_request_duration_seconds_bucket")) and
	[.panels[].targets[].expr | select(contains("apiserver_") | not)] as $expressions |
	any($expressions[]; contains("unikorn_identity_organization_lease_acquisitions_total")) and
	any($expressions[]; contains("unikorn_identity_organization_lease_section_seconds_bucket")) and
	all(($expressions + [.templating.list[1].query])[]; contains("service=\"unikorn-identity\"")) and
	all(($expressions + [.templating.list[1].query])[]; contains("app=") | not) and
	all(($expressions + [.templating.list[1].query])[]; contains("job=") | not)
' "$chart/files/dashboards/uni-identity-leases.json" >/dev/null

jq --exit-status '
	[.panels[].title] as $titles |
	all("Ready controllers", "Controller builds", "Server ready", "Server builds";
		. as $title | $titles | index($title)
	) and
	[.panels[].targets[].expr] as $expressions |
	any($expressions[]; contains("unikorn_controller_ready")) and
	any($expressions[]; contains("unikorn_identity_controller_build_info")) and
	any($expressions[]; contains("unikorn_server_ready")) and
	any($expressions[]; contains("unikorn_identity_server_build_info")) and
	all(($expressions + [.templating.list[1].query])[]; contains("service=\"unikorn-identity\"")) and
	all(($expressions + [.templating.list[1].query])[]; contains("app=") | not) and
	all(($expressions + [.templating.list[1].query])[]; contains("job=") | not) and
	all($expressions[]; contains("controller_runtime") | not) and
	all($expressions[]; contains("state-metrics") | not) and
	[.panels[] | select(.title == "Ready controllers")] as $controllerReadiness |
	($controllerReadiness | length == 1) and
	all($controllerReadiness[];
		.targets[0].expr == "sum by (cluster) (unikorn_controller_ready{service=\"unikorn-identity\", cluster=~\"$cluster\"})" and
		.targets[0].legendFormat == "{{cluster}}" and
		.options.textMode == "value_and_name" and
		.options.reduceOptions.values == false and
		.fieldConfig.defaults.mappings[0].type == "value" and
		.fieldConfig.defaults.mappings[0].options["0"].text == "0/3" and
		.fieldConfig.defaults.mappings[0].options["1"].text == "1/3" and
		.fieldConfig.defaults.mappings[0].options["2"].text == "2/3" and
		.fieldConfig.defaults.mappings[0].options["3"].text == "3/3"
	) and
	[.panels[] | select(.title == "Server ready")] as $serverReadiness |
	($serverReadiness | length == 1) and
	all($serverReadiness[];
		.targets[0].expr == "sum by (cluster) (unikorn_server_ready{service=\"unikorn-identity\", cluster=~\"$cluster\"})" and
		.targets[0].legendFormat == "{{cluster}}" and
		.options.textMode == "value_and_name" and
		.options.reduceOptions.values == false and
		.fieldConfig.defaults.mappings[0].type == "value" and
		.fieldConfig.defaults.mappings[0].options["0"].text == "0/1" and
		.fieldConfig.defaults.mappings[0].options["1"].text == "1/1"
	)
' "$chart/files/dashboards/uni-identity-operations.json" >/dev/null
