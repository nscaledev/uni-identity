#!/usr/bin/env bash
# Copyright 2026 Nscale.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Render assertions for globalRoleBindings, globalGroupRoleBindings and
# server.runtimeSchemaValidation.
# `make lint` runs this script.
set -euo pipefail

CHART=charts/identity

render() { helm template test "$CHART" --set-json "globalRoleBindings=$1"; }

die() { echo "FAIL: $*" >&2; exit 1; }

# role_id_of <friendly-name> resolves a Role manifest name from a render on
# stdin: remember the most recent metadata name, emit it on the matching label.
role_id_of() { awk -v want="$1" '$1=="name:"{n=$2} $0 ~ "unikorn-cloud.org/name: "want"$"{print n; exit}'; }

# assert_one_match <output> <pattern> — anchors on a resolved role ID so an
# empty/absent ID (or a duplicate/missing flag) can't pass vacuously.
assert_one_match() { [[ $(grep -c -- "$2" <<<"$1") -eq 1 ]] || die "expected exactly one match for: $2"; }

# assert_no_match <output> <pattern> fails if <pattern> occurs in <output>.
assert_no_match() { [[ $(grep -c -- "$2" <<<"$1") -eq 0 ]] || die "expected no match for: $2"; }

# must_fail requires the expected message, so another failing guard cannot
# satisfy the check.
must_fail() {
	local out
	if out=$(render "$1" 2>&1 >/dev/null); then
		die "expected render failure (fragment: $2), but render succeeded"
	fi
	if ! grep -qF -- "$2" <<<"$out"; then
		die "render failed, but not for the expected reason
  expected fragment: $2
  actual output:     $out"
	fi
}

out=$(render '[{"issuer":"https://staff.example.com/","subject":"*","roles":["reader"]}]')
reader_role_id=$(role_id_of reader <<<"$out")
[[ -n "$reader_role_id" ]] || die "could not resolve role ID for 'reader'"
assert_one_match "$out" "--global-role-binding=https://staff.example.com/::\*::${reader_role_id}\""

# The first non-vacuous positive for the wildcard guard: platform-reader is a
# genuinely read-only GLOBAL role, so this proves the guard accepts read-only
# global scopes rather than merely roles with no global block at all.
out=$(render '[{"issuer":"https://staff.example.com/","subject":"*","roles":["platform-reader"]}]')
platform_reader_role_id=$(role_id_of platform-reader <<<"$out")
[[ -n "$platform_reader_role_id" ]] || die "could not resolve role ID for 'platform-reader'"
assert_one_match "$out" "--global-role-binding=https://staff.example.com/::\*::${platform_reader_role_id}\""

out=$(render '[{"issuer":"uni","subjects":["a@x.com","b@x.com"],"roles":["platform-administrator"]}]')
role_id=$(role_id_of platform-administrator <<<"$out")
[[ -n "$role_id" ]] || die "could not resolve role ID for 'platform-administrator'"
assert_one_match "$out" "--global-role-binding=uni::a@x.com::${role_id}\""
assert_one_match "$out" "--global-role-binding=uni::b@x.com::${role_id}\""

must_fail '[{"issuer":"uni","subject":"a@x.com","subjects":["b@x.com"],"roles":["reader"]}]' \
	"subject and subjects are mutually exclusive"
must_fail '[{"issuer":"uni","subjects":[],"roles":["reader"]}]' \
	"exactly one of subject or non-empty subjects required"
must_fail '[{"issuer":"uni","subjects":["a@x.com",""],"roles":["reader"]}]' \
	"empty or whitespace-only subject"
must_fail '[{"issuer":"uni","subject":"a@x.com"}]' \
	"roles must be non-empty"
must_fail '[{"issuer":"uni","subject":"a@x.com","roles":["no-such-role"]}]' \
	'unknown role "no-such-role"'
must_fail '[{"subject":"a@x.com","roles":["reader"]}]' \
	"issuer is required"
must_fail '[{"issuer":"uni","subject":"*","roles":["reader"]}]' \
	"globalRoleBindings[0]: wildcard subject not allowed on the UNI sentinel issuer"
must_fail '[{"issuer":"https://a.com/ ","subject":"a@x.com","roles":["reader"]}]' \
	"globalRoleBindings[0]: issuer must not contain whitespace"
must_fail '[{"issuer":"https://staff.example.com/","subject":"*","roles":["platform-administrator"]}]' \
	'globalRoleBindings[0]: wildcard binding role "platform-administrator" grants non-read global operation'
must_fail '[{"issuer":"https://staff.example.com/","subjects":["alice@x.com","*"],"roles":["platform-administrator"]}]' \
	'globalRoleBindings[0]: wildcard binding role "platform-administrator" grants non-read global operation'

# A padded subject must reach every guard trimmed: the server trims before
# matching, so guarding the raw string would deploy " * " as a real wildcard.
must_fail '[{"issuer":"https://staff.example.com/","subject":" * ","roles":["platform-administrator"]}]' \
	'globalRoleBindings[0]: wildcard binding role "platform-administrator" grants non-read global operation'
must_fail '[{"issuer":"uni","subject":" * ","roles":["reader"]}]' \
	"globalRoleBindings[0]: wildcard subject not allowed on the UNI sentinel issuer"

# "::" on either side shifts the right-anchored parse boundary; unrejected here
# it is undetectable server-side, so it must fail the render, not the pod.
must_fail '[{"issuer":"uni","subject":"a::b","roles":["reader"]}]' \
	'globalRoleBindings[0].subjects[0]: subject must not contain "::"'
must_fail '[{"issuer":"https://x.com/?q=a::b","subject":"alice@x.com","roles":["reader"]}]' \
	'globalRoleBindings[0]: issuer must not contain "::"'

# The trimmed subject is what gets emitted, not the padded original.
out=$(render '[{"issuer":"https://staff.example.com/","subject":" alice@x.com ","roles":["reader"]}]')
reader_role_id=$(role_id_of reader <<<"$out")
assert_one_match "$out" "--global-role-binding=https://staff.example.com/::alice@x.com::${reader_role_id}\""

# The server matches subjects case-sensitively, so a mixed-case subject would
# silently stop matching once deployed; reject it at render time instead.
must_fail '[{"issuer":"https://staff.example.com/","subject":"Alice@x.com","roles":["reader"]}]' \
	"globalRoleBindings[0].subjects[0]: subject must be its canonical lower-case form"
must_fail '[{"issuer":"https://staff.example.com/","subjects":["alice@x.com","Bob@x.com"],"roles":["reader"]}]' \
	"globalRoleBindings[0].subjects[1]: subject must be its canonical lower-case form"

# The wildcard subject itself must never trip the case guard: it has no
# letters to begin with, but the guard explicitly skips it for clarity.
out=$(render '[{"issuer":"https://staff.example.com/","subject":"*","roles":["reader"]}]')
reader_role_id=$(role_id_of reader <<<"$out")
assert_one_match "$out" "--global-role-binding=https://staff.example.com/::\*::${reader_role_id}\""

# platformAdministrators.subjects is translated into the same bindings and
# must be guarded equivalently, for both the bare (UNI-sentinel) and
# issuer-qualified forms.
render_admin() { helm template test "$CHART" --set-json "platformAdministrators.subjects=$1"; }
must_fail_admin() {
	local out
	if out=$(render_admin "$1" 2>&1 >/dev/null); then
		die "expected render failure (fragment: $2), but render succeeded"
	fi
	if ! grep -qF -- "$2" <<<"$out"; then
		die "render failed, but not for the expected reason
  expected fragment: $2
  actual output:     $out"
	fi
}

must_fail_admin '["Admin@x.com"]' \
	"platformAdministrators.subjects[0]: subject must be its canonical lower-case form"
must_fail_admin '["https://staff.example.com/::Admin@x.com"]' \
	"platformAdministrators.subjects[0]: subject must be its canonical lower-case form"

render_group() { helm template test "$CHART" --set-json "globalGroupRoleBindings=$1"; }

must_fail_group() {
	local out
	if out=$(render_group "$1" 2>&1 >/dev/null); then
		die "expected render failure (fragment: $2), but render succeeded"
	fi
	if ! grep -qF -- "$2" <<<"$out"; then
		die "render failed, but not for the expected reason
  expected fragment: $2
  actual output:     $out"
	fi
}

# Title Case group names must render. Group names are byte-exact, and the
# lower-case guard that applies to subjects does NOT apply to them. The role is
# platform-reader. It reads the credential scopes and writes none, so it passes
# the credential-scope guard.
out=$(render_group '[{"issuer":"https://staff.example.com/","group":"Platform Engineering","roles":["platform-reader"]}]')
reader_role_id=$(role_id_of platform-reader <<<"$out")
[[ -n "$reader_role_id" ]] || die "could not resolve role ID for 'platform-reader'"
assert_one_match "$out" "--global-group-role-binding=https://staff.example.com/::Platform Engineering::${reader_role_id}\""

# The values.yaml example pattern must render: a purpose-built additionalRoles
# role with a non-credential write (identity:quotas update) passes the
# credential-scope guard. This pins the guard's allow path for write-bearing
# roles, not only its read-only path above.
support_role='{"support-quota-editor":{"description":"Support quota editor","protected":true,"scopes":{"global":{"identity:organizations":["read"],"identity:projects":["read"],"identity:quotas":["read","update"]}}}}'
out=$(helm template test "$CHART" --set-json "additionalRoles=$support_role" \
	--set-json 'globalGroupRoleBindings=[{"issuer":"https://staff.example.com/","group":"Support Engineering","roles":["support-quota-editor"]}]')
support_role_id=$(role_id_of support-quota-editor <<<"$out")
[[ -n "$support_role_id" ]] || die "could not resolve role ID for 'support-quota-editor'"
assert_one_match "$out" "--global-group-role-binding=https://staff.example.com/::Support Engineering::${support_role_id}\""

must_fail_group '[{"group":"SRE","roles":["platform-administrator"]}]' "issuer is required"
must_fail_group '[{"issuer":"https://a.com/ ","group":"SRE","roles":["platform-administrator"]}]' "issuer must not contain whitespace"
must_fail_group '[{"issuer":"https://x.com/?q=a::b","group":"SRE","roles":["platform-administrator"]}]' 'issuer must not contain "::"'
must_fail_group '[{"issuer":"uni","group":"SRE","roles":["platform-administrator"]}]' "the uni sentinel issuer cannot carry groups"
must_fail_group '[{"issuer":"https://staff.example.com/","group":"*","roles":["platform-administrator"]}]' "wildcard group not allowed"
must_fail_group '[{"issuer":"https://staff.example.com/","group":"a::b","roles":["platform-administrator"]}]' "group must not contain"
must_fail_group '[{"issuer":"https://staff.example.com/","group":"Platform\tEngineering","roles":["platform-administrator"]}]' "group must not contain control whitespace"
must_fail_group '[{"issuer":"https://staff.example.com/","group":"  ","roles":["platform-administrator"]}]' "group is required"
must_fail_group '[{"issuer":"https://staff.example.com/","group":"SRE","roles":["no-such-role"]}]' "unknown role"
must_fail_group '[{"issuer":"https://staff.example.com/","group":"SRE","roles":["platform-administrator"]}]' "on credential scope"

# The built-in project-administrator role renders with its own ID. An additionalRoles
# entry of the same name fails the render and does not merge into the role.
out=$(helm template test "$CHART")
project_administrator_role_id=$(role_id_of project-administrator <<<"$out")
[[ -n "$project_administrator_role_id" ]] || die "could not resolve role ID for 'project-administrator'"
assert_one_match "$(yq -r 'select(.kind == "Role") | .metadata.name' <<<"$out")" "^${project_administrator_role_id}$"

if out=$(helm template test "$CHART" --set-json 'additionalRoles={"project-administrator":{"description":"Conflicting role","scopes":{"project":{"identity:projects":["read"]}}}}' 2>&1 >/dev/null); then
	die "expected render failure for an additionalRoles key named project-administrator, but render succeeded"
fi
grep -qF -- "conflicts with built-in role" <<<"$out" || die "render failed, but not for the expected reason
  expected fragment: conflicts with built-in role
  actual output:     $out"

# server.runtimeSchemaValidation: the flag renders only for the boolean
# false.  The default and null keep the binary default.  A string fails the
# render, so a quoted "false" cannot leave validation on.
out=$(helm template test "$CHART")
assert_no_match "$out" "--runtime-schema-validation"

out=$(helm template test "$CHART" --set server.runtimeSchemaValidation=null)
assert_no_match "$out" "--runtime-schema-validation"

out=$(helm template test "$CHART" --set server.runtimeSchemaValidation=false)
assert_one_match "$out" "--runtime-schema-validation=false"

if helm template test "$CHART" --set-string server.runtimeSchemaValidation=false >/dev/null 2>&1; then
	die "expected render failure for string server.runtimeSchemaValidation"
fi

# The shared endpoint must reach every workload, for traces.  The code names
# the service, so OTEL_SERVICE_NAME would have no effect and must not be set;
# each workload sets service.instance.id from the pod name so its spans can be
# told apart.
out=$(helm template test "$CHART" --set otlp.endpoint=collector.example:4318)
for workload in server organization-controller oauth2client-controller project-controller; do
	flag=$(yq -r "select(.kind == \"Deployment\" and .metadata.name == \"test-${workload}\") | .spec.template.spec.containers[].args[] | select(. == \"--otlp-endpoint=collector.example:4318\")" <<<"$out")
	[[ "$flag" == "--otlp-endpoint=collector.example:4318" ]] || die "expected OTLP endpoint on test-${workload}"
	service_name=$(yq -r "select(.kind == \"Deployment\" and .metadata.name == \"test-${workload}\") | .spec.template.spec.containers[].env[] | select(.name == \"OTEL_SERVICE_NAME\") | .value" <<<"$out")
	[[ -z "$service_name" ]] || die "expected no OTEL_SERVICE_NAME on test-${workload}"
	attributes=$(yq -r "select(.kind == \"Deployment\" and .metadata.name == \"test-${workload}\") | .spec.template.spec.containers[].env[] | select(.name == \"OTEL_RESOURCE_ATTRIBUTES\") | .value" <<<"$out")
	[[ "$attributes" == 'service.instance.id=$(POD_NAME)' ]] || die "expected service.instance.id from POD_NAME on test-${workload}"
	pod_name_source=$(yq -r "select(.kind == \"Deployment\" and .metadata.name == \"test-${workload}\") | .spec.template.spec.containers[].env[] | select(.name == \"POD_NAME\") | .valueFrom.fieldRef.fieldPath" <<<"$out")
	[[ "$pod_name_source" == "metadata.name" ]] || die "expected POD_NAME from the downward API on test-${workload}"
	metrics_port=$(yq -r "select(.kind == \"Deployment\" and .metadata.name == \"test-${workload}\") | .spec.template.spec.containers[].ports[] | select(.name == \"prometheus\") | .containerPort" <<<"$out")
	[[ "$metrics_port" == "8080" ]] || die "expected Prometheus port on test-${workload}"
done

# Direct Kubernetes reads require a get permission; list/watch only permit
# informer synchronization and cannot authorize an API-server GET.
has_server_get() {
	resource="$1" yq -e '
		select(.kind == "ClusterRole" and .metadata.name == "test-server") |
		.rules[] |
		select(.resources[] == strenv(resource)) |
		select(.verbs[] == "get")
	' <<<"$out" >/dev/null
}

for resource in \
	groups oauth2clients oauth2providers organizations projects quotas quotametadata \
	roles serviceaccounts users organizationusers signingkeys secrets; do
	has_server_get "$resource" || die "expected get permission for server resource: $resource"
done

# server_verbs prints the sorted verbs the server role grants on a resource.
server_verbs() {
	resource="$1" yq -r '
		select(.kind == "ClusterRole" and .metadata.name == "test-server") |
		.rules[] |
		select(.resources[] == strenv(resource)) |
		.verbs[]
	' <<<"$out" | sort -u | paste -sd, -
}

# Only the read cache watches, and only the kinds it holds; without watch on a
# kind the cache still syncs from list but relists every 30-60 s, and without
# list it never syncs (startup gives up after its sync timeout).  Core resources are
# read directly and only with the verbs the server uses.
watched=$(yq -r '
	select(.kind == "ClusterRole" and .metadata.name == "test-server") |
	.rules[] |
	select(.verbs[] == "watch") |
	.resources[]
' <<<"$out" | sort -u | paste -sd, -)
[[ "$watched" == "allocations,groups,oauth2providers,organizations,organizationusers,projects,quotas,roles,serviceaccounts,signingkeys,users" ]] || die "expected watch only on the read cache kinds for the server, got: $watched"
[[ "$(server_verbs signingkeys)" == "create,get,list,update,watch" ]] || die "expected only create, get, list, update and watch on signingkeys for the server"
[[ "$(server_verbs secrets)" == "get" ]] || die "expected only get on secrets for the server"
[[ "$(server_verbs namespaces)" == "list" ]] || die "expected only list on namespaces for the server"
# Organization Lease release deletes the Lease; without delete every release
# fails and the next writer waits for a takeover.
[[ "$(server_verbs leases)" == "create,delete,get,update" ]] || die "expected only create, delete, get and update on leases for the server"
[[ -z "$(server_verbs configmaps)" ]] || die "expected no configmaps permission for the server"

# The server reports readiness on /readyz, so a rollout only sends traffic to a
# replica once it can read the signing key. The probe has its own port, which
# the Service does not expose, so the ingress cannot reach it.
rendered=$(helm template test "$CHART")
server_deployment() { yq -r "select(.kind == \"Deployment\" and .metadata.name == \"test-server\") | $1" <<<"$rendered"; }
[[ "$(server_deployment '.spec.template.spec.containers[0].readinessProbe.httpGet | .path + " " + .port')" == "/readyz health" ]] || die "expected a readiness probe on /readyz on the health port"
[[ "$(yq -r 'select(.kind == "Service" and .metadata.name == "test-server") | .spec.ports[].targetPort' <<<"$rendered")" == "http" ]] || die "expected the server Service to expose only the http port"
# pkg/server/shutdown_internal_test.go checks the shutdown fits in this.
[[ "$(server_deployment '.spec.template.spec.terminationGracePeriodSeconds')" == "60" ]] || die "expected a 60s termination grace period for the server"

# The identity API server defaults to two replicas and its PDB permits one
# voluntary disruption without preventing a one-replica node drain. Best-effort
# hostname spreading keeps the replicas on different nodes when possible.
deployment=$(helm template test "$CHART" | awk 'BEGIN { RS="---" } /kind: Deployment/ && /name: test-server/ { print }')
[[ $(grep -c '^  replicas: 2$' <<<"$deployment") -eq 1 ]] || die "expected identity server to default to two replicas"
[[ "$(yq -r '.spec.template.spec.topologySpreadConstraints | length' <<<"$deployment")" == "1" ]] || die "expected one identity server topology spread constraint"
[[ "$(yq -r '.spec.template.spec.topologySpreadConstraints[0].maxSkew' <<<"$deployment")" == "1" ]] || die "expected identity server topology spread maxSkew of one"
[[ "$(yq -r '.spec.template.spec.topologySpreadConstraints[0].topologyKey' <<<"$deployment")" == "kubernetes.io/hostname" ]] || die "expected identity server hostname topology spread"
[[ "$(yq -r '.spec.template.spec.topologySpreadConstraints[0].whenUnsatisfiable' <<<"$deployment")" == "ScheduleAnyway" ]] || die "expected best-effort identity server topology spread"
[[ "$(yq -r '.spec.template.spec.topologySpreadConstraints[0].labelSelector.matchLabels.app' <<<"$deployment")" == "test-server" ]] || die "expected identity server topology spread selector"

deployment=$(helm template test "$CHART" --set server.replicas=3 | awk 'BEGIN { RS="---" } /kind: Deployment/ && /name: test-server/ { print }')
[[ $(grep -c '^  replicas: 3$' <<<"$deployment") -eq 1 ]] || die "expected identity server replica override"

deployment=$(helm template test "$CHART" --set server.replicas=1 | awk 'BEGIN { RS="---" } /kind: Deployment/ && /name: test-server/ { print }')
[[ $(grep -c '^  replicas: 1$' <<<"$deployment") -eq 1 ]] || die "expected identity server one-replica override"

pdb=$(helm template test "$CHART" | awk 'BEGIN { RS="---" } /kind: PodDisruptionBudget/ && /name: test-server/ { print }')
[[ $(grep -c '^  maxUnavailable: 1$' <<<"$pdb") -eq 1 ]] || die "expected identity server PDB to allow one unavailable pod"
[[ $(grep -c '^      app: test-server$' <<<"$pdb") -eq 1 ]] || die "expected identity server PDB selector"

# The load test installs with test-values.yaml then load-values.yaml. It must
# run at production's ACL cache timeout, not the short one the integration
# tests use.
out=$(helm template test "$CHART" -f hack/ci/test-values.yaml -f hack/ci/load-values.yaml)
assert_no_match "$out" "--acl-cache-timeout"
# The warm-up's rolling restart needs room for one more server pod.
load_server() { yq -r "select(.kind == \"Deployment\" and .metadata.name == \"test-server\") | $1" <<<"$out"; }
[[ "$(load_server '.spec.template.spec.containers[0].resources.requests.cpu')" == "250m" ]] || die "expected a 250m CPU request on the load test server"
[[ "$(load_server '.spec.template.spec.containers[0].resources.limits.cpu')" == "1" ]] || die "expected a 1 CPU limit on the load test server"

# Per-service splits of the organization roles. Each <role>-<prefix> holds
# exactly the original's scopes with that prefix; each <role>-<prefix>-off
# keeps only their read and delete operations. Expected scopes come from
# values.yaml, not from the template, so a template bug cannot pass.
# They are off by default; builtinRoleSplits.enabled turns them on.
render_splits() { helm template test "$CHART" --set builtinRoleSplits.enabled=true "$@"; }
out=$(render_splits)
on=$out

# rendered_scopes <name> prints "level scope ops" lines for a rendered Role.
rendered_scopes() {
	n="$1" yq -r '
		select(.kind == "Role" and .metadata.labels["unikorn-cloud.org/name"] == strenv(n)) |
		.spec.scopes | to_entries[] | .key as $l | .value[] |
		$l + " " + .name + " " + (.operations | join(","))
	' <<<"$out" | sort
}

# expected_scopes <role> <prefix> <ops-regex> prints the same lines from the
# original role in values.yaml, keeping operations that match <ops-regex>.
expected_scopes() {
	r="$1" p="$2" o="$3" yq -r '
		.roles[strenv(r)].scopes | to_entries[] | .key as $l | .value | to_entries[] |
		select(.key | test("^" + strenv(p) + ":")) |
		[$l, .key, (.value | map(select(test(strenv(o)))) | join(","))] |
		select(.[2] != "") | join(" ")
	' "$CHART/values.yaml" | sort
}

split_field() { yq -r ".builtinRoleSplits.$1[]" "$CHART/values.yaml"; }

# role_field <name> <path> prints a field of the rendered Role.
role_field() {
	n="$1" yq -r "select(.kind == \"Role\" and .metadata.labels[\"unikorn-cloud.org/name\"] == strenv(n)) | $2" <<<"$out"
}

check_split() {
	local name="$1" role="$2" prefix="$3" ops="$4" want got
	want=$(expected_scopes "$role" "$prefix" "$ops")
	[[ -n "$want" ]] || die "split $name: original $role has no $prefix scopes"
	got=$(rendered_scopes "$name")
	[[ "$got" == "$want" ]] || die "split $name: scopes differ from $role
  want: $want
  got:  $got"
	[[ "$(role_field "$name" '.spec.protected')" == "null" ]] || die "split $name must not be protected"
	[[ "$(role_field "$name" '.metadata.name')" == "$(n="$name" yq -r '.builtinRoleSplits.ids[strenv(n)]' "$CHART/values.yaml")" ]] ||
		die "split $name: ID is not builtinRoleSplits.ids.$name"
}

splits=0
for role in $(split_field roles); do
	for prefix in $(split_field prefixes); do
		check_split "$role-$prefix" "$role" "$prefix" '.*'
		splits=$((splits + 1))
	done
	for prefix in $(split_field offPrefixes); do
		check_split "$role-$prefix-off" "$role" "$prefix" '^(read|delete)$'
		splits=$((splits + 1))
	done
done
expected_splits=$(($(split_field roles | wc -l) * ($(split_field prefixes | wc -l) + $(split_field offPrefixes | wc -l))))
[[ $expected_splits -gt 0 && $splits -eq $expected_splits ]] || die "expected $expected_splits per-service roles, checked $splits"

# A copy of a role with no description has no leading space.
out=$(render_splits --set roles.user.description=null)
[[ "$(role_field user-compute '.metadata.annotations["unikorn-cloud.org/description"]')" == "(compute)" ]] ||
	die "expected description \"(compute)\" for a copy of a role with no description"
out=$on

# Role IDs and names stay unique once the splits are added.
[[ -z "$(yq -r 'select(.kind == "Role" and .apiVersion == "identity.unikorn-cloud.org/v1alpha1") | .metadata.name' <<<"$out" | grep -v '^---$' | sort | uniq -d)" ]] ||
	die "duplicate Role IDs"
[[ -z "$(yq -r 'select(.kind == "Role" and .apiVersion == "identity.unikorn-cloud.org/v1alpha1") | .metadata.labels["unikorn-cloud.org/name"]' <<<"$out" | grep -v '^---$' | sort | uniq -d)" ]] ||
	die "duplicate Role names"

# without_splits drops the split Role documents from a render on stdin,
# leaving every other byte as rendered.
without_splits() {
	awk -v re='\n    unikorn-cloud.org/name: (administrator|auditor|user|reader)-(identity|region|compute|kubernetes|storage)(-off)?\n' '
		/^---$/ { if (doc !~ re) printf "%s", doc; doc = "" }
		{ doc = doc $0 "\n" }
		END { if (doc !~ re) printf "%s", doc }
	'
}

# Off (the default) renders exactly what the chart rendered before the
# splits: the "on" render minus the split documents, byte for byte.
# This cannot catch a change to the old roles; only a diff against the base
# render does.
off=$(helm template test "$CHART")
[[ $(grep -c 'unikorn-cloud.org/name: ' <<<"$on") -eq $(($(grep -c 'unikorn-cloud.org/name: ' <<<"$off") + expected_splits)) ]] ||
	die "expected the on render to add exactly $expected_splits Roles"
diff <(printf '%s\n' "$off") <(without_splits <<<"$on") >/dev/null ||
	die "default render differs from the on render without the splits"
out=$off
[[ -z "$(rendered_scopes administrator-compute)" ]] || die "expected no splits by default"

# An empty role list renders no split roles either.
out=$(render_splits --set-json 'builtinRoleSplits.roles=[]')
[[ -z "$(rendered_scopes administrator-compute)" ]] || die "expected no splits when builtinRoleSplits.roles is empty"

# A split name is reserved, like a built-in role name.
if err=$(render_splits --set-json 'additionalRoles={"user-compute":{"description":"x"}}' 2>&1 >/dev/null); then
	die "expected render failure for additionalRoles key user-compute"
fi
grep -qF 'additionalRoles key "user-compute" conflicts with built-in role' <<<"$err" ||
	die "additionalRoles conflict failed for the wrong reason: $err"

# A split without a fixed ID fails the render rather than falling back.
if err=$(render_splits --set 'builtinRoleSplits.ids.user-compute=null' 2>&1 >/dev/null); then
	die "expected render failure for a split without an ID"
fi
grep -qF 'builtinRoleSplits.ids has no ID for "user-compute"' <<<"$err" ||
	die "missing split ID failed for the wrong reason: $err"

echo "chart render checks OK"
