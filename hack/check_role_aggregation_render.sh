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

# Render assertions for role aggregation (roles.yaml and the
# role-aggregation admission policy).  `make lint` runs this script.
set -euo pipefail

CHART=${CHART:-charts/identity}

die() { echo "FAIL: $*" >&2; exit 1; }

# role_doc <render> <name> prints the Role manifest whose name label is <name>.
# The name label is quoted (B-3), so the match is on the quoted form.
role_doc() { awk -v want="$2" 'BEGIN{RS="\n---\n"} /kind: Role\n/ && $0 ~ "unikorn-cloud.org/name: \""want"\"\n" {print}' <<<"$1"; }

# must_role_doc <render> <name> is role_doc, failing if there is no such Role,
# so a negative grep on it can't pass on an empty document.
must_role_doc() {
	local doc
	doc=$(role_doc "$1" "$2")
	[[ -n "$doc" ]] || die "no Role rendered for $2"
	echo "$doc"
}

# spec_of <doc> prints the spec block of a Role manifest.
spec_of() { awk '/^spec:/{p=1} p' <<<"$1"; }

# must_render <helm args...> requires the render to succeed.
must_render() {
	local out
	out=$(helm template test "$CHART" "$@" 2>&1 >/dev/null) || die "expected render to succeed ($*), but: $out"
}

# id_of <name> computes the role ID the chart derives from a name.
sha256() { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; }
id_of() { local s; s=$(printf %s "$1" | sha256 | cut -c1-32); echo "f${s:1:7}-${s:8:4}-4${s:13:3}-8${s:17:3}-${s:20:12}"; }

# must_fail <fragment> <helm args...> requires the expected message.
must_fail() {
	local want=$1 out
	shift
	if out=$(helm template test "$CHART" "$@" 2>&1 >/dev/null); then
		die "expected render failure (fragment: $want), but render succeeded"
	fi
	grep -qF -- "$want" <<<"$out" || die "render failed, but not for the expected reason
  expected fragment: $want
  actual output:     $out"
}

default=$(helm template test "$CHART")
aggregating=$(helm template test "$CHART" --set aggregation.builtinRoles=true)

# Default (aggregation.builtinRoles off): the built-in roles render as they did
# before aggregation, holding exactly their base role's scopes.
for name in administrator auditor user reader; do
	doc=$(must_role_doc "$default" "$name") || exit 1
	base=$(must_role_doc "$default" "$name-base") || exit 1
	grep -qF "name: $(id_of "$name")" <<<"$doc" || die "$name has changed ID"
	grep -q "aggregationRule:" <<<"$doc" && die "$name aggregates with aggregation.builtinRoles off"
	grep -q "aggregate-to-" <<<"$doc" && die "$name carries an aggregate-to-* label with aggregation.builtinRoles off"
	grep -q "sync-wave" <<<"$doc" && die "$name has a sync wave with aggregation.builtinRoles off"
	grep -q "protected: true" <<<"$base" || die "$name-base is not protected"
	[[ "$(spec_of "$doc")" == "$(spec_of "$base" | grep -vx '  protected: true')" ]] || die "$name does not hold exactly the scopes of $name-base"
	grep -q "^    organization:" <<<"$doc" || die "$name has no organization scopes"
done

# The built-in roles are never protected: an org admin grants them.
for render in "$default" "$aggregating"; do
	for name in administrator auditor user reader; do
		grep -q "protected: true" <<<"$(must_role_doc "$render" "$name")" && die "$name is protected"
	done
done

# aggregation.builtinRoles on: the built-in roles aggregate, keeping their IDs.
for name in administrator auditor user reader; do
	doc=$(must_role_doc "$aggregating" "$name") || exit 1
	grep -qF "name: $(id_of "$name")" <<<"$doc" || die "$name has changed ID"
	grep -q "aggregationRule:" <<<"$doc" || die "$name is not aggregating"
	grep -q "^  scopes:" <<<"$doc" && die "$name renders spec.scopes"
	grep -qF -- "- $(id_of "$name-base")" <<<"$doc" || die "$name does not ref $name-base"
	grep -q "protected: true" <<<"$(must_role_doc "$aggregating" "$name-base")" || die "$name-base is not protected"
done

# The chain: reader -> auditor and user; auditor and user -> administrator.
grep -qF 'identity.unikorn-cloud.org/aggregate-to-auditor: "true"' <<<"$(role_doc "$aggregating" reader)" || die "reader is not labelled for auditor"
grep -qF 'identity.unikorn-cloud.org/aggregate-to-user: "true"' <<<"$(role_doc "$aggregating" reader)" || die "reader is not labelled for user"
grep -qF 'identity.unikorn-cloud.org/aggregate-to-administrator: "true"' <<<"$(role_doc "$aggregating" user)" || die "user is not labelled for administrator"
grep -qF 'identity.unikorn-cloud.org/aggregate-to-administrator: "true"' <<<"$(role_doc "$aggregating" auditor)" || die "auditor is not labelled for administrator"

# Only administrator and auditor flatten project scopes into organization.
for name in administrator auditor; do
	grep -qx '    flattenToOrganization: true' <<<"$(role_doc "$aggregating" "$name")" || die "$name does not flatten"
done
for name in user reader; do
	grep -q 'flattenToOrganization' <<<"$(role_doc "$aggregating" "$name")" && die "$name flattens"
done

# Each aggregating role selects exactly its own label.
for name in administrator auditor user reader; do
	selector=$(awk '/matchLabels:/{getline; print; exit}' <<<"$(role_doc "$aggregating" "$name")")
	[[ "$selector" == "        identity.unikorn-cloud.org/aggregate-to-$name: \"true\"" ]] || die "$name selects '$selector', not aggregate-to-$name"
done

# Platform roles never aggregate.
for name in platform-administrator platform-reader; do
	for render in "$default" "$aggregating"; do
		doc=$(must_role_doc "$render" "$name") || exit 1
		grep -q "aggregationRule:" <<<"$doc" && die "$name aggregates"
	done
done

# Base roles are applied before the roles that ref them.
pos_base=$(grep -m1 -n "unikorn-cloud.org/name: \"administrator-base\"$" <<<"$aggregating" | cut -d: -f1) || die "administrator-base is not rendered"
pos_admin=$(grep -m1 -n "unikorn-cloud.org/name: \"administrator\"$" <<<"$aggregating" | cut -d: -f1) || die "administrator is not rendered"
[[ "$pos_base" -lt "$pos_admin" ]] || die "administrator-base is not rendered before administrator"
grep -qF 'argocd.argoproj.io/sync-wave: "1"' <<<"$(role_doc "$aggregating" administrator)" || die "administrator has no later sync wave"

# The admission policy is release scoped, binds the release namespace only,
# and its allow-list holds IDs, not names.
for render in "$default" "$aggregating"; do
	grep -qF "name: test-role-aggregation.identity.unikorn-cloud.org" <<<"$render" || die "the role aggregation policy is not named for the release"
	grep -qF "kubernetes.io/metadata.name: default" <<<"$render" || die "the role aggregation policy binding is not limited to the release namespace"
	grep -qF "'$(id_of fleet-operator)'" <<<"$render" || die "fleet-operator is not on the rendered allow-list"
	grep -qF "'$(id_of resource-pool-admin)'" <<<"$render" && die "resource-pool-admin is on the rendered allow-list"
	grep -qF "'region:identities'" <<<"$render" || die "region:identities is not on the rendered platform-only list"
	grep -qF "'$(id_of administrator)': true, '$(id_of auditor)': true, '$(id_of reader)': false, '$(id_of user)': false" <<<"$render" || die "the policy does not pin flattenToOrganization on the built-in roles"
	grep -qF "'$(id_of reader)': ['identity.unikorn-cloud.org/aggregate-to-auditor', 'identity.unikorn-cloud.org/aggregate-to-user']" <<<"$render" || die "the policy does not pin reader's aggregate-to-* labels"
done

# The allow-list is exactly the agreed set; adding a name is a reviewed change.
want_sources="auditor environment-admin environment-deployer environment-viewer fleet-operator nks-organization-admin nks-organization-auditor nks-organization-kubernetes-api-reader nks-organization-kubernetes-api-writer nks-project-admin nks-project-auditor nks-project-kubernetes-api-reader nks-project-kubernetes-api-writer org-catalog-admin org-catalog-viewer project-environment-admin project-product-admin project-viewer reader reservation-capacity-manager reservation-capacity-reader reservation-placement-operator reservation-placement-reader reservation-placement-user resource-pool-viewer user"
got_sources=$(yq '.aggregation.allowedSources[]' "$CHART/values.yaml" | sort | tr '\n' ' ' | sed 's/ $//')
[[ "$got_sources" == "$want_sources" ]] || die "aggregation.allowedSources is not the agreed set
  want: $want_sources
  got:  $got_sources"

# The role controller is deployed, and writes role status in its own namespace only.
awk 'BEGIN{RS="\n---\n"} /kind: Deployment\n/ && /\n  name: test-role-controller\n/ {found=1} END{exit !found}' <<<"$default" || die "role controller Deployment is not rendered"
awk 'BEGIN{RS="\n---\n"} /kind: ClusterRole\n/ && /roles\/status/ {found=1} END{exit !found}' <<<"$default" && die "roles/status is granted cluster-wide"
awk 'BEGIN{RS="\n---\n"} /kind: Role\n/ && /name: test-role-controller\n/ && /roles\/status/ {found=1} END{exit !found}' <<<"$default" || die "roles/status is not granted in the release namespace"

# Custom labels and aggregateTo on additionalRoles; duplicate targets render once.
out=$(helm template test "$CHART" --set-json 'additionalRoles={"fleet-operator":{"description":"Fleet operator","labels":{"example.com/team":"radar"},"aggregateTo":["reader","reader"],"scopes":{"organization":{"radar:topology":["read"]}}}}')
doc=$(must_role_doc "$out" fleet-operator) || exit 1
grep -qF '"example.com/team": "radar"' <<<"$doc" || die "custom label not rendered"
[[ $(grep -cF 'identity.unikorn-cloud.org/aggregate-to-reader: "true"' <<<"$doc") -eq 1 ]] || die "aggregateTo label not rendered exactly once"

must_fail "must not set scopes" --set-json 'additionalRoles={"x":{"aggregationRule":{"roleRefs":["reader-base"]},"scopes":{"organization":{"a:b":["read"]}}}}'
must_fail "names unknown role" --set-json 'additionalRoles={"x":{"aggregationRule":{"roleRefs":["typo-base"]}}}'
must_fail "names itself" --set-json 'additionalRoles={"x":{"aggregationRule":{"roleRefs":["x"]}}}'
must_fail "needs the role on aggregation.allowedSources" --set-json 'additionalRoles={"not-allowed":{"aggregateTo":["reader"],"scopes":{"organization":{"a:b":["read"]}}}}'
must_fail "a protected role cannot opt into aggregation" --set-json 'additionalRoles={"fleet-operator":{"protected":true,"aggregateTo":["reader"]}}'
must_fail "which is not an aggregating role" --set-json 'additionalRoles={"fleet-operator":{"aggregateTo":["administrator-base"],"scopes":{"organization":{"radar:topology":["read"]}}}}'

# Render guards mirror the admission policy.
must_fail "global scopes cannot opt into aggregation" --set-json 'additionalRoles={"fleet-operator":{"aggregateTo":["reader"],"scopes":{"global":{"radar:topology":["read"]}}}}'
must_fail "identity:* or credential" --set-json 'additionalRoles={"fleet-operator":{"aggregateTo":["reader"],"scopes":{"organization":{"identity:allocations":["read"]}}}}'
must_fail "identity:* or credential" --set-json 'additionalRoles={"fleet-operator":{"aggregateTo":["reader"],"scopes":{"project":{"storage:objectstorageendpoints/accesskeys":["read"]}}}}'
must_fail "cannot also aggregate, except the built-in chain roles" --set-json 'additionalRoles={"fleet-operator":{"aggregateTo":["reader"],"aggregationRule":{"roleRefs":["platform-administrator"]}}}'
must_fail "a built-in role must ref exactly reader-base" --set aggregation.builtinRoles=true --set-json 'roles.reader.aggregationRule={"roleRefs":["reader-base","platform-administrator"]}'
must_fail "labels must not set \"identity.unikorn-cloud.org/aggregate-to-administrator\"" --set-json 'additionalRoles={"x":{"labels":{"identity.unikorn-cloud.org/aggregate-to-administrator":"true"},"scopes":{"organization":{"a:b":["read"]}}}}'
must_fail "labels must not set \"unikorn-cloud.org/name\"" --set-json 'additionalRoles={"x":{"labels":{"unikorn-cloud.org/name":"administrator"},"scopes":{"organization":{"a:b":["read"]}}}}'

# A labelled role can't hold a platform-only scope, and holding one in values
# does not take it off the list.
must_fail "platform-only scope \"region:servers\"" --set-json 'additionalRoles={"fleet-operator":{"aggregateTo":["reader"],"scopes":{"organization":{"region:servers":["create"]}}}}'
must_fail "platform-only scope \"region:identities\"" --set-json 'additionalRoles={"fleet-operator":{"aggregateTo":["reader"],"scopes":{"project":{"region:identities":["create"]}}}}'

# With aggregation.builtinRoles on, the built-in roles keep their fixed shape.
on=(--set aggregation.builtinRoles=true)
must_fail "a built-in role's aggregateTo must be exactly [auditor user]" "${on[@]}" --set-json 'roles.reader.aggregateTo=["user"]'
must_fail "a built-in role's aggregateTo must be exactly [administrator]" "${on[@]}" --set-json 'roles.user.aggregateTo=["administrator","auditor"]'
must_fail "a built-in role's aggregateTo must be exactly []" "${on[@]}" --set-json 'roles.administrator.aggregateTo=["auditor"]'
must_fail "\"auditor\": a built-in role's flattenToOrganization must be true" "${on[@]}" --set-json 'roles.auditor.aggregationRule={"roleRefs":["auditor-base"],"flattenToOrganization":false}'
must_fail "\"administrator\": a built-in role's flattenToOrganization must be true" "${on[@]}" --set-json 'roles.administrator.aggregationRule={"roleRefs":["administrator-base"],"flattenToOrganization":null}'
must_fail "\"user\": a built-in role's flattenToOrganization must be false" "${on[@]}" --set-json 'roles.user.aggregationRule={"roleRefs":["user-base"],"flattenToOrganization":true}'
must_fail "\"reader\": a built-in role's flattenToOrganization must be false" "${on[@]}" --set-json 'roles.reader.aggregationRule={"roleRefs":["reader-base"],"flattenToOrganization":true}'
must_fail "a built-in role must set aggregationRule" "${on[@]}" --set-json 'roles.reader.aggregationRule=null'
must_fail "must not set scopes" "${on[@]}" --set-json 'roles.reader.scopes={"organization":{"a:b":["read"]}}'
must_fail "needs the role on aggregation.allowedSources" "${on[@]}" --set-json 'aggregation.allowedSources=["fleet-operator"]'

# With it off, the built-in roles render plain and their aggregation is not checked.
must_render --set-json 'roles.reader.scopes={"organization":{"a:b":["read"]}}'
must_render --set-json 'aggregation.allowedSources=["fleet-operator"]'

# aggregation.builtinRoles must be a bool: a string "false" is truthy.
must_fail "aggregation.builtinRoles must be true or false" --set-string aggregation.builtinRoles=false
must_fail "aggregation.builtinRoles must be true or false" --set aggregation=null

# Label keys are checked, so a key can't inject YAML into the Role.
must_fail "is not a valid label key" --set-json 'additionalRoles={"x":{"labels":{"a: b\n    identity.unikorn-cloud.org/aggregate-to-administrator":"true"},"scopes":{"organization":{"a:b":["read"]}}}}'
must_fail "is not a valid label key" --set-json 'additionalRoles={"x":{"labels":{"Bad_Prefix/x":"y"},"scopes":{"organization":{"a:b":["read"]}}}}'
must_fail "a role name must be a DNS-1123 label" --set-json 'additionalRoles={"bad name":{"aggregationRule":{"roleRefs":["reader-base"]}}}'

# A null allow-list is an empty one: a clear error, not a nil pointer.
must_fail "aggregateTo needs the role on aggregation.allowedSources" --set aggregation.allowedSources=null --set-json 'additionalRoles={"fleet-operator":{"aggregateTo":["reader"],"scopes":{"organization":{"radar:topology":["read"]}}}}'

# Every built-in role refs exactly its base role, administrator included
# (it carries no label, so the chain-role check never covered it).
must_fail "\"administrator\": a built-in role must ref exactly administrator-base" "${on[@]}" --set-json 'roles.administrator.aggregationRule={"roleRefs":["administrator-base","platform-administrator"],"flattenToOrganization":true}'
must_fail "\"user\": a built-in role must ref exactly user-base" "${on[@]}" --set-json 'roles.user.aggregationRule={"roleRefs":["platform-administrator"]}'

# The policy pins every aggregating built-in role, administrator included, to
# its base ref and its own selector, and chain label values to "true".
pin="'$(id_of administrator)': {'ref': '$(id_of administrator-base)', 'label': 'identity.unikorn-cloud.org/aggregate-to-administrator'}"
grep -qF "$pin" <<<"$default" || die "the policy does not pin administrator's roleRefs and selector"
grep -qxF "      !variables.aggregating || !(object.metadata.name in variables.builtin) ||" <<<"$default" || die "the policy does not pin unlabelled built-in roles"
grep -qF "object.metadata.labels[k] == 'true'" <<<"$default" || die "the policy does not pin chain label values to \"true\""

# A decoy additionalRoles role holding a chart platform scope in an
# organization block does not take it off the platform-only list.
decoy='"decoy":{"scopes":{"organization":{"region:servers":["read"]}}}'
must_fail "platform-only scope \"region:servers\"" --set-json "additionalRoles={$decoy,\"fleet-operator\":{\"aggregateTo\":[\"reader\"],\"scopes\":{\"organization\":{\"region:servers\":[\"create\"]}}}}"
# A labelled role in this chart's own roles does not take it off the list either.
must_fail "platform-only scope \"region:servers\"" --set-json 'roles.fleet-operator={"aggregateTo":["reader"],"scopes":{"organization":{"region:servers":["create"]}}}'
grep -qF "'region:servers'" <<<"$(helm template test "$CHART" --set-json "additionalRoles={$decoy}")" || die "a decoy additionalRoles role takes region:servers off the platform-only list"

# Role names, descriptions and scope names can't inject YAML.
must_fail "a role name must be a DNS-1123 label" --set-json 'additionalRoles={"x\n    identity.unikorn-cloud.org/aggregate-to-administrator":{"scopes":{"organization":{"a:b":["read"]}}}}'
must_fail "a role name must be a DNS-1123 label" --set-json 'additionalRoles={"Upper":{"scopes":{"organization":{"a:b":["read"]}}}}'
inj='\n    identity.unikorn-cloud.org/aggregate-to-administrator: \"true\"'
out=$(helm template test "$CHART" --set-json "additionalRoles={\"x\":{\"description\":\"d$inj\",\"scopes\":{\"global\":{\"a:b$inj\":[\"read\"]},\"organization\":{\"a:b$inj\":[\"read\"]},\"project\":{\"a:b$inj\":[\"read\"]}}}}")
doc=$(must_role_doc "$out" x) || exit 1
[[ "$(yq '.metadata.labels | keys | map(select(test("aggregate-to-"))) | length' <<<"$doc")" == 0 ]] || die "a description or scope name injects a label"
want=$(printf 'd\n    identity.unikorn-cloud.org/aggregate-to-administrator: "true"')
[[ "$(yq '.metadata.annotations."unikorn-cloud.org/description"' <<<"$doc")" == "$want" ]] || die "description not rendered as one string"
for block in global organization project; do
	[[ "$(yq ".spec.scopes.$block | length" <<<"$doc")" == 1 ]] || die "a $block scope name injects a scope"
	[[ "$(yq ".spec.scopes.$block[0].name" <<<"$doc")" == "a:b${want#d}" ]] || die "$block scope name not rendered as one string"
done

# A built-in role must not set labels: off they would be dropped silently.
must_fail "\"reader\": a built-in role must not set labels" --set-json 'roles.reader.labels={"example.com/team":"x"}'
must_fail "\"administrator\": a built-in role must not set labels" "${on[@]}" --set-json 'roles.administrator.labels={"example.com/team":"x"}'

echo "role aggregation render checks passed"
