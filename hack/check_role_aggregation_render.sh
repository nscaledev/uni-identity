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

CHART=charts/identity

die() { echo "FAIL: $*" >&2; exit 1; }

# role_doc <render> <name> prints the Role manifest whose name label is <name>.
role_doc() { awk -v want="$2" 'BEGIN{RS="\n---\n"} /kind: Role\n/ && $0 ~ "unikorn-cloud.org/name: "want"\n" {print}' <<<"$1"; }

# must_role_doc <render> <name> is role_doc, failing if there is no such Role,
# so a negative grep on it can't pass on an empty document.
must_role_doc() {
	local doc
	doc=$(role_doc "$1" "$2")
	[[ -n "$doc" ]] || die "no Role rendered for $2"
	echo "$doc"
}

# spec_of <doc> prints the spec block of a Role manifest, without protected.
spec_of() { awk '/^spec:/{p=1} p' <<<"$1" | grep -vx '  protected: true'; }

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
	[[ "$(spec_of "$doc")" == "$(spec_of "$base")" ]] || die "$name does not hold exactly the scopes of $name-base"
	grep -q "^    organization:" <<<"$doc" || die "$name has no organization scopes"
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
pos_base=$(grep -m1 -n "unikorn-cloud.org/name: administrator-base$" <<<"$aggregating" | cut -d: -f1) || die "administrator-base is not rendered"
pos_admin=$(grep -m1 -n "unikorn-cloud.org/name: administrator$" <<<"$aggregating" | cut -d: -f1) || die "administrator is not rendered"
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
done

# The role controller is deployed, and writes role status in its own namespace only.
awk 'BEGIN{RS="\n---\n"} /kind: Deployment\n/ && /\n  name: test-role-controller\n/ {found=1} END{exit !found}' <<<"$default" || die "role controller Deployment is not rendered"
awk 'BEGIN{RS="\n---\n"} /kind: ClusterRole\n/ && /roles\/status/ {found=1} END{exit !found}' <<<"$default" && die "roles/status is granted cluster-wide"
awk 'BEGIN{RS="\n---\n"} /kind: Role\n/ && /name: test-role-controller\n/ && /roles\/status/ {found=1} END{exit !found}' <<<"$default" || die "roles/status is not granted in the release namespace"

# Custom labels and aggregateTo on additionalRoles; duplicate targets render once.
out=$(helm template test "$CHART" --set-json 'additionalRoles={"fleet-operator":{"description":"Fleet operator","labels":{"example.com/team":"radar"},"aggregateTo":["reader","reader"],"scopes":{"organization":{"radar:topology":["read"]}}}}')
doc=$(must_role_doc "$out" fleet-operator) || exit 1
grep -qF 'example.com/team: "radar"' <<<"$doc" || die "custom label not rendered"
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
must_fail "a chain role must ref exactly reader-base" --set-json 'roles.reader.aggregationRule={"roleRefs":["reader-base","platform-administrator"]}'
must_fail "labels must not set \"identity.unikorn-cloud.org/aggregate-to-administrator\"" --set-json 'additionalRoles={"x":{"labels":{"identity.unikorn-cloud.org/aggregate-to-administrator":"true"},"scopes":{"organization":{"a:b":["read"]}}}}'
must_fail "labels must not set \"unikorn-cloud.org/name\"" --set-json 'additionalRoles={"x":{"labels":{"unikorn-cloud.org/name":"administrator"},"scopes":{"organization":{"a:b":["read"]}}}}'

# A null aggregation block means an empty allow-list: a clear error, not a nil pointer.
must_fail "aggregateTo needs the role on aggregation.allowedSources" --set aggregation=null

echo "role aggregation render checks passed"
