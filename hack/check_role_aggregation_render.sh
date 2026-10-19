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

# id_of <name> computes the role ID the chart derives from a name.
id_of() { local s; s=$(printf %s "$1" | sha256sum | cut -c1-32); echo "f${s:1:7}-${s:8:4}-4${s:13:3}-8${s:17:3}-${s:20:12}"; }

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

out=$(helm template test "$CHART")

# The built-in roles keep their IDs, so every group that names them is unchanged.
for name in administrator auditor user reader; do
	doc=$(role_doc "$out" "$name")
	[[ -n "$doc" ]] || die "no Role rendered for $name"
	grep -qF "name: $(id_of "$name")" <<<"$doc" || die "$name has changed ID"
	grep -q "aggregationRule:" <<<"$doc" || die "$name is not aggregating"
	grep -q "^  scopes:" <<<"$doc" && die "$name renders spec.scopes"
	grep -qF -- "- $(id_of "$name-base")" <<<"$doc" || die "$name does not ref $name-base"
done

# The chain: reader -> auditor and user; auditor and user -> administrator.
grep -qF 'identity.unikorn-cloud.org/aggregate-to-auditor: "true"' <<<"$(role_doc "$out" reader)" || die "reader is not labelled for auditor"
grep -qF 'identity.unikorn-cloud.org/aggregate-to-user: "true"' <<<"$(role_doc "$out" reader)" || die "reader is not labelled for user"
grep -qF 'identity.unikorn-cloud.org/aggregate-to-administrator: "true"' <<<"$(role_doc "$out" user)" || die "user is not labelled for administrator"
grep -qF 'identity.unikorn-cloud.org/aggregate-to-administrator: "true"' <<<"$(role_doc "$out" auditor)" || die "auditor is not labelled for administrator"

# public-administrator never aggregates.
grep -q "aggregationRule:" <<<"$(role_doc "$out" public-administrator)" && die "public-administrator aggregates"

# Base roles are protected.
for name in administrator auditor user reader; do
	grep -q "protected: true" <<<"$(role_doc "$out" "$name-base")" || die "$name-base is not protected"
done

# The admission policy allow-list holds IDs, not names.
grep -qF "'$(id_of fleet-operator)'" <<<"$out" || die "fleet-operator is not on the rendered allow-list"

# The role controller is deployed.
grep -q "name: test-role-controller" <<<"$out" || die "role controller is not rendered"

# Custom labels and aggregateTo on additionalRoles.
out=$(helm template test "$CHART" --set-json 'additionalRoles={"fleet-operator":{"description":"Fleet operator","labels":{"example.com/team":"radar"},"aggregateTo":["reader"],"scopes":{"organization":{"radar:topology":["read"]}}}}')
doc=$(role_doc "$out" fleet-operator)
grep -qF 'example.com/team: "radar"' <<<"$doc" || die "custom label not rendered"
grep -qF 'identity.unikorn-cloud.org/aggregate-to-reader: "true"' <<<"$doc" || die "aggregateTo label not rendered"

must_fail "must not set scopes" --set-json 'additionalRoles={"x":{"aggregationRule":{"roleRefs":["reader-base"]},"scopes":{"organization":{"a:b":["read"]}}}}'
must_fail "names unknown role" --set-json 'additionalRoles={"x":{"aggregationRule":{"roleRefs":["typo-base"]}}}'
must_fail "names itself" --set-json 'additionalRoles={"x":{"aggregationRule":{"roleRefs":["x"]}}}'
must_fail "needs the role on aggregation.allowedSources" --set-json 'additionalRoles={"not-allowed":{"aggregateTo":["reader"],"scopes":{"organization":{"a:b":["read"]}}}}'
must_fail "a protected role cannot opt into aggregation" --set-json 'additionalRoles={"fleet-operator":{"protected":true,"aggregateTo":["reader"]}}'

echo "role aggregation render checks passed"
