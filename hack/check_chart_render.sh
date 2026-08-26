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

# Render assertions for globalRoleBindings and globalGroupRoleBindings.
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

# Render assertions for the enclave authorization profile
# (templates/enclave-authorization). The ClusterRole is the write guard, so
# its verb list is pinned directly: route omission in the binary makes write
# handlers unreachable, and this is what makes them powerless if reached.
out=$(helm template test "$CHART" --set enclaveAuthorization.enabled=true)

# manifest_by_source <source-suffix> isolates ONE rendered manifest by its
# `# Source:` comment, reading from stdin. Grepping the whole render for a
# flag proves only that the flag rendered SOMEWHERE — it would still pass if
# the flag were moved to a different (e.g. always-rendered) Deployment. This
# scopes the assertion to the one manifest that must carry it.
manifest_by_source() {
	awk -v want="$1" '
		/^# Source: / && index($0, want) { p=1 }
		p { print }
		p && /^---$/ { exit }
	'
}

enclave_deployment=$(manifest_by_source 'enclave-authorization/deployment.yaml' <<<"$out")
[[ -n "$enclave_deployment" ]] || die "could not find the enclave-authorization Deployment manifest in the render"
[[ $(grep -cE -- "^\s*-\s*--api-profile=authorization\s*\$" <<<"$enclave_deployment") -eq 1 ]] || \
	die "expected exactly one --api-profile=authorization arg in the enclave-authorization Deployment's own manifest"

# --host is the token ISSUER this profile validates against, not the address it
# serves on. It validates as a resource server, so the issuer is the centre:
# rendering enclaveAuthorization.host here rejects every centrally minted
# passport on issuer and audience. Pin the value, not just its presence.
enclave_host_arg=$(grep -oE -- "--host=[^[:space:]]+" <<<"$enclave_deployment" | head -1)
[[ "$enclave_host_arg" == "--host=https://identity.acme.org" ]] || \
	die "enclave-authorization --host must be the central identity host (identity.host), got: ${enclave_host_arg:-none}"

# The policy projection gates Service membership, so no pod takes traffic
# before the controller has published: a required (non-optional) volume plus a
# /readyz READINESS probe on the first-party container. Readiness and not
# startup is load-bearing, because the publication marker makes a withdrawal
# ready: a replacement pod during a withdrawal then joins the Service instead
# of restarting forever. Pin the kind, not just the presence.
grep -qE "^\s*readinessProbe:\s*\$" <<<"$enclave_deployment" || \
	die "enclave-authorization Deployment must gate readiness on the policy projection"
if grep -qE "^\s*startupProbe:\s*\$" <<<"$enclave_deployment"; then
	die "the policy projection must gate readiness, not startup: a startup gate restarts a pod that starts during a withdrawal"
fi
if grep -qE "^\s*optional:\s*true\s*\$" <<<"$enclave_deployment"; then
	die "the enclave-authorization policy volume must not be optional: an empty projection denies every request"
fi

enclave_clusterrole=$(awk '/^kind: ClusterRole$/{cr=1} cr && /^  name:.*-enclave-authorization$/{p=1} p{print} /^---$/{if(p){exit}; cr=0}' <<<"$out")
[[ -n "$enclave_clusterrole" ]] || die "could not find the *-enclave-authorization ClusterRole in the render"

# verbs_of extracts every "- <verb>" list item that follows a "verbs:" key,
# reading a manifest from stdin. A deny-list of write verbs (the previous
# form of this check) passes for any verb it did not name, including a
# wildcard "- '*'" that grants everything. Asserting a SUBSET of the
# read-only verbs instead closes that gap: nothing this ClusterRole grants
# can be outside {get, list, watch}, however it is spelled.
verbs_of() {
	awk '
		/^[[:space:]]*verbs:[[:space:]]*$/ { invb = 1; next }
		invb && /^[[:space:]]*-[[:space:]]*[^[:space:]]+[[:space:]]*$/ {
			line = $0
			sub(/^[[:space:]]*-[[:space:]]*/, "", line)
			sub(/[[:space:]]*$/, "", line)
			print line
			next
		}
		{ invb = 0 }
	'
}

found_verb=""
while IFS= read -r verb; do
	found_verb=1

	case "$verb" in
	get | list | watch) ;;
	*) die "enclave authorization ClusterRole verb \"$verb\" is outside the read-only subset {get, list, watch}" ;;
	esac
done < <(verbs_of <<<"$enclave_clusterrole")
[[ -n "$found_verb" ]] || die "could not find any verb in the enclave authorization ClusterRole"

default_out=$(helm template test "$CHART")
if grep -q "enclave-authorization" <<<"$default_out"; then
	die "default values must not render any enclave-authorization resource"
fi

# C1: an enclave-only release (identity.enabled: false, controllers.enabled:
# false, alongside enclaveAuthorization.enabled: true) must render no
# write-capable identity server and none of the three write-capable
# controllers that would otherwise race an enclave's replicator over the
# same projected objects.
#
# The same release must also author no central state and own no cluster-scoped
# object. roles.yaml and quotametadata.yaml are central authoring authority
# (docs/authorization/distributed-pdp-design.md section 3) and reach an enclave
# by replication; the admission policies are cluster-scoped with fixed names, so
# a second release carrying them cannot install beside the central one. Neither
# class holds an RBAC verb, so the verb sweep below cannot catch them.
gated_out=$(helm template test "$CHART" --set enclaveAuthorization.enabled=true --set identity.enabled=false --set controllers.enabled=false)

for source in templates/identity/deployment.yaml templates/organization-controller/ templates/project-controller/ templates/oauth2client-controller/ templates/roles.yaml templates/quotametadata.yaml templates/validatingadmissionpolicies/; do
	if grep -qF -- "# Source: unikorn-identity/${source}" <<<"$gated_out"; then
		die "identity.enabled=false and controllers.enabled=false must render no manifest from $source"
	fi
done

# The remaining write verb anywhere outside policy-controller/ would mean a
# write-capable ClusterRole/Role slipped past the two gates above.
# policy-controller/ is excluded on purpose: an enclave-only release still
# runs its own policy controller, which needs a narrowly scoped Role to
# publish its own ConfigMap (controllers.enabled does not cover it — see
# values.yaml).
non_policy_controller_out=$(awk '
	/^# Source: / { p = (index($0, "templates/policy-controller/") == 0) }
	p { print }
' <<<"$gated_out")

for verb in create update patch delete deletecollection; do
	if grep -qE "^\s*-\s*${verb}\s*\$" <<<"$non_policy_controller_out"; then
		die "identity.enabled=false and controllers.enabled=false render must grant no verb outside policy-controller/: $verb"
	fi
done

echo "chart render checks OK"
