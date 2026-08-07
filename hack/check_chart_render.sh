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

# Render assertions for globalRoleBindings; wired into `make lint`.
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

echo "chart render checks OK"
