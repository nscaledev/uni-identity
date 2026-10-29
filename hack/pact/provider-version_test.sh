#!/usr/bin/env bash
# Tests hack/pact/provider-version.sh against a throwaway git repository: a main commit is accepted,
# a commit off main or an unknown commit exits 2 (skip), and a short SHA or a ref name is refused.
# Run: hack/pact/provider-version_test.sh
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/provider-version.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $1" >&2; exit 1; }

git -C "$tmp" init -q -b main
commit() { git -C "$tmp" -c user.name=t -c user.email=t@t commit -q --allow-empty -m "$1"; git -C "$tmp" rev-parse HEAD; }
release="$(commit release)"
commit later > /dev/null
git -C "$tmp" update-ref refs/remotes/origin/main HEAD
git -C "$tmp" checkout -q -b side "$release"
side="$(commit side)"

check() { (cd "$tmp" && "$SCRIPT" "$1") 2> "$tmp/err"; }

[ "$(check "$release")" = "$release" ] || fail "a commit on main was refused"
echo "ok  a commit on origin/main is accepted"

for off in "$side" "$(printf 'f%.0s' {1..40})"; do
  rc=0; check "$off" > /dev/null || rc=$?
  [ "$rc" = 2 ] || fail "a full SHA off main gave exit $rc, want 2 (skip): '$off'"
  grep -q "not a commit on origin/main" "$tmp/err" || fail "the skip didn't say why"
done
echo "ok  a commit off main or an unknown commit exits 2, so the workflow skips it"

for bad in "${release:0:12}" main "$release; echo injected" ""; do
  rc=0; check "$bad" > /dev/null || rc=$?
  [ "$rc" = 1 ] || fail "a malformed provider_version gave exit $rc, want 1: '$bad'"
  grep -q "not a full commit SHA" "$tmp/err" || fail "the refusal didn't say why"
done
echo "ok  a short SHA, a ref name, an injected command or an empty value is refused"
