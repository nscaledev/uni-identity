#!/usr/bin/env bash
# Checks skips.jq against a hand-made Ginkgo report. Needs only jq.
# Usage: skips_test.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ginkgo reports a spec that a label or focus filter leaves out, and one skipped because an
# earlier ordered spec failed, with State "skipped" too; only a Skip() call, here or in a
# BeforeAll above, is a real skip. A
# Skip() in BeforeSuite leaves every spec looking filtered, so the BeforeSuite node must count.
report='[{"SpecReports": [
  {"LeafNodeType": "BeforeSuite", "State": "skipped", "LeafNodeText": "", "Failure": {"Message": "no staging access"}},
  {"LeafNodeType": "It", "State": "passed", "ContainerHierarchyTexts": ["Users"], "LeafNodeText": "lists"},
  {"LeafNodeType": "It", "State": "skipped", "ContainerHierarchyTexts": ["Users"], "LeafNodeText": "filtered", "Failure": {"Message": ""}},
  {"LeafNodeType": "It", "State": "skipped", "ContainerHierarchyTexts": ["Users"], "LeafNodeText": "after a failure", "Failure": {"Message": "Spec skipped because an earlier spec in an ordered container failed"}},
  {"LeafNodeType": "It", "State": "skipped", "ContainerHierarchyTexts": ["RBAC", "When authenticated as a user"], "LeafNodeText": "denies", "Failure": {"Message": "USER_AUTH_TOKEN is required"}},
  {"LeafNodeType": "It", "State": "skipped", "ContainerHierarchyTexts": ["Roles"], "LeafNodeText": "binds", "Failure": {"Message": "Spec skipped because Skip() was called in BeforeAll"}}
]}]'

want='no staging access: BeforeSuite
USER_AUTH_TOKEN is required: RBAC > When authenticated as a user > denies
Spec skipped because Skip() was called in BeforeAll: Roles > binds'
got="$(jq -r -f "${HERE}/skips.jq" <<<"${report}")"

if [[ "${got}" == "${want}" ]]; then
  echo "ok   skips: only Skip() calls are listed"
else
  echo "FAIL skips: want '${want}' got '${got}'"
  exit 1
fi
