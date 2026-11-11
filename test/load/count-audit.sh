#!/usr/bin/env bash
# Counts identity's kube-apiserver calls per load phase and gates on them.
#
# Usage: count-audit.sh AUDIT_LOG PHASES_JSON OUT_JSON
#
# AUDIT_LOG   kube-apiserver audit log (JSON lines).
# PHASES_JSON {"baseline":{"start","end"},"phases":[{"name","start","end","requests"}]}
#             with RFC 3339 UTC timestamps.
# OUT_JSON    per-phase counts, written even when the gate fails.
#
# Environment:
#   IDENTITY_USER         audit user of identity's server ServiceAccount
#   MAX_CALLS_PER_REQUEST gate, default 0.05 (leaves room for stray background calls)
#
# Exits 1 when any phase exceeds the gate, saw no requests, or the log has no
# events at all from IDENTITY_USER.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 AUDIT_LOG PHASES_JSON OUT_JSON" >&2
  exit 2
fi

AUDIT_LOG="$1"
PHASES="$2"
OUT="$3"
USER_NAME="${IDENTITY_USER:?IDENTITY_USER is required}"
MAX="${MAX_CALLS_PER_REQUEST:-0.05}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Filter while streaming so only identity's events are held in memory.
jq -c --arg user "${USER_NAME}" 'select(.user.username == $user)' "${AUDIT_LOG}" \
  | jq -s --slurpfile phases "${PHASES}" --argjson max "${MAX}" -f "${HERE}/count-audit.jq" \
  > "${OUT}"

jq -r '.phases[] | select(.pass | not)
  | "FAIL \(.name): " + (if .callsPerRequest == null then "no requests were made" else "\(.callsPerRequest) API-server calls per request over \(.requests) requests (gate \($ENV.MAX_CALLS_PER_REQUEST // "0.05"))" end)' "${OUT}" >&2

if [[ "$(jq '.identityEvents' "${OUT}")" -eq 0 ]]; then
  echo "FAIL: the audit log has no events from ${USER_NAME}; the probe is blind (wrong user or audit policy)" >&2
fi

jq -e '.pass' "${OUT}" > /dev/null
