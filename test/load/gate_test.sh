#!/usr/bin/env bash
# Checks the count gate on a hand-made audit log: count-audit.sh (and so
# count-audit.jq: the limit, other users, a repeated audit ID, a window's edges,
# a blind probe) and gate-summary.sh; and that run-phases.sh fails when k6's
# thresholds fail (a 5xx), using a stub k6 and kubectl. Needs only bash and jq.
# Usage: gate_test.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR="$(mktemp -d)"
trap 'rm -rf "${DIR}"' EXIT
failed=0
export IDENTITY_USER=system:serviceaccount:ns:rel-server

# Phases: baseline 10:00:00-10:00:10, "quiet" 10:00:10-10:00:30 (400 requests),
# "noisy" 10:00:30-10:00:50 (400 requests).
phases() { # QUIET_K6_EXIT
  jq -n --argjson k6 "$1" '{baseline: {start: "2026-01-01T10:00:00Z", end: "2026-01-01T10:00:10Z"},
    phases: [{name: "quiet", start: "2026-01-01T10:00:10Z", end: "2026-01-01T10:00:30Z", requests: 400, k6Exit: $k6},
             {name: "noisy", start: "2026-01-01T10:00:30Z", end: "2026-01-01T10:00:50Z", requests: 400, k6Exit: 0}]}' > "${DIR}/phases.json"
}

# event ID TIME USER: one audit event.
event() { jq -cn --arg id "$1" --arg t "$2" --arg u "$3" \
  '{auditID: $id, verb: "get", user: {username: $u}, objectRef: {resource: "organizations"}, requestReceivedTimestamp: $t}'; }

# log NOISY_CALLS: one call in quiet's window (within the 20-call allowance),
# NOISY_CALLS in noisy's, and 100 from another user, which must be ignored.
log() {
  {
    event start 2026-01-01T10:00:00Z "${IDENTITY_USER}"
    event q1 2026-01-01T10:00:15Z "${IDENTITY_USER}"
    for i in $(seq 1 "$1"); do event "n${i}" 2026-01-01T10:00:35Z "${IDENTITY_USER}"; done
    for i in $(seq 1 100); do event "o${i}" 2026-01-01T10:00:35Z system:serviceaccount:other:x; done
  } > "${DIR}/audit.log"
}

# check NAME WANT_EXIT WANT_TEXT: runs both scripts; wants count-audit's exit
# status and, in gate-summary's output, WANT_TEXT (empty: no output at all).
check() {
  local rc=0 out
  "${HERE}/count-audit.sh" "${DIR}/audit.log" "${DIR}/phases.json" "${DIR}/counts.json" 2> "${DIR}/err" || rc=$?
  out=$("${HERE}/gate-summary.sh" "${DIR}/phases.json" "${DIR}/counts.json")
  # A failing gate also says so in the step log (count-audit's stderr).
  if [[ "${rc}" == "$2" && ( "$2" == 0 || "$(cat "${DIR}/err")" == *FAIL* ) && ( -z "$3" && -z "${out}" || -n "$3" && "${out}" == *"$3"* ) ]]; then
    echo "ok   $1"
  else
    echo "FAIL $1: exit ${rc} (want $2); summary: ${out}; log: $(cat "${DIR}/err")"; failed=1
  fi
}

phases 0; log 0;  check pass 0 ""
phases 0; log 30; check calls-over-gate 1 "**noisy**: 0.07 API-server calls per request over 400 requests"
phases 1; log 0;  check 5xx-in-k6 0 "**quiet**: k6 thresholds failed"
phases 0; : > "${DIR}/audit.log"; check blind-probe 1 "no events from identity"

# A watch logs one call twice (two stages): the same audit ID counts once.
# 30 events with 8 IDs in noisy's window is 8 calls, under its 20; counted as
# 30 it fails. Events at a window's end (10:00:50, noisy's) are outside it:
# 12 on the edge plus 15 inside would be over the allowance if counted.
phases 0
{ event q1 2026-01-01T10:00:15Z "${IDENTITY_USER}"
  for i in $(seq 1 30); do event "d$((i % 8))" 2026-01-01T10:00:35Z "${IDENTITY_USER}"; done; } > "${DIR}/audit.log"
check repeated-audit-id 0 ""
phases 0
{ event q1 2026-01-01T10:00:15Z "${IDENTITY_USER}"
  for i in $(seq 1 15); do event "n${i}" 2026-01-01T10:00:35Z "${IDENTITY_USER}"; done
  for i in $(seq 1 12); do event "e${i}" 2026-01-01T10:00:50Z "${IDENTITY_USER}"; done; } > "${DIR}/audit.log"
check window-end-excluded 0 ""

# run-phases.sh: a stub k6 fails acl-heavy only (as a 5xx would); the script
# must exit non-zero, still run every phase, and record the k6 exit.
mkdir -p "${DIR}/bin"
cat > "${DIR}/bin/k6" <<'K6'
#!/usr/bin/env bash
jq -n '{requests: 400, countNotOK: 0}' > "${SUMMARY_OUT}"
[[ "${PHASE}" != acl-heavy || "${DURATION}" == 5 ]] || exit 99
K6
cat > "${DIR}/bin/kubectl" <<'KUBECTL'
#!/usr/bin/env bash
case "$*" in
  *"get pod -n"*"-l app="*) echo -n pod-0 ;;
  *"get pod -n"*nodeName*) echo -n node-0 ;;
  *"get --raw"*) echo 'container_cpu_usage_seconds_total{container="srv",pod="pod-0"} 1' ;;
  *) echo "stub kubectl: unexpected $*" >&2; exit 1 ;;
esac
KUBECTL
chmod +x "${DIR}/bin/k6" "${DIR}/bin/kubectl"
rc=0
PATH="${DIR}/bin:${PATH}" BASE_URL=http://unused TOKENS=unused OUT_DIR="${DIR}/run" NAMESPACE=ns SERVER_DEPLOYMENT=srv \
  SETTLE=0 BASELINE_SECONDS=1 RATE=1 DURATION=1 "${HERE}/run-phases.sh" > "${DIR}/run.log" 2>&1 || rc=$?
got=$(jq -r '[.phases[] | "\(.name)=\(.k6Exit)"] | join(" ")' "${DIR}/run/phases.json" 2>/dev/null || true)
if [[ "${rc}" != 0 && "${got}" == "auth0-bearer=0 passport-exchange=0 acl-heavy=99 service-account=0" ]]; then
  echo "ok   run-phases-k6-failure"
else
  echo "FAIL run-phases-k6-failure: exit ${rc}; phases: ${got}"; cat "${DIR}/run.log"; failed=1
fi

exit "${failed}"
