#!/usr/bin/env bash
# Checks the count gate on a hand-made audit log: count-audit.sh (and so
# count-audit.jq: the limit, other users, a repeated audit ID, a window's edges,
# a blind probe) and gate-summary.sh; and that run-phases.sh fails when k6's
# thresholds fail (a 5xx), using a stub k6, kubectl and docker. Needs only bash and jq.
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
# Like k6, it logs to the file named by --log-output=file=PATH,level=warning,
# or to the console without it.
logfile=/dev/stderr
for a in "$@"; do
  case "${a}" in --log-output=file=*,level=warning) logfile="${a#--log-output=file=}"; logfile="${logfile%,level=warning}" ;; esac
done
jq -n '{requests: 400, countNotOK: 0}' > "${SUMMARY_OUT}"
echo "stub summary ${PHASE}"
for _ in 1 2 3 4 5 6 7 8; do echo 'time="x" level=warning msg="Request Failed" error="EOF"' >> "${logfile}"; done
if [[ "${PHASE}" == acl-heavy && "${DURATION}" != 5 ]]; then
  echo 'time="x" level=error msg="thresholds on metrics have been crossed"' >> "${logfile}"
  exit 99
fi
K6
cat > "${DIR}/bin/kubectl" <<'KUBECTL'
#!/usr/bin/env bash
case "$*" in
  *"get pod -n"*"-l app="*) echo '{"items":[{"metadata":{"name":"pod-0"}}]}' ;;
  *"get pod -n"*"pod-0 -o json"*) echo '{"spec":{"nodeName":"node-0"},"status":{"containerStatuses":[{"name":"sidecar","containerID":"containerd://sidecarid"},{"name":"srv","containerID":"containerd://srvid"}]}}' ;;
  *) echo "stub kubectl: unexpected $*" >&2; exit 1 ;;
esac
KUBECTL
cat > "${DIR}/bin/docker" <<'DOCKER'
#!/usr/bin/env bash
# The CPU read: docker exec NODE crictl stats -o json --id ID, for the server's container only.
[[ "$*" == "exec node-0 crictl stats -o json --id srvid" ]] \
  || { echo "stub docker: unexpected $*" >&2; exit 1; }
echo '{"stats":[{"cpu":{"usageCoreNanoSeconds":{"value":"1000000000"}}}]}'
DOCKER
chmod +x "${DIR}/bin/k6" "${DIR}/bin/kubectl" "${DIR}/bin/docker"
rc=0
PATH="${DIR}/bin:${PATH}" BASE_URL=http://unused TOKENS=unused OUT_DIR="${DIR}/run" NAMESPACE=ns SERVER_DEPLOYMENT=srv \
  SETTLE=0 BASELINE_SECONDS=1 RATE=1 DURATION=1 "${HERE}/run-phases.sh" > "${DIR}/run.log" 2>&1 || rc=$?
got=$(jq -r '[.phases[] | "\(.name)=\(.k6Exit)"] | join(" ")' "${DIR}/run/phases.json" 2>/dev/null || true)
if [[ "${rc}" != 0 && "${got}" == "auth0-bearer=0 passport-exchange=0 acl-heavy=99 service-account=0" ]]; then
  echo "ok   run-phases-k6-failure"
else
  echo "FAIL run-phases-k6-failure: exit ${rc}; phases: ${got}"; cat "${DIR}/run.log"; failed=1
fi

# The console has the summaries, and for the failed phase a FAIL line with the
# first k6 errors (at most 5); the per-request lines are in the k6 log files.
if [[ "$(grep -c 'Request Failed' "${DIR}/run.log")" -le 5 ]] && grep -q 'stub summary acl-heavy' "${DIR}/run.log"; then
  echo "ok   run-phases-console-quiet"
else
  echo "FAIL run-phases-console-quiet: per-request lines on the console, or no summary"; cat "${DIR}/run.log"; failed=1
fi
if grep -q '^FAIL acl-heavy: k6 exited 99' "${DIR}/run.log" && grep -q 'thresholds on metrics have been crossed' "${DIR}/run.log"; then
  echo "ok   run-phases-fail-line-and-excerpt"
else
  echo "FAIL run-phases-fail-line-and-excerpt"; cat "${DIR}/run.log"; failed=1
fi
if [[ "$(grep -c 'Request Failed' "${DIR}/run/k6-acl-heavy.log" 2>/dev/null)" == 8 ]]; then
  echo "ok   run-phases-k6-log-file"
else
  echo "FAIL run-phases-k6-log-file: k6-acl-heavy.log lacks the 8 per-request lines"; failed=1
fi

# server_pod: just after a rollout the old, terminating pod is listed first;
# only the live one may be read. Two live pods is an error, not a guess.
mkdir -p "${DIR}/pods/bin"
cat > "${DIR}/pods/bin/kubectl" <<'KUBECTL'
#!/usr/bin/env bash
cat "${PODS_JSON}"
KUBECTL
chmod +x "${DIR}/pods/bin/kubectl"
pods() { PODS_JSON="$1" PATH="${DIR}/pods/bin:${PATH}" NAMESPACE=ns SERVER_DEPLOYMENT=srv \
  bash -c '. "$0"; server_pod' "${HERE}/lib.sh" 2>/dev/null; }
echo '{"items":[{"metadata":{"name":"old","deletionTimestamp":"2026-01-01T00:00:00Z"}},{"metadata":{"name":"new"}}]}' > "${DIR}/pods/swap.json"
echo '{"items":[{"metadata":{"name":"a"}},{"metadata":{"name":"b"}}]}' > "${DIR}/pods/two.json"
if [[ "$(pods "${DIR}/pods/swap.json")" == new ]]; then
  echo "ok   server-pod-skips-terminating"
else
  echo "FAIL server-pod-skips-terminating: got '$(pods "${DIR}/pods/swap.json")'"; failed=1
fi
if ! pods "${DIR}/pods/two.json" > /dev/null; then
  echo "ok   server-pod-two-live-fails"
else
  echo "FAIL server-pod-two-live-fails: picked one of two live pods"; failed=1
fi

# read_cpu: the CPU figure is crictl's usageCoreNanoSeconds for the server's own
# container (not a sidecar's), with containerd:// stripped from its ID, in
# seconds. A missing or empty figure stops the run: it is never 0.
mkdir -p "${DIR}/cpu/bin"
cat > "${DIR}/cpu/bin/kubectl" <<'KUBECTL'
#!/usr/bin/env bash
case "$*" in
  *"-l app="*) echo '{"items":[{"metadata":{"name":"pod-0"}}]}' ;;
  *"pod-0 -o json"*) cat "${POD_JSON}" ;;
  *) exit 1 ;;
esac
KUBECTL
cat > "${DIR}/cpu/bin/docker" <<'DOCKER'
#!/usr/bin/env bash
echo "$*" > "${DOCKER_ARGS}"
printf '%s' "${CRICTL_OUT}"
DOCKER
chmod +x "${DIR}/cpu/bin/kubectl" "${DIR}/cpu/bin/docker"
echo '{"spec":{"nodeName":"node-0"},"status":{"containerStatuses":[{"name":"sidecar","containerID":"containerd://sidecarid"},{"name":"srv","containerID":"containerd://srvid"}]}}' > "${DIR}/cpu/ok.json"
echo '{"spec":{"nodeName":"node-0"},"status":{"containerStatuses":[{"name":"sidecar","containerID":"containerd://sidecarid"}]}}' > "${DIR}/cpu/nosrv.json"
# cpu POD_JSON CRICTL_OUT: runs read_cpu; prints its stdout, then the exit status.
cpu() {
  local out rc=0
  out=$(POD_JSON="$1" CRICTL_OUT="$2" DOCKER_ARGS="${DIR}/cpu/args" PATH="${DIR}/cpu/bin:${PATH}" NAMESPACE=ns SERVER_DEPLOYMENT=srv \
    bash -c '. "$0"; read_cpu' "${HERE}/lib.sh" 2> /dev/null) || rc=$?
  echo "${out}|${rc}"
}
GOOD='{"stats":[{"cpu":{"usageCoreNanoSeconds":{"value":"2500000000"}}}]}'
got=$(cpu "${DIR}/cpu/ok.json" "${GOOD}")
if [[ "${got}" == "2.500|0" && "$(cat "${DIR}/cpu/args")" == "exec node-0 crictl stats -o json --id srvid" ]]; then
  echo "ok   read-cpu-server-container-id"
else
  echo "FAIL read-cpu-server-container-id: got '${got}', docker ran '$(cat "${DIR}/cpu/args")'"; failed=1
fi
for case in "empty:" 'no-stats:{"stats":[]}' 'no-cpu:{"stats":[{"memory":{}}]}' 'null-value:{"stats":[{"cpu":{"usageCoreNanoSeconds":{}}}]}'; do
  got=$(cpu "${DIR}/cpu/ok.json" "${case#*:}")
  if [[ "${got}" == "|1" ]]; then
    echo "ok   read-cpu-missing-figure-fails (${case%%:*})"
  else
    echo "FAIL read-cpu-missing-figure-fails (${case%%:*}): got '${got}'"; failed=1
  fi
done
got=$(cpu "${DIR}/cpu/nosrv.json" "${GOOD}")
if [[ "${got}" == "|1" ]]; then
  echo "ok   read-cpu-no-server-container-fails"
else
  echo "FAIL read-cpu-no-server-container-fails: got '${got}'"; failed=1
fi

exit "${failed}"
