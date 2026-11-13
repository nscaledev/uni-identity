#!/usr/bin/env bash
# Finds each phase's ceiling: the highest rate identity serves with no failed
# request. Report-only; it fails only when the tooling does.
#
# Usage: ceiling.sh
#
# Per phase (see "The ceiling" in the README):
#   1. one ramp from RATE to CEILING_MAX over 120 s that stops at the first
#      failure: a non-200, a 5 s timeout, or k6 falling behind its schedule
#      because it ran out of VUs. R is the rate when that failure started. No failure
#      means R is CEILING_MAX, with topReached true.
#   2. 30 s holds, each ended by its own CPU read: 0.9R, then 0.7R, then 0.5R,
#      stopping at the first that passes: no failed request and at
#      least 95% of the target rate delivered. The ceiling is
#      that hold's rate; if all three fail it is null.
# The decisions are in ceiling.jq.
#
# Output: OUT_DIR/ceiling-<phase>.json, plus the k6 summaries it came from and
# k6's per-request logs (k6-*.log), which the console does not show.
#
# Environment (all required unless a default is shown):
#   BASE_URL, TOKENS, OUT_DIR, NAMESPACE, SERVER_DEPLOYMENT   as run-phases.sh
#   IDLE_CORES    server CPU with no load, in cores (from run-phases.sh)
#   RATE          where the ramp starts, requests per second (20)
#   CEILING_MAX   the ramp's top, requests per second (2000)
#   HOLD_SECONDS  length of each hold (30)
set -euo pipefail

: "${BASE_URL:?}" "${TOKENS:?}" "${OUT_DIR:?}" "${NAMESPACE:?}" "${SERVER_DEPLOYMENT:?}" "${IDLE_CORES:?}"
export BASE_URL TOKENS
RATE="${RATE:-20}" CEILING_MAX="${CEILING_MAX:-2000}" HOLD_SECONDS="${HOLD_SECONDS:-30}"
[[ "${RATE}" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: RATE must be a positive integer" >&2; exit 1; }
[[ "${HOLD_SECONDS}" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: HOLD_SECONDS must be a positive integer" >&2; exit 1; }
[[ "${CEILING_MAX}" =~ ^[1-9][0-9]*$ ]] && (( CEILING_MAX > RATE )) \
  || { echo "ERROR: CEILING_MAX must be an integer above RATE" >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/load/lib.sh
. "${HERE}/lib.sh"
mkdir -p "${OUT_DIR}"

# k6 exits 99 when a threshold fails, which is how a failed request shows. Any
# other non-zero exit is the tooling and stops the run. LOG is k6's own log.
run_k6() {
  local status=0
  k6_run "$1" >&2 || status=$?
  [[ "${status}" -eq 0 || "${status}" -eq 99 ]] || { echo "ERROR: k6 exited ${status} for ${PHASE}" >&2; k6_excerpt "$1"; exit 1; }
}

# Warm up: caches and validators are not what is measured. A restart has
# just cleared them.
echo "==> Warming up for the ceiling" >&2
for phase in "${PHASES[@]}"; do
  PHASE="${phase}" MODE=fixed RATE=5 DURATION=5 SUMMARY_OUT="${OUT_DIR}/warmup-ceiling-${phase}.json" \
    k6_run "${OUT_DIR}/warmup-ceiling-${phase}.log" >&2 \
      || { echo "ERROR: warm-up of ${phase} failed; fixtures or trust are wrong" >&2; k6_excerpt "${OUT_DIR}/warmup-ceiling-${phase}.log"; exit 1; }
done

for phase in "${PHASES[@]}"; do
  echo "==> Ceiling ${phase}: ramp ${RATE} to ${CEILING_MAX} req/s (failures expected: this finds the edge)" >&2
  export PHASE="${phase}"
  MODE=ceiling RATE="${RATE}" CEILING_MAX="${CEILING_MAX}" SUMMARY_OUT="${OUT_DIR}/k6-ceiling-${phase}.json" run_k6 "${OUT_DIR}/k6-ceiling-${phase}.log"
  ramp="${OUT_DIR}/k6-ceiling-${phase}.json"
  result=$(jq -c -L "${HERE}" 'include "ceiling"; ramp_result' "${ramp}")
  r=$(jq -r .r <<< "${result}")
  echo "==> ${phase}: first failure at $(jq -r '.firstFailureRps // "none"' <<< "${result}") req/s" >&2

  # The reads span the quiet before a hold and the quiet after it; the later
  # hold starts from the earlier one's closing read, as nothing runs between.
  sleep "${SETTLE}"
  cpu_before=$(read_cpu)
  t_before=$(date +%s.%N)
  holds='[]'
  for share in 0.9 0.7 0.5; do
    rate=$(jq -n -L "${HERE}" --argjson r "${r}" --argjson s "${share}" 'include "ceiling"; hold_rate($r; $s)')
    echo "==> ${phase}: hold ${rate} req/s (${share} of ${r}) for ${HOLD_SECONDS}s (failures here mean back off)" >&2
    out="${OUT_DIR}/k6-hold-${phase}-${share}.json"
    start=$(date +%s.%N)
    MODE=fixed RATE="${rate}" DURATION="${HOLD_SECONDS}" SUMMARY_OUT="${out}" run_k6 "${OUT_DIR}/k6-hold-${phase}-${share}.log"
    end=$(date +%s.%N)
    sleep "${SETTLE}"
    cpu_after=$(read_cpu)
    t_after=$(date +%s.%N)
    # The same figure as a steady-state phase (metrics.jq): less the idle rate,
    # null when the hold used no more than that.
    cores=$(jq -n -L "${HERE}" --argjson c0 "${cpu_before}" --argjson c1 "${cpu_after}" --argjson idle "${IDLE_CORES}" \
      --argjson t0 "${t_before}" --argjson t1 "${t_after}" --argjson w0 "${start}" --argjson w1 "${end}" \
      'include "metrics"; cores_used(net_cpu($c1 - $c0; $idle; $t1 - $t0); $w1 - $w0)')
    holds=$(jq -c -L "${HERE}" --argjson rate "${rate}" --argjson cores "${cores}" --slurpfile k "${out}" \
      'include "ceiling"; . + [$k[0] | hold_record($rate; $cores)]' <<< "${holds}")
    cpu_before="${cpu_after}" t_before="${t_after}"
    if jq -e '.[-1].pass' <<< "${holds}" > /dev/null; then
      echo "==> ${phase}: hold ${rate} req/s: clean -> ceiling ${rate} req/s" >&2
      break
    fi
    echo "==> ${phase}: hold ${rate} req/s: $(jq -r '.[-1] | "\(.failed) failed, \(.deliveredRps | floor) delivered"' <<< "${holds}"), backing off" >&2
  done
  ceiling=$(jq -c -L "${HERE}" --argjson holds "${holds}" -n 'include "ceiling"; ceiling_of($holds)')
  [[ "${ceiling}" != null ]] || echo "==> ${phase}: no hold passed: the ceiling is below $(jq -r '.[-1].rate' <<< "${holds}") req/s" >&2

  # The ceiling's figures are its hold's; null when no hold passed.
  jq -n --arg phase "${phase}" --argjson result "${result}" --argjson holds "${holds}" \
    --argjson ceiling "${ceiling}" --slurpfile ramp "${ramp}" --argjson max "${CEILING_MAX}" '
    {phase: $phase, ceilingMax: $max, firstFailureRps: $result.firstFailureRps,
     firstFailureAtSeconds: $ramp[0].firstFailureAtSeconds, topReached: $result.topReached, r: $result.r, holds: $holds,
     ceilingRps: ($ceiling.rate // null), p95Ms: ($ceiling.p95Ms // null),
     cpuCores: ($ceiling.cpuCores // null), failureRate: ($ceiling.failureRate // null)}' \
    > "${OUT_DIR}/ceiling-${phase}.json"
done
