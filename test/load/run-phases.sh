#!/usr/bin/env bash
# Runs the load phases one after another and records, for each, its window and
# identity's CPU use. The counting and reporting steps read the result.
#
# Usage: run-phases.sh
#
# Environment (all required unless a default is shown):
#   BASE_URL           identity's base URL
#   TOKENS             tokens.json from hack/ci/loadfixtures
#   OUT_DIR            output directory: phases.json, k6-<phase>.json
#   NAMESPACE          identity's namespace
#   SERVER_DEPLOYMENT  identity's server deployment (also its container name)
#   RATE               requests per second per phase (20)
#   DURATION           seconds per phase (60)
#   CEILING            true to find each phase's ceiling after the phases
#                      (ceiling.sh), false to skip it (false)
#   CEILING_MAX        the ceiling ramp's top, requests per second (2000)
#   BASELINE_SECONDS   idle window before the phases (60)
#
# Exits 1 when any phase's k6 thresholds fail; every phase still runs. The
# ceiling search is report-only and never sets that status.
set -euo pipefail

: "${BASE_URL:?}" "${TOKENS:?}" "${OUT_DIR:?}" "${NAMESPACE:?}" "${SERVER_DEPLOYMENT:?}"
export BASE_URL TOKENS
export RATE="${RATE:-20}" DURATION="${DURATION:-60}"
CEILING="${CEILING:-false}" CEILING_MAX="${CEILING_MAX:-2000}"
BASELINE_SECONDS="${BASELINE_SECONDS:-60}"

# Inputs are checked here, so a bad one fails before any load runs.
[[ "${RATE}" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: RATE must be a positive integer" >&2; exit 1; }
[[ "${DURATION}" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: DURATION must be a positive integer" >&2; exit 1; }
# The idle rate divides by it, so zero is refused.
[[ "${BASELINE_SECONDS}" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: BASELINE_SECONDS must be a positive integer" >&2; exit 1; }
case "${CEILING}" in
  true)
    [[ "${CEILING_MAX}" =~ ^[1-9][0-9]*$ ]] && (( CEILING_MAX > RATE )) \
      || { echo "ERROR: CEILING_MAX must be an integer above RATE" >&2; exit 1; }
    ;;
  false) ;;
  *) echo "ERROR: CEILING must be true or false" >&2; exit 1 ;;
esac

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/load/lib.sh
. "${HERE}/lib.sh"
mkdir -p "${OUT_DIR}"

# Warm up: informer caches, validators and JWKS fetches are not what is measured.
echo "==> Warming up" >&2
for phase in "${PHASES[@]}"; do
  PHASE="${phase}" MODE=fixed RATE=5 DURATION=5 SUMMARY_OUT="${OUT_DIR}/warmup-${phase}.json" \
    k6 run -q "${HERE}/identity.js" || { echo "ERROR: warm-up of ${phase} failed; fixtures or trust are wrong" >&2; exit 1; }
done

echo "==> Baseline (${BASELINE_SECONDS}s, no load)" >&2
sleep "${SETTLE}"
base_cpu0=$(read_cpu)
base_start=$(now)
sleep "${BASELINE_SECONDS}"
base_end=$(now)
sleep "${SETTLE}"
base_cpu1=$(read_cpu)

phases='[]'
status=0

for phase in "${PHASES[@]}"; do
  echo "==> Phase ${phase}" >&2
  sleep "${SETTLE}"
  cpu0=$(read_cpu)
  start=$(now)

  k6_status=0
  PHASE="${phase}" MODE=fixed SUMMARY_OUT="${OUT_DIR}/k6-${phase}.json" k6 run -q "${HERE}/identity.js" || k6_status=$?

  end=$(now)
  sleep "${SETTLE}"
  cpu1=$(read_cpu)

  [[ "${k6_status}" -eq 0 ]] || status=1

  # Requests are the 200 responses: failures do no cache-served work and
  # would dilute calls per request.
  phases=$(jq -c --arg name "${phase}" --arg start "${start}" --arg end "${end}" \
    --argjson cpu0 "${cpu0}" --argjson cpu1 "${cpu1}" --argjson k6 "${k6_status}" \
    --slurpfile sum "${OUT_DIR}/k6-${phase}.json" \
    '. + [{name: $name, start: $start, end: $end, requests: ($sum[0].requests - $sum[0].countNotOK), cpuBefore: $cpu0, cpuAfter: $cpu1, k6Exit: $k6}]' <<< "${phases}")
done

jq -n --arg bs "${base_start}" --arg be "${base_end}" \
  --argjson c0 "${base_cpu0}" --argjson c1 "${base_cpu1}" --argjson phases "${phases}" \
  --argjson settle "${SETTLE}" \
  '{baseline: {start: $bs, end: $be, cpuBefore: $c0, cpuAfter: $c1}, settleSeconds: $settle, phases: $phases}' \
  > "${OUT_DIR}/phases.json"

# Report-only, after every steady window so its load never touches one.
if [[ "${CEILING}" == true ]]; then
  IDLE_CORES=$(idle_cores "${OUT_DIR}/phases.json") OUT_DIR="${OUT_DIR}/ceiling" "${HERE}/ceiling.sh"
fi

exit "${status}"
