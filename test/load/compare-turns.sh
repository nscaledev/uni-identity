#!/usr/bin/env bash
# Runs the load phases against two builds in the order baseline, candidate,
# candidate, baseline, and records each turn in its own folder.
#
# Usage: compare-turns.sh
#
# Output: OUT_DIR/turns.json and OUT_DIR/turns/<n>-<build>/ per turn, each
# holding what run-phases.sh and warmup.sh write, then OUT_DIR/ceiling/<build>/
# per build, holding what ceiling.sh writes. Counting the audit log
# (count-turns.sh) and the summary (compare.sh) come after.
#
# Environment (all required unless a default is shown):
#   BASELINE_REF, CANDIDATE_REF       names for messages and the summary
#   BASELINE_TAG, CANDIDATE_TAG       image tags, already loaded; must differ
#   NAMESPACE, RELEASE   as swap-build.sh
#   OUT_DIR, BASE_URL, TOKENS, SERVER_DEPLOYMENT, RATE, DURATION and the other
#     run-phases.sh and warmup.sh variables
#
# Each turn: swap-build.sh switches the server's image and restarts it, then
# warmup.sh restarts it
# WARMUP_RESTARTS times. The turns run the steady state only (CEILING is forced
# to false). After the fourth turn, unless CEILING is false, each build gets
# one ceiling search (ceiling.sh), on a fresh restart, baseline first. Stops at
# the first step that fails.
set -euo pipefail

: "${BASELINE_REF:?}" "${CANDIDATE_REF:?}"
: "${BASELINE_TAG:?}" "${CANDIDATE_TAG:?}" "${OUT_DIR:?}" "${RELEASE:?}" "${NAMESPACE:?}"
[[ "${BASELINE_TAG}" != "${CANDIDATE_TAG}" ]] || { echo "ERROR: the two builds need different image tags" >&2; exit 1; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The turns are steady state only; the ceiling (CEILING, default true) runs after them.
CEILING_WANTED="${CEILING:-true}"
export CEILING=false
export SERVER_DEPLOYMENT="${SERVER_DEPLOYMENT:-${RELEASE}-server}"
# shellcheck source=test/load/lib.sh
. "${HERE}/lib.sh"

mkdir -p "${OUT_DIR}/turns"
jq -n --arg b "${BASELINE_REF}" --arg c "${CANDIDATE_REF}" \
  '{baselineRef: $b, candidateRef: $c, order: ["baseline", "candidate", "candidate", "baseline"]}' > "${OUT_DIR}/turns.json"

n=0
for build in baseline candidate candidate baseline; do
  n=$((n + 1))
  if [[ "${build}" == baseline ]]; then
    name="${BASELINE_REF}" tag="${BASELINE_TAG}"
  else
    name="${CANDIDATE_REF}" tag="${CANDIDATE_TAG}"
  fi
  echo "==> Turn ${n} of 4: ${build} (${name})" >&2

  turn_dir="${OUT_DIR}/turns/${n}-${build}"
  mkdir -p "${turn_dir}"
  step() { echo "ERROR: turn ${n} (${build}, ${name}) failed at $1" >&2; exit 1; }

  "${HERE}/swap-build.sh" "${name}" "${tag}" || step "the switch to the build"
  OUT_DIR="${turn_dir}" "${HERE}/warmup.sh" || step "the warm-up restarts"
  OUT_DIR="${turn_dir}" "${HERE}/run-phases.sh" || step "the load phases (k6 warm-up, phases, thresholds or CPU read; see its output above)"
done

# One ceiling search per build. Each starts on a fresh pod, as a turn does, and
# takes its idle CPU from that build's last turn. Report-only.
for build in baseline candidate; do
  [[ "${CEILING_WANTED}" == true ]] || break
  if [[ "${build}" == baseline ]]; then
    name="${BASELINE_REF}" tag="${BASELINE_TAG}" idle_from="${OUT_DIR}/turns/4-baseline/phases.json"
  else
    name="${CANDIDATE_REF}" tag="${CANDIDATE_TAG}" idle_from="${OUT_DIR}/turns/3-candidate/phases.json"
  fi
  echo "==> Ceiling: ${build} (${name})" >&2
  "${HERE}/swap-build.sh" "${name}" "${tag}" || { echo "ERROR: the ceiling search for ${build} (${name}) failed at the switch to the build" >&2; exit 1; }
  IDLE_CORES=$(idle_cores "${idle_from}") OUT_DIR="${OUT_DIR}/ceiling/${build}" "${HERE}/ceiling.sh" \
    || { echo "ERROR: the ceiling search for ${build} (${name}) failed (see its output above)" >&2; exit 1; }
done
