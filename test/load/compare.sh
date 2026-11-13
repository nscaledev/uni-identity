#!/usr/bin/env bash
# Writes the compare run's job summary (markdown) to stdout: the absolute
# checks on the candidate, the comparison against the baseline, a table of all
# turns, the ceiling of each build side by side, then each turn's full report.
#
# Usage: compare.sh OUT_DIR
#
# Reads OUT_DIR/turns.json and OUT_DIR/turns/<n>-<build>/ (what run-phases.sh,
# warmup.sh and count-turns.sh wrote). Writes OUT_DIR/verdicts.json (compare.jq's
# output, when all four turns finished). This script never fails on the
# comparison; perf-gate.sh decides what a verdict does.
# Environment: COMPARE_MARGIN_PCT (25), COMPARE_GATE (true when CPU per request
# is gated, default false; wording only), and what report.sh reads.
set -euo pipefail

OUT_DIR="${1:?Usage: $0 OUT_DIR}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/load/lib.sh
. "${HERE}/lib.sh"
MARGIN="${COMPARE_MARGIN_PCT:-25}"
GATE="${COMPARE_GATE:-false}"
BASELINE_REF=$(jq -r .baselineRef "${OUT_DIR}/turns.json")
CANDIDATE_REF=$(jq -r .candidateRef "${OUT_DIR}/turns.json")

# One object per finished turn, in run order: {turn, build, rows, counts}.
turns='[]'
for turn_dir in "${OUT_DIR}"/turns/*/; do
  turn_dir="${turn_dir%/}"
  [[ -s "${turn_dir}/counts.json" ]] || continue
  name="${turn_dir##*/}"
  turns=$(jq -c --arg turn "${name%%-*}" --arg build "${name#*-}" \
    --slurpfile phases "${turn_dir}/phases.json" --slurpfile counts "${turn_dir}/counts.json" \
    --slurpfile k6 <(jq -c . "${turn_dir}"/k6-*.json) -L "${HERE}" '
      include "metrics";
      . + [{turn: $turn, build: $build, counts: $counts[0],
            rows: (rows($phases[0]; $counts[0]; $k6)
                   | map({name, cpuPerRequest, cpuCores, p95Ms: .k.p95Ms, failureRate: .k.failureRate, callsPerRequest: .cnt.callsPerRequest,
                          requests: .k.requests, rate5xx: .k.rate5xx}))}]' <<< "${turns}")
done

finished=$(jq length <<< "${turns}")
echo "## Load test: ${CANDIDATE_REF} against ${BASELINE_REF}"
echo
# What the baseline is: its ref and, when the caller recorded it, its commit.
jq -r '"Baseline: \(.baselineRef)" + (if .baselineCommit then " at commit \(.baselineCommit)" else "" end)' "${OUT_DIR}/turns.json"
echo

# Absolute checks, candidate only. They come first: a build that fails them is
# not rescued by a good comparison.
echo "### Absolute checks (candidate)"
echo
jq -r '
  [.[] | select(.build == "candidate")] as $c
  | if ($c | length) == 0 then "No candidate turn finished; see the failed step."
    else
      "Count gate (at most \($c[0].counts.maxCallsPerRequest) identity API-server calls per request): "
        + (if ($c | all(.counts.pass)) then "**PASS**" else "**FAIL**" end)
        + " in \($c | length) candidate turn(s).",
      "",
      "5xx responses: " + (if ($c | all(.rows | all(.rate5xx == 0))) then "**none**" else "**FAIL**, some" end) + "."
    end' <<< "${turns}"
echo

if [[ "${GATE}" == true ]]; then
  echo "### Comparison (CPU per request is gated; p95 is shown, not gated)"
else
  echo "### Comparison (report-only, not a gate)"
fi
echo
echo "Turn order: baseline, candidate, candidate, baseline. A phase is worse (or better) only when both candidate turns are more than ${MARGIN}% worse than the worse baseline turn (or better than the better one). The ceiling is reported below, per build, and not compared by this rule."
echo
rm -f "${OUT_DIR}/verdicts.json"
if [[ "${finished}" -eq 4 ]]; then
  jq -c --arg ref "${BASELINE_REF}" --argjson margin "${MARGIN}" --argjson gate "${GATE}" -L "${HERE}" -L "${HERE}" -f "${HERE}/compare.jq" <<< "${turns}" > "${OUT_DIR}/verdicts.json"
  jq -r '.[].line | "- " + .' "${OUT_DIR}/verdicts.json"
else
  echo "Not made: ${finished} of 4 turns finished."
fi
echo

echo "### All turns"
echo
echo "Baseline turns are not gated. CPU per request is in CPU seconds, less the idle rate. The vs baseline columns are a candidate turn against the mean of the baseline turns for that phase."
echo
echo "| Turn | Build | Phase | CPU per request | CPU vs baseline | CPU cores used | p95 ms | p95 vs baseline | API-server calls per request | Failure rate (any non-200) |"
echo "|---|---|---|---|---|---|---|---|---|---|"
jq -r -L "${HERE}" --arg b "${BASELINE_REF}" --arg c "${CANDIDATE_REF}" 'include "metrics";
  . as $turns
  | def r5: (. * 100000 | round) / 100000;
  def mean: add / length;
  # Signed percent against the mean of the baseline turns for the phase; blank on a
  # baseline row, n/a when either side has no reading.
  def vs($t; $phase; $key):
    if $t.build == "baseline" then ""
    else ([$turns[] | select(.build == "baseline") | .rows[] | select(.name == $phase) | .[$key]]) as $b
      | if .[$key] == null or ($b | length) == 0 or ($b | any(. == null or . <= 0)) then "n/a"
        else (.[$key] / ($b | mean) * 100 - 100) as $d
          | $d | signed_pct end
    end;
  $turns[] | . as $t | .rows[] | . as $row
  | "| \($t.turn) | \(if $t.build == "baseline" then $b else $c end) (\($t.build)) | \(.name) | \(if .cpuPerRequest == null then "below noise" else (.cpuPerRequest | r5) end) | \($row | vs($t; $row.name; "cpuPerRequest")) | \(if .cpuCores == null then "below noise" else (.cpuCores * 1000 | round / 1000) end) | \(.p95Ms * 100 | round / 100) | \($row | vs($t; $row.name; "p95Ms")) | \(if .callsPerRequest == null then "n/a" else (.callsPerRequest * 1000 | round / 1000) end) | \(.failureRate) |"' <<< "${turns}"
echo

# The ceiling of each build, once each, after the four turns. Report-only.
echo "### Ceiling per build (report-only, not a gate)"
echo
# Each phase of each build stands alone: a search that stopped part way still
# shows what it finished, and the rest says "not measured". Phases are in run
# order (lib.sh), not alphabetical.
shopt -s nullglob
files=("${OUT_DIR}"/ceiling/*/ceiling-*.json)
shopt -u nullglob
if [[ "${#files[@]}" -eq 0 ]]; then
  echo "Not made: no ceiling search finished for either build (ceiling off, or the search stopped first)."
else
  echo "The highest rate with no failed request: one ramp that stopped at the first failure (a non-200, a 5 s timeout, or k6 falling behind its schedule), then 30 s holds at 0.9, 0.7 and 0.5 of the rate the failure started at, stopping at the first that failed nothing and delivered 95% of its rate. Each build ran once, on a fresh restart. Figures are for this runner."
  echo
  echo "| Phase | Build | First failure at req/s | Ceiling req/s | p95 ms | CPU cores used | Failure rate | Ceiling vs baseline |"
  echo "|---|---|---|---|---|---|---|---|"
  for phase in "${PHASES[@]}"; do
    for build in baseline candidate; do
      ref="${CANDIDATE_REF}"
      [[ "${build}" == baseline ]] && ref="${BASELINE_REF}"
      f="${OUT_DIR}/ceiling/${build}/ceiling-${phase}.json"
      if [[ ! -s "${f}" ]]; then
        echo "| ${phase} | ${ref} (${build}) | not measured | not measured | n/a | n/a | n/a | n/a |"
        continue
      fi
      # The candidate's ceiling against the baseline's, when both held one.
      base_f="${OUT_DIR}/ceiling/baseline/ceiling-${phase}.json"
      base_rps=null
      if [[ "${build}" == candidate && -s "${base_f}" ]]; then base_rps=$(jq -c .ceilingRps "${base_f}"); fi
      jq -r -L "${HERE}" --arg build "${build}" --arg ref "${ref}" --argjson baseRps "${base_rps}" 'include "metrics";
        def f3: . * 1000 | round / 1000;
        def vs: if $build == "baseline" then "" elif .ceilingRps == null or $baseRps == null or $baseRps <= 0 then "n/a"
          else (.ceilingRps / $baseRps * 100 - 100) | signed_pct end;
        "| \(.phase) | \($ref) (\($build)) | \(if .topReached then "none (top \(.ceilingMax) reached)" else (.firstFailureRps | round | tostring) end) | \(if .ceilingRps == null then "none held" else .ceilingRps end) | \(if .p95Ms == null then "n/a" else (.p95Ms * 100 | round / 100) end) | \(if .cpuCores == null then "n/a" else (.cpuCores | f3) end) | \(if .failureRate == null then "n/a" else .failureRate end) | \(vs) |"' \
        "${f}"
    done
  done
fi
echo

for turn_dir in "${OUT_DIR}"/turns/*/; do
  turn_dir="${turn_dir%/}"
  [[ -s "${turn_dir}/counts.json" ]] || continue
  name="${turn_dir##*/}"
  gated=true
  if [[ "${name}" == *-baseline ]]; then gated=false; fi
  echo "<details><summary>Turn ${name%%-*}, ${name#*-}: full report</summary>"
  echo
  GATED="${gated}" DATASET_JSON="${OUT_DIR}/dataset.json" "${HERE}/report.sh" "${turn_dir}"
  echo
  echo "</details>"
  echo
done
