#!/usr/bin/env bash
# Checks compare.jq against hand-made turns. Needs only jq.
# Usage: compare_test.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
failed=0

# run CPU P95 [MARGIN]: CPU and P95 are JSON arrays of four values, one per
# turn in run order: baseline, candidate, candidate, baseline. DROP=n (0 to 3)
# leaves that turn without the phase's row.
run() {
  jq -n --argjson cpu "$1" --argjson p95 "$2" '
    ["baseline", "candidate", "candidate", "baseline"] | to_entries
    | map({build: .value, rows: (if .key == (env.DROP // "-1" | tonumber) then [] else [{name: "acl-heavy", cpuPerRequest: $cpu[.key], p95Ms: $p95[.key]}] end)})' \
    | jq -c --arg ref v1.0.0 --argjson margin "${3:-25}" --argjson gate "${GATE:-false}" -L "${HERE}" -f "${HERE}/compare.jq"
}

# expect NAME CPU P95 CPU_VERDICT P95_VERDICT [MARGIN]
expect() {
  local got
  got=$(run "$2" "$3" "${6:-25}" | jq -r '[.[0].verdict, .[1].verdict] | join(" ")')
  if [[ "${got}" == "$4 $5" ]]; then echo "ok   $1: ${got}"; else echo "FAIL $1: want '$4 $5' got '${got}'"; failed=1; fi
}

expect worse        '[1.0,1.4,1.5,1.1]'    '[100,140,150,110]' worse worse
expect better       '[1.0,0.6,0.7,1.1]'    '[100,60,70,110]'   better better
expect same         '[1.0,1.05,0.98,1.02]' '[100,105,98,102]'  same same
expect mixed-turns  '[1.0,1.6,1.1,1.0]'    '[100,160,110,100]' same same
expect aa-identical '[1.0,1.0,1.0,1.0]'    '[100,100,100,100]' same same
# The worse baseline turn sets the bar: 1.3 is 30% over 1.0 but only 18% over 1.1.
expect worse-bar    '[1.0,1.3,1.3,1.1]'    '[100,100,100,100]' same same
# Nor the mean: 1.6 is over 1.2 (mean) by 33% but under 1.4 (worse) by 14%.
expect worse-mean   '[1.0,1.6,1.6,1.4]'    '[100,100,100,100]' same same
expect cpu-only     '[1.0,1.4,1.5,1.1]'    '[100,101,99,100]'  worse same
expect margin       '[1.0,1.4,1.5,1.1]'    '[100,140,150,110]' same same 60
expect no-reading   '[1.0,null,1.5,1.1]'   '[100,100,100,100]' "no reading" same
# "Better" is judged against the better baseline turn: 0.9 is 10% under 1.0.
expect better-bar   '[1.0,0.8,0.8,1.4]'    '[100,100,100,100]' same same
# "Better" needs both candidate turns under the line.
expect better-both  '[1.0,0.6,1.0,1.0]'    '[100,100,100,100]' same same
# A zero reading is no reading, in a candidate turn or a baseline turn.
expect zero-cand    '[1.0,0,1.0,1.0]'      '[100,100,100,100]' "no reading" same
expect zero-base    '[0,1.0,1.0,1.0]'      '[100,100,100,100]' "no reading" same
# Fewer than four readings is no verdict.
got=$(DROP=2 run '[1.0,1.4,1.5,1.1]' '[100,140,150,110]' | jq -r '[.[0].verdict, .[1].verdict] | join(" ")')
if [[ "${got}" == "no reading no reading" ]]; then echo "ok   three-readings: ${got}"; else echo "FAIL three-readings: got '${got}'"; failed=1; fi
# The same with the first baseline turn missing: the phase still gets a line.
got=$(DROP=0 run '[1.0,1.4,1.5,1.1]' '[100,140,150,110]' | jq -r '[.[0].verdict, .[1].verdict] | join(" ")')
if [[ "${got}" == "no reading no reading" ]]; then echo "ok   first-turn-missing: ${got}"; else echo "FAIL first-turn-missing: got '${got}'"; failed=1; fi

# The line carries the numbers the summary shows: mean of the candidate turns
# against the mean of the baseline turns, each turn on its own, the baseline spread.
line=$(run '[1.0,1.4,1.5,1.1]' '[100,100,100,100]' | jq -r '.[0].line')
want='CPU per request, acl-heavy: +38.1% vs v1.0.0 (candidate turns +33.3%, +42.9%; baseline spread 9.5%) — worse (report-only)'
if [[ "${line}" == "${want}" ]]; then echo "ok   line"; else echo "FAIL line: ${line}"; failed=1; fi

# A zero change reads "0%", and one that rounds to zero does too; never "+0%"
# or "-0%" (the table's vs baseline columns use the same def, signed_pct).
line=$(run '[1.0,1.0,1.0,1.0]' '[100,100,100,100]' | jq -r '.[0].line')
if [[ "${line}" == *": 0% vs v1.0.0 (candidate turns 0%, 0%;"* ]]; then echo "ok   zero-change-line"; else echo "FAIL zero-change-line: ${line}"; failed=1; fi
line=$(run '[1.0,0.9996,1.0,1.0]' '[100,100,100,100]' | jq -r '.[0].line')
if [[ "${line}" == *": 0% vs v1.0.0 (candidate turns 0%, 0%;"* ]]; then echo "ok   rounds-to-zero-line"; else echo "FAIL rounds-to-zero-line: ${line}"; failed=1; fi

# The gate's rule at its margin (100, 2x): only CPU is gated, p95 never is. A
# 2.5x candidate is worse and gated; a 1.3x one is same; the lines say "gated".
expect gate-2.5x    '[1.0,2.5,2.6,1.1]'    '[100,250,260,110]' worse worse 100
expect gate-1.3x    '[1.0,1.3,1.4,1.1]'    '[100,130,140,110]' same same 100
got=$(GATE=true run '[1.0,2.5,2.6,1.1]' '[100,250,260,110]' 100 | jq -r '[.[] | "\(.check)=\(.gated)"] | join(" ")')
if [[ "${got}" == "CPU per request=true p95 latency=false" ]]; then echo "ok   gated-flags"; else echo "FAIL gated-flags: ${got}"; failed=1; fi
got=$(GATE=true run '[1.0,2.5,2.6,1.1]' '[100,250,260,110]' 100 | jq -r '[.[].line | capture("\\((?<m>gated|report-only)\\)$").m] | join(" ")')
if [[ "${got}" == "gated report-only" ]]; then echo "ok   gated-wording"; else echo "FAIL gated-wording: ${got}"; failed=1; fi
got=$(GATE=true run '[1.0,null,1.5,1.1]' '[100,100,100,100]' 100 | jq -r '.[0] | "\(.verdict) \(.gated)"')
if [[ "${got}" == "no reading true" ]]; then echo "ok   gated-no-reading"; else echo "FAIL gated-no-reading: ${got}"; failed=1; fi

# compare.sh with a ceiling search that stopped part way: each phase of each
# build stands alone, "not measured" fills the gaps, the order is the run order
# (not alphabetical), and nothing is lost after the ceiling section.
OUT="$(mktemp -d)"
trap 'rm -rf "${OUT}"' EXIT
mkdir -p "${OUT}/ceiling/baseline" "${OUT}/ceiling/candidate"
echo '{"baselineRef": "v1.0.0", "candidateRef": "cand", "order": []}' > "${OUT}/turns.json"
ceiling_file() { # BUILD PHASE
  jq -n --arg p "$2" '{phase: $p, ceilingMax: 2000, topReached: false, firstFailureRps: 1010, ceilingRps: 909, p95Ms: 5, cpuCores: 0.5, failureRate: 0}' \
    > "${OUT}/ceiling/$1/ceiling-$2.json"
}
# The candidate has only a later phase; the baseline has the first two.
ceiling_file baseline auth0-bearer
ceiling_file baseline passport-exchange
ceiling_file candidate acl-heavy
status=0
summary=$("${HERE}/compare.sh" "${OUT}" 2> "${OUT}/err") || status=$?
rows=$(grep -E '^\| (auth0-bearer|passport-exchange|acl-heavy|service-account) \|' <<< "${summary}" | cut -d'|' -f2-5 | tr -s ' ' || true)
want=$' auth0-bearer | v1.0.0 (baseline) | 1010 | 909 \n auth0-bearer | cand (candidate) | not measured | not measured \n passport-exchange | v1.0.0 (baseline) | 1010 | 909 \n passport-exchange | cand (candidate) | not measured | not measured \n acl-heavy | v1.0.0 (baseline) | not measured | not measured \n acl-heavy | cand (candidate) | 1010 | 909 \n service-account | v1.0.0 (baseline) | not measured | not measured \n service-account | cand (candidate) | not measured | not measured '
if [[ "${status}" -eq 0 && "${rows}" == "${want}" ]]; then echo "ok   partial-ceiling"; else echo "FAIL partial-ceiling: exit ${status}, rows:"; echo "${rows}"; cat "${OUT}/err"; failed=1; fi
# After the ceiling section the per-turn reports still follow (none here), and
# with no ceiling file at all the section says it was not made.
rm "${OUT}"/ceiling/*/ceiling-*.json
summary=$("${HERE}/compare.sh" "${OUT}" 2>&1) || true
if grep -q '^Not made: no ceiling search finished' <<< "${summary}"; then echo "ok   no-ceiling"; else echo "FAIL no-ceiling"; failed=1; fi

# compare-turns.sh honours CEILING: the ceiling search runs once per build, in
# order, unless CEILING is false. Its steps are stubs that log their calls.
TURNS="${OUT}/turns-bin"
mkdir -p "${TURNS}"
cp "${HERE}/compare-turns.sh" "${HERE}/lib.sh" "${HERE}/metrics.jq" "${TURNS}/"
for stub in swap-build warmup count-turns; do printf '#!/usr/bin/env bash\n' > "${TURNS}/${stub}.sh"; done
cat > "${TURNS}/run-phases.sh" <<'STUB'
#!/usr/bin/env bash
echo '{"settleSeconds": 5, "baseline": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T00:01:00Z", "cpuBefore": 0, "cpuAfter": 1}}' > "${OUT_DIR}/phases.json"
STUB
cat > "${TURNS}/ceiling.sh" <<'STUB'
#!/usr/bin/env bash
echo "${OUT_DIR##*/}" >> "${CEILING_LOG}"
STUB
chmod +x "${TURNS}"/*.sh
turns_ceilings() { # CEILING value (empty: unset) -> the builds that got a ceiling search
  rm -f "${OUT}/ceiling.log"; touch "${OUT}/ceiling.log"
  env ${1:+CEILING="$1"} CEILING_LOG="${OUT}/ceiling.log" BASELINE_REF=v1 CANDIDATE_REF=cand BASELINE_TAG=a CANDIDATE_TAG=b \
    OUT_DIR="${OUT}/run-$1" RELEASE=r NAMESPACE=ns "${TURNS}/compare-turns.sh" > /dev/null 2>&1 || echo "compare-turns.sh failed"
  tr '\n' ' ' < "${OUT}/ceiling.log"
}
for want in "false:" "true:baseline candidate " ":baseline candidate "; do
  got=$(turns_ceilings "${want%%:*}")
  if [[ "${got}" == "${want#*:}" ]]; then echo "ok   turns-ceiling ${want%%:*}: '${got}'"; else echo "FAIL turns-ceiling ${want%%:*}: want '${want#*:}' got '${got}'"; failed=1; fi
done

# A failed turn is recorded in turns.json for perf-gate.sh: here the base's
# image switch fails (turn 1), and the commit passed in is kept.
printf '#!/usr/bin/env bash\nexit 1\n' > "${TURNS}/swap-build.sh"
BASELINE_COMMIT=abc123 BASELINE_REF=v1 CANDIDATE_REF=cand BASELINE_TAG=a CANDIDATE_TAG=b OUT_DIR="${OUT}/run-fail" RELEASE=r NAMESPACE=ns \
  "${TURNS}/compare-turns.sh" > /dev/null 2>&1 && echo "compare-turns.sh should have failed"
got=$(jq -r '"\(.failure.turn) \(.failure.build) \(.failure.step) \(.baselineCommit)"' "${OUT}/run-fail/turns.json")
if [[ "${got}" == "1 baseline switch abc123" ]]; then echo "ok   turns-failure-recorded"; else echo "FAIL turns-failure-recorded: '${got}'"; failed=1; fi

# The workflow's input check needs ceiling_max above rate only when the ceiling
# is on (yq extracts the step; the script runs as the job runs it).
yq -r '.jobs[].steps[] | select(.name == "Check inputs") | .run' "${HERE}/../../.github/workflows/load-test.yaml" > "${OUT}/check.sh"
# A refusal counts only with its own message, so a broken extraction cannot pass.
check_inputs() { # CEILING RATE CEILING_MAX
  local msg
  if msg=$(WARMUP_RESTARTS=0 DURATION=60 COMPARE_MARGIN_PCT=25 CEILING="$1" RATE="$2" CEILING_MAX="$3" bash "${OUT}/check.sh" 2>&1); then
    echo accepted
  else
    echo "refused: ${msg}"
  fi
}
for want in "true 20 20 refused: ceiling_max must be above rate" "true 20 2000 accepted" "false 20 20 accepted" "false 20 0 refused: ceiling_max must be a positive integer"; do
  read -r c r m w <<< "${want}"
  got=$(check_inputs "${c}" "${r}" "${m}")
  if [[ "${got}" == "${w}" ]]; then echo "ok   inputs ceiling=${c} rate=${r} ceiling_max=${m}: ${got}"; else echo "FAIL inputs ceiling=${c} rate=${r} ceiling_max=${m}: want ${w} got ${got}"; failed=1; fi
done

exit "${failed}"
