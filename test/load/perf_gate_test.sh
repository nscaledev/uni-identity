#!/usr/bin/env bash
# Checks the per-PR performance gate: compare.sh's verdicts file and "vs baseline"
# columns, and perf-gate.sh's decisions (worse, no reading, base could not
# start, a turn not finishing, the label, the count gate), with a stub gh.
# Needs only bash and jq. Usage: perf_gate_test.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR="$(mktemp -d)"
trap 'rm -rf "${DIR}"' EXIT
failed=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; failed=1; }

# compare.sh, with report.sh stubbed: it needs a cluster-free summary only.
BIN="${DIR}/bin"
mkdir -p "${BIN}"
cp "${HERE}/compare.sh" "${HERE}/compare.jq" "${HERE}/lib.sh" "${HERE}/metrics.jq" "${BIN}/"
printf '#!/usr/bin/env bash\n' > "${BIN}/report.sh"
chmod +x "${BIN}"/*.sh

# turn OUT N BUILD CPU P95 CALLS_PASS: one finished turn, one phase (acl-heavy)
# of 100 requests, CPU seconds per request CPU, no idle load.
turn() {
  local d="$1/turns/$2-$3"
  mkdir -p "${d}"
  jq -n --argjson cpu "$4" '{settleSeconds: 0, baseline: {start: "2026-01-01T00:00:00Z", end: "2026-01-01T00:00:10Z", cpuBefore: 0, cpuAfter: 0},
    phases: [{name: "acl-heavy", start: "2026-01-01T00:01:00Z", end: "2026-01-01T00:02:00Z", requests: 100, cpuBefore: 0, cpuAfter: (if $cpu == null then 0 else $cpu * 100 end), k6Exit: 0}]}' > "${d}/phases.json"
  jq -n --argjson pass "$6" '{maxCallsPerRequest: 0.05, pass: $pass, phases: [{name: "acl-heavy", callsPerRequest: 0, pass: $pass}]}' > "${d}/counts.json"
  jq -n --argjson p95 "$5" '{phase: "acl-heavy", p95Ms: $p95, failureRate: 0, requests: 100, rate5xx: 0}' > "${d}/k6-acl-heavy.json"
}
# run OUT CPUS P95S [CALLS_PASS]: four turns, base cand cand base.
run() {
  local out="$1" i
  mkdir -p "${out}"
  jq -n '{baselineRef: "main", candidateRef: "cand", baselineCommit: "abc12345"}' > "${out}/turns.json"
  local builds=(baseline candidate candidate baseline)
  for i in 0 1 2 3; do
    turn "${out}" "$((i + 1))" "${builds[i]}" "$(jq ".[${i}]" <<< "$2")" "$(jq ".[${i}]" <<< "$3")" "${4:-true}"
  done
  COMPARE_GATE=true COMPARE_MARGIN_PCT=100 "${BIN}/compare.sh" "${out}" > "${out}/summary.md" 2> "${out}/err" || { cat "${out}/err"; return 1; }
}

# The vs baseline column: the candidate against the mean of the base turns, signed,
# blank on a base row. Base mean CPU 1.05; candidate 1.575 is +50%, 0.525 is -50%.
run "${DIR}/col" '[1.0,1.575,0.525,1.1]' '[100,150,50,110]'
rows=$(grep -E '^\| [0-9] \|' "${DIR}/col/summary.md" | cut -d'|' -f2,6,9 | tr -s ' ')
want=$' 1 | | \n 2 | +50% | +42.9% \n 3 | -50% | -52.4% \n 4 | | '
# p95 base mean is 105: 150 is +42.9%, 50 is -52.4%.
if [[ "${rows}" == "${want}" ]]; then ok vs-base-column; else bad "vs-base-column: ${rows}"; fi
# No change, and a change that rounds to none, read "0%": never "+0%", "-0%" or "+-0%".
run "${DIR}/zero" '[1.0,1.0,0.9996,1.0]' '[100,100,100,100]'
rows=$(grep -E '^\| [0-9] \|' "${DIR}/zero/summary.md" | cut -d'|' -f2,6,9 | tr -s ' ')
want=$' 1 | | \n 2 | 0% | 0% \n 3 | 0% | 0% \n 4 | | '
if [[ "${rows}" == "${want}" ]]; then ok vs-baseline-zero; else bad "vs-baseline-zero: ${rows}"; fi
if grep -q '^Baseline: main at commit abc12345' "${DIR}/col/summary.md"; then ok baseline-header; else bad baseline-header; fi

# The ceiling table: the candidate's ceiling against the base's.
mkdir -p "${DIR}/col/ceiling/baseline" "${DIR}/col/ceiling/candidate"
for b in baseline candidate; do
  rps=800; [[ "${b}" == candidate ]] && rps=600
  jq -n --argjson r "${rps}" '{phase: "acl-heavy", ceilingMax: 2000, topReached: false, firstFailureRps: 1000, ceilingRps: $r, p95Ms: 5, cpuCores: 0.5, failureRate: 0}' > "${DIR}/col/ceiling/${b}/ceiling-acl-heavy.json"
done
COMPARE_GATE=true "${BIN}/compare.sh" "${DIR}/col" 2> /dev/null | grep -E '^\| acl-heavy \| (main|cand) \((baseline|candidate)\) \| 1000' | awk -F'|' '{print $9}' | tr -d ' ' | tr '\n' ' ' > "${DIR}/ceil.txt"
if [[ "$(cat "${DIR}/ceil.txt")" == " -25% " ]]; then ok vs-base-ceiling; else bad "vs-base-ceiling: '$(cat "${DIR}/ceil.txt")'"; fi

# perf-gate.sh. A stub gh answers `pr view` with the labels in LABELS.
mkdir -p "${DIR}/ghbin"
cat > "${DIR}/ghbin/gh" <<'GH'
#!/usr/bin/env bash
[[ "$1 $2" == "pr view" ]] || { echo "stub gh: unexpected $*" >&2; exit 1; }
printf '%s\n' ${LABELS:-}
GH
chmod +x "${DIR}/ghbin/gh"

# gate NAME OUT LABELS WANT_EXIT WANT_TEXT
gate() {
  local rc=0 out
  out=$(PATH="${DIR}/ghbin:${PATH}" PR_NUMBER=7 LABELS="$3" "${HERE}/perf-gate.sh" "$2" 2>&1) || rc=$?
  if [[ "${rc}" == "$4" && "${out}" == *"$5"* ]]; then ok "$1"; else bad "$1: exit ${rc} (want $4); out: ${out}"; fi
}

run "${DIR}/pass" '[1.0,1.3,1.4,1.1]' '[100,100,100,100]'
gate pass-1.3x "${DIR}/pass" "" 0 "**PASS**"
run "${DIR}/slow" '[1.0,2.5,2.6,1.1]' '[100,100,100,100]'
gate fail-2.5x "${DIR}/slow" "" 1 "CPU per request worse** in acl-heavy"
gate label-lets-cpu-through "${DIR}/slow" "other perf-regression-accepted" 0 "Let through by the \`perf-regression-accepted\` label"
gate other-label-does-not "${DIR}/slow" "other" 1 "**FAIL**"
# p95 alone never fails.
run "${DIR}/p95" '[1.0,1.0,1.0,1.0]' '[100,500,500,100]'
gate p95-not-gated "${DIR}/p95" "" 0 "**PASS**"
# A null CPU reading is a failure, not a pass.
run "${DIR}/null" '[1.0,null,1.5,1.1]' '[100,100,100,100]'
gate fail-no-reading "${DIR}/null" "" 1 "no reading** in acl-heavy"
# The label does not override the calls-per-request gate.
run "${DIR}/calls" '[1.0,2.5,2.6,1.1]' '[100,100,100,100]' false
gate label-not-for-count-gate "${DIR}/calls" "perf-regression-accepted" 1 "API-call count gate failed"
# Base could not start: red, let through by the label, and the summary says the count gate did not run.
mkdir -p "${DIR}/nobase"
jq -n '{baselineRef: "main", candidateRef: "cand", failure: {turn: 1, build: "baseline", step: "switch", at: "the switch to the build"}}' > "${DIR}/nobase/turns.json"
gate fail-base-could-not-start "${DIR}/nobase" "" 1 "base could not start"
gate label-lets-base-through "${DIR}/nobase" "perf-regression-accepted" 0 "count gate did not run"
# A turn not finishing is red, and the label does not cover it.
mkdir -p "${DIR}/unfinished"
jq -n '{baselineRef: "main", candidateRef: "cand", failure: {turn: 2, build: "candidate", step: "phases", at: "the load phases"}}' > "${DIR}/unfinished/turns.json"
gate fail-turn-unfinished "${DIR}/unfinished" "" 1 "a turn did not finish"
gate label-not-for-unfinished "${DIR}/unfinished" "perf-regression-accepted" 1 "does not cover a turn that did not finish"
# gh failing (no network, no token) reads as no label.
printf '#!/usr/bin/env bash\nexit 1\n' > "${DIR}/ghbin/gh"
gate gh-failure-is-no-label "${DIR}/slow" "" 1 "**FAIL**"

exit "${failed}"
