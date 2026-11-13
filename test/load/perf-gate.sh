#!/usr/bin/env bash
# The per-PR performance gate. Prints its verdict as markdown and exits 1 when
# the PR is red. See "Per-PR gate" in test/load/README.md.
#
# Usage: perf-gate.sh OUT_DIR
#
# Reads OUT_DIR/turns.json (compare-turns.sh) and OUT_DIR/verdicts.json
# (compare.sh, run with COMPARE_GATE=true). Red when CPU per request is worse
# or unread in any phase, the base could not start, or a turn did not finish.
# The label perf-regression-accepted on the PR lets the first three through; it
# never covers a turn that did not finish, nor a candidate turn that failed the
# API-call count gate (count-turns.sh, which is red on its own).
#
# Environment: PR_NUMBER and GH_TOKEN (gh reads the labels live: a re-run keeps
# the original event's labels, which go stale). No PR_NUMBER, or gh failing,
# means no label. LABEL overrides the label name.
set -euo pipefail

OUT_DIR="${1:?Usage: $0 OUT_DIR}"
LABEL="${LABEL:-perf-regression-accepted}"

has_label() {
  [[ -n "${PR_NUMBER:-}" ]] || return 1
  gh pr view "${PR_NUMBER}" --json labels -q '.labels[].name' 2> /dev/null | grep -qxF "${LABEL}"
}

# Each reason: {letThrough: bool, text}. A letThrough one the label can cover.
reasons='[]'
add() { reasons=$(jq -c --argjson l "$1" --arg t "$2" '. + [{letThrough: $l, text: $t}]' <<< "${reasons}"); }

failure=$(jq -c '.failure // null' "${OUT_DIR}/turns.json" 2> /dev/null || echo null)
if [[ ! -s "${OUT_DIR}/turns.json" ]]; then
  add false "no turn ran; see the failed step."
elif [[ "${failure}" != null ]]; then
  if [[ "$(jq -r '.build + "/" + .step' <<< "${failure}")" == baseline/switch ]]; then
    add true "**base could not start**: the base build did not become Ready on this PR's chart (turn $(jq -r .turn <<< "${failure}")). No comparison was made, and the candidate's turns did not run, so the API-call count gate did not run either."
  else
    add false "**a turn did not finish**: turn $(jq -r '"\(.turn) (\(.build)) failed at \(.at)"' <<< "${failure}")."
  fi
elif [[ ! -s "${OUT_DIR}/verdicts.json" ]]; then
  add false "**a turn did not finish**: the comparison could not be made."
else
  while IFS= read -r line; do
    add true "${line}"
  done < <(jq -r '.[] | select(.gated and (.verdict == "worse" or .verdict == "no reading"))
    | "**\(if .verdict == "worse" then "CPU per request worse" else "no reading" end)** in \(.phase): \(.line)"' "${OUT_DIR}/verdicts.json")
fi

# The count gate is not the label's to override.
for counts in "${OUT_DIR}"/turns/*-candidate/counts.json; do
  [[ -s "${counts}" ]] || continue
  if [[ "$(jq '.pass' "${counts}")" != true ]]; then
    add false "**API-call count gate failed** in $(basename "$(dirname "${counts}")") (more than $(jq -r .maxCallsPerRequest "${counts}") identity API-server calls per request, or a blind probe)."
  fi
done

echo "### Performance gate"
echo
if [[ "$(jq length <<< "${reasons}")" -eq 0 ]]; then
  echo "**PASS**: CPU per request is not worse than the base in any phase."
  exit 0
fi

jq -r '.[] | "- " + .text' <<< "${reasons}"
echo
blocked=$(jq '[.[] | select(.letThrough | not)] | length' <<< "${reasons}")
if [[ "${blocked}" -gt 0 ]]; then
  echo "**FAIL**. The \`${LABEL}\` label does not cover a turn that did not finish."
  exit 1
elif has_label; then
  echo "**Let through by the \`${LABEL}\` label.** The figures above stand; the job is not failed for them."
  exit 0
else
  echo "**FAIL**. A deliberate slowdown is let through by the \`${LABEL}\` label on the PR."
  exit 1
fi
