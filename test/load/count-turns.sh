#!/usr/bin/env bash
# Counts identity's API-server calls for every turn of a compare run, from the
# one audit log. The count gate applies to the candidate turns only; a baseline
# turn's counts are written and reported, never gated.
#
# Usage: count-turns.sh AUDIT_LOG OUT_DIR
#
# Environment: IDENTITY_USER and MAX_CALLS_PER_REQUEST, as count-audit.sh.
# Exits 1 when a candidate turn fails the gate.
set -euo pipefail

[[ $# -eq 2 ]] || { echo "Usage: $0 AUDIT_LOG OUT_DIR" >&2; exit 2; }
AUDIT_LOG="$1" OUT_DIR="$2"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

status=0
for turn_dir in "${OUT_DIR}"/turns/*/; do
  turn_dir="${turn_dir%/}"
  [[ -s "${turn_dir}/phases.json" ]] || continue
  if [[ "${turn_dir}" == *-baseline ]]; then
    echo "==> ${turn_dir##*/} (baseline: reported, not gated)" >&2
    "${HERE}/count-audit.sh" "${AUDIT_LOG}" "${turn_dir}/phases.json" "${turn_dir}/counts.json" || true
  else
    echo "==> ${turn_dir##*/} (candidate: gated)" >&2
    "${HERE}/count-audit.sh" "${AUDIT_LOG}" "${turn_dir}/phases.json" "${turn_dir}/counts.json" || status=1
  fi
done
exit "${status}"
