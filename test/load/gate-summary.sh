#!/usr/bin/env bash
# Prints, as markdown, what failed the count gate and why. Prints nothing when
# every phase passed.
#
# Usage: gate-summary.sh PHASES_JSON COUNTS_JSON
#
# PHASES_JSON and COUNTS_JSON are run-phases.sh's and count-audit.sh's outputs.
# Each failed phase is named with its figure: API-server calls per request, or
# the failed k6 thresholds (a 5xx, a 401 or any non-200 response).
set -euo pipefail

[[ $# -eq 2 ]] || { echo "Usage: $0 PHASES_JSON COUNTS_JSON" >&2; exit 2; }

jq -r --slurpfile phases "$1" '
  .maxCallsPerRequest as $max
  | ([.phases[] | select(.pass | not)
    | "- **\(.name)**: " + (if .callsPerRequest == null then "no requests were made"
        else "\(.callsPerRequest * 1000 | round / 1000) API-server calls per request over \(.requests) requests (gate \($max))" end)]
   + [$phases[0].phases[] | select(.k6Exit != 0)
      | "- **\(.name)**: k6 thresholds failed (a 5xx, a 401 or a non-200 response; k6 exit \(.k6Exit))"]
   + (if .identityEvents == 0 then ["- the audit log has no events from identity'"'"'s ServiceAccount, so the probe is blind"] else [] end)
  ) as $fails
  | if ($fails | length) == 0 then empty
    else (["### Gate failed", ""] + $fails | join("\n")) end' "$2"
