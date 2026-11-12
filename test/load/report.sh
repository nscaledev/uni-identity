#!/usr/bin/env bash
# Writes the load test's job summary (markdown) to stdout.
#
# Usage: report.sh OUT_DIR
#
# Reads OUT_DIR/{phases,counts}.json, dataset.json (or DATASET_JSON) and OUT_DIR/k6-*.json, and
# OUT_DIR/warmup.json when it exists.
# Reads OUT_DIR/ceiling/ceiling-*.json when they exist.
# Environment: GATED (false for a baseline turn), RATE, DURATION, CEILING_MAX, DATASET;
# NAMESPACE and SERVER_DEPLOYMENT to read the server's CPU limit (optional).
set -euo pipefail

OUT_DIR="${1:?Usage: $0 OUT_DIR}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"

# The limiter constant is read from the code so the model cannot drift from it.
QPS=$(awk '$1 == "kubernetesClientQPS" { print $3 }' "${REPO_ROOT}/cmd/unikorn-identity/main.go")

# Server CPU limit in cores ("1" or "500m"), or null. Every compare turn runs
# on the same chart, so the live Deployment's limit holds for all of them.
raw=''
if [[ -n "${NAMESPACE:-}" && -n "${SERVER_DEPLOYMENT:-}" ]]; then
  raw=$(kubectl get deployment -n "${NAMESPACE}" "${SERVER_DEPLOYMENT}" \
    -o jsonpath='{.spec.template.spec.containers[0].resources.limits.cpu}' 2>/dev/null || true)
fi
CPU_LIMIT=null
case "${raw}" in
  '') ;;
  *m) CPU_LIMIT=$(awk -v m="${raw%m}" 'BEGIN { print m / 1000 }') ;;
  *) CPU_LIMIT="${raw}" ;;
esac

WARMUP=null
if [[ -s "${OUT_DIR}/warmup.json" ]]; then
  WARMUP=$(jq -c . "${OUT_DIR}/warmup.json")
fi

jq -rn \
  --slurpfile phases "${OUT_DIR}/phases.json" \
  --slurpfile counts "${OUT_DIR}/counts.json" \
  --slurpfile k6 <(jq -c . "${OUT_DIR}"/k6-*.json) \
  --slurpfile dataset "${DATASET_JSON:-${OUT_DIR}/dataset.json}" \
  --argjson inputs "$(jq -n --arg dataset "${DATASET:-small}" --arg rate "${RATE:-20}" --arg duration "${DURATION:-60}" \
    --arg gated "${GATED:-true}" --arg ceilingMax "${CEILING_MAX:-2000}" \
    '$ARGS.named')" \
  --slurpfile ceilings <(jq -c . "${OUT_DIR}"/ceiling/ceiling-*.json 2>/dev/null || true) \
  --argjson qps "${QPS}" --argjson cpuLimit "${CPU_LIMIT}" --argjson warmup "${WARMUP}" \
  -L "${HERE}" -f "${HERE}/report.jq"
