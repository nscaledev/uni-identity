#!/usr/bin/env bash
# Restarts identity's server deployment N times and records how it comes back:
# the cost of a cold start and whether a restart drops traffic.
#
# Usage: warmup.sh
#
# Environment (all required unless a default is shown):
#   NAMESPACE          identity's namespace
#   SERVER_DEPLOYMENT  identity's server deployment (also its container name)
#   OUT_DIR            output directory: warmup.json
#   WARMUP_RESTARTS    how many restarts (3); 0 records the settings only
#
# Per restart, warmup.json records:
#   secondsToReady     from the new pod's creation to its Ready condition. Both
#                      are Kubernetes timestamps, so the resolution is 1 s.
#   workingSetBytes    the server container's memory working set, read from
#                      cadvisor once the pod is Ready (cadvisor takes a few
#                      seconds to publish a new pod; readAfterReadySeconds says
#                      how long this one took)
#   surged             an old pod was still serving while the new pod existed
#                      and was not yet Ready
#   noServingSeconds   seconds, at 1 s polls, in which no pod was serving
#
# The deployment's readiness probe, progressDeadlineSeconds and rollout
# strategy are recorded once, as they bound the figures above.
set -euo pipefail
# Command substitutions stop the script too, so a failed kubectl is not read as
# an empty answer.
shopt -s inherit_errexit

: "${NAMESPACE:?}" "${SERVER_DEPLOYMENT:?}" "${OUT_DIR:?}"
RESTARTS="${WARMUP_RESTARTS:-3}"
[[ "${RESTARTS}" =~ ^[0-9]+$ ]] || { echo "ERROR: WARMUP_RESTARTS must be a non-negative integer" >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/load/lib.sh
. "${HERE}/lib.sh"
mkdir -p "${OUT_DIR}"

# How long to wait for cadvisor to publish the new pod's series.
CADVISOR_WAIT=90

settings=$(kubectl get deployment -n "${NAMESPACE}" "${SERVER_DEPLOYMENT}" -o json | jq -c '
  {
    readinessProbe: (.spec.template.spec.containers[0].readinessProbe // null),
    progressDeadlineSeconds: .spec.progressDeadlineSeconds,
    strategy: .spec.strategy,
    replicas: .spec.replicas
  }')
deadline=$(jq -r '.progressDeadlineSeconds // 600' <<< "${settings}")

# One poll of the server's pods, given the names of the pods the restart
# replaces: how many of each kind exist and are serving. A pod serves when it
# is Ready and not terminating.
snapshot() {
  kubectl get pods -n "${NAMESPACE}" -l "app=${SERVER_DEPLOYMENT}" -o json | jq -c --argjson old "$1" '
    def serving: (.metadata.deletionTimestamp == null)
      and any(.status.conditions[]?; .type == "Ready" and .status == "True");
    .items as $items
    | ($items | map(select(.metadata.name as $n | $old | index($n)))) as $olds
    | ($items | map(select(.metadata.name as $n | ($old | index($n)) | not))) as $news
    | {
        oldPresent: ($olds | length),
        oldServing: ($olds | map(select(serving)) | length),
        newPresent: ($news | length),
        newServing: ($news | map(select(serving)) | length),
        newName: ($news | map(select(serving)) | (.[0].metadata.name // null))
      }'
}

restart_once() {
  local old snap start surged=false gap=0 pod ready_at
  old=$(kubectl get pods -n "${NAMESPACE}" -l "app=${SERVER_DEPLOYMENT}" -o json | jq -c '[.items[].metadata.name]')

  kubectl rollout restart -n "${NAMESPACE}" "deployment/${SERVER_DEPLOYMENT}" > /dev/null || return 1
  start=$(date +%s)

  # Until the new pod serves and the old ones are gone, so the next restart
  # starts from one pod.
  while true; do
    snap=$(snapshot "${old}")

    jq -e '.oldServing > 0 and .newPresent > 0 and .newServing == 0' <<< "${snap}" > /dev/null && surged=true
    jq -e '.oldServing + .newServing == 0' <<< "${snap}" > /dev/null && gap=$((gap + 1))
    jq -e '.newServing > 0 and .oldPresent == 0' <<< "${snap}" > /dev/null && break

    (( $(date +%s) - start < deadline )) \
      || { echo "ERROR: the restart did not finish within progressDeadlineSeconds (${deadline})" >&2; return 1; }
    sleep 1
  done

  pod=$(jq -r '.newName' <<< "${snap}")
  ready_at=$(date +%s)

  # cadvisor publishes a new pod a few seconds late.
  local waited=0 bytes
  until bytes=$(cadvisor_sum container_memory_working_set_bytes "${pod}" "%.0f" 2> /dev/null); do
    (( waited < CADVISOR_WAIT )) || { echo "ERROR: no memory reading for ${pod} within ${CADVISOR_WAIT}s" >&2; return 1; }
    sleep 2
    waited=$((waited + 2))
  done

  kubectl get pod -n "${NAMESPACE}" "${pod}" -o json | jq -c \
    --argjson surged "${surged}" --argjson gap "${gap}" --argjson bytes "${bytes}" \
    --argjson after "$(( $(date +%s) - ready_at ))" '
    def secs: fromdateiso8601;
    (.status.conditions[] | select(.type == "Ready") | .lastTransitionTime) as $ready
    | {
        pod: .metadata.name,
        created: .metadata.creationTimestamp,
        ready: $ready,
        secondsToReady: (($ready | secs) - (.metadata.creationTimestamp | secs)),
        workingSetBytes: $bytes,
        readAfterReadySeconds: $after,
        surged: $surged,
        noServingSeconds: $gap
      }'
}

restarts='[]'

for n in $(seq 1 "${RESTARTS}"); do
  echo "==> Restart ${n} of ${RESTARTS}" >&2
  # The assignment's status is restart_once's, so a failed restart stops the run.
  one=$(restart_once)
  restarts=$(jq -c --argjson one "${one}" '. + [$one]' <<< "${restarts}")
done

jq -n --argjson settings "${settings}" --argjson restarts "${restarts}" '$settings + {restarts: $restarts}' \
  > "${OUT_DIR}/warmup.json"
