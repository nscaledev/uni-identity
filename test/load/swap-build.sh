#!/usr/bin/env bash
# Switches identity's server to one build by image alone and restarts it, so
# every turn starts on a fresh pod. Only the server Deployment is touched: the
# chart, CRDs, values and the controllers (left at 0 in direct mode) stay as
# the first install made them. Fails, never skips, if the build's image does
# not become Ready on that chart.
#
# Usage: swap-build.sh NAME IMAGE_TAG
#
# NAME        what to call the build in messages (a git ref)
# IMAGE_TAG   tag of its images, already loaded into the cluster
#
# Environment:
#   NAMESPACE, RELEASE   required: identity's namespace and Helm release
#   SERVER_DEPLOYMENT    the server Deployment, also its container name
#                        (RELEASE-server)
set -euo pipefail

[[ $# -eq 2 ]] || { echo "Usage: $0 NAME IMAGE_TAG" >&2; exit 2; }
NAME="$1" TAG="$2"
: "${NAMESPACE:?}" "${RELEASE:?}"
SERVER="${SERVER_DEPLOYMENT:-${RELEASE}-server}"

fail() { echo "ERROR: build ${NAME} ${1}; the comparison cannot be made" >&2; exit 1; }

# Keep the image's repository, change only its tag.
current=$(kubectl get deployment -n "${NAMESPACE}" "${SERVER}" -o jsonpath='{.spec.template.spec.containers[?(@.name=="'"${SERVER}"'")].image}')
[[ -n "${current}" ]] || fail "has no server container to switch (${SERVER})"
image="${current%:*}:${TAG}"

echo "==> Switching to ${NAME} (${image})" >&2
kubectl set image -n "${NAMESPACE}" "deployment/${SERVER}" "${SERVER}=${image}" >&2 \
  || fail "could not be set on the server"
# Always restart: if the image did not change (turn 2 to 3) nothing else would.
kubectl rollout restart -n "${NAMESPACE}" "deployment/${SERVER}" >&2 \
  || fail "could not be restarted"
kubectl rollout status -n "${NAMESPACE}" "deployment/${SERVER}" --timeout=300s >&2 \
  || fail "did not become Ready on the candidate's chart (${image})"
echo "==> ${NAME} is serving (${image})" >&2
