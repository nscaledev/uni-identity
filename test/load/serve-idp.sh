#!/usr/bin/env bash
# Serves the load test's stand-in identity provider (idp.yaml) with the public
# key set the fixtures wrote, and waits until it is Ready.
#
# Usage: serve-idp.sh JWKS_JSON
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JWKS="${1:?usage: serve-idp.sh JWKS_JSON}"
NS=load-test-idp

# A Pod is refused until its namespace has a default ServiceAccount. The
# controller that adds one works through every new namespace in turn, and the
# fixtures have just written thousands, so create it here rather than wait.
kubectl create namespace "${NS}"
kubectl create serviceaccount default -n "${NS}" --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f "${HERE}/idp.yaml"
kubectl create configmap jwks -n "${NS}" --from-file=jwks.json="${JWKS}"
kubectl wait --for=condition=Ready pod/jwks -n "${NS}" --timeout=120s
