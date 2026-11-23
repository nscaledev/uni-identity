#!/usr/bin/env bash
# Checks that lib.sh reads the server's CPU over every serving replica, against
# a fake kubectl. Needs only bash and jq.
# Usage: lib_test.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${WORK}/bin"

# Two serving replicas and one terminating, which must not be counted.
cat > "${WORK}/bin/kubectl" <<'KUBECTL'
#!/usr/bin/env bash
case "$*" in
  *"get pod -n"*"-l app="*) echo '{"items": [
    {"metadata": {"name": "pod-0"}},
    {"metadata": {"name": "pod-1"}},
    {"metadata": {"name": "pod-2", "deletionTimestamp": "2026-01-01T00:00:00Z"}}]}' ;;
  *"get pod -n"*nodeName*) echo -n node-0 ;;
  *"get --raw"*) cat <<'METRICS'
container_cpu_usage_seconds_total{container="srv",pod="pod-0"} 1.5
container_cpu_usage_seconds_total{container="srv",pod="pod-1"} 2.25
container_cpu_usage_seconds_total{container="srv",pod="pod-2"} 100
METRICS
  ;;
  *) echo "fake kubectl: unexpected $*" >&2; exit 1 ;;
esac
KUBECTL
chmod +x "${WORK}/bin/kubectl"

got=$(PATH="${WORK}/bin:${PATH}" NAMESPACE=ns SERVER_DEPLOYMENT=srv bash -c ". '${HERE}/lib.sh'; cpu_seconds")
if [[ "${got}" == "3.750" ]]; then
  echo "ok   cpu_seconds sums the serving replicas: ${got}"
else
  echo "FAIL cpu_seconds: want 3.750 got ${got}"
  exit 1
fi
