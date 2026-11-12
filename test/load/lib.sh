# Shared by run-phases.sh, ceiling.sh and warmup.sh: reads of the server
# container's metrics from the kubelet's cadvisor. Source it; it needs NAMESPACE and
# SERVER_DEPLOYMENT (also the server container's name) in the environment.

# server_pod prints the name of the server's pod. It fails when there is none.
server_pod() {
  local pod
  pod=$(kubectl get pod -n "${NAMESPACE}" -l "app=${SERVER_DEPLOYMENT}" -o jsonpath='{.items[0].metadata.name}') \
    && [[ -n "${pod}" ]] || { echo "ERROR: no server pod for app=${SERVER_DEPLOYMENT}" >&2; return 1; }
  echo "${pod}"
}

# cadvisor_sum METRIC POD FORMAT prints the sum of METRIC over the server
# container of POD, formatted with the awk printf FORMAT. It fails, with a
# message, when the series is absent, rather than printing 0: command
# substitution does not stop the script, so every step is checked here.
cadvisor_sum() {
  local metric="$1" pod="$2" format="$3" node
  node=$(kubectl get pod -n "${NAMESPACE}" "${pod}" -o jsonpath='{.spec.nodeName}') \
    && [[ -n "${node}" ]] || { echo "ERROR: pod ${pod} has no node" >&2; return 1; }
  kubectl get --raw "/api/v1/nodes/${node}/proxy/metrics/cadvisor" \
    | awk -v metric="${metric}" -v pod="${pod}" -v ctr="${SERVER_DEPLOYMENT}" -v format="${format}" '
        index($0, metric "{") == 1 && index($0, "pod=\"" pod "\"") && index($0, "container=\"" ctr "\"") {
          # The value follows the labels; a timestamp may follow the value.
          v = $0; sub(/^.*\} /, "", v); split(v, a, " "); sum += a[1]; n++
        }
        END {
          if (n == 0) { print "ERROR: no cadvisor series " metric " for " pod "/" ctr > "/dev/stderr"; exit 1 }
          printf format "\n", sum
        }'
}

# cadvisor lags the cgroup by up to ~10s, so CPU is read after a quiet gap on
# both sides of a window.
SETTLE="${SETTLE:-15}"

now() { date -u +%Y-%m-%dT%H:%M:%S.%NZ; }

# Total CPU seconds used by the server container, from the kubelet's cadvisor.
cpu_seconds() {
  local pod
  pod=$(server_pod) || return 1
  cadvisor_sum container_cpu_usage_seconds_total "${pod}" "%.3f"
}

# Reads the CPU counter or stops the run: a missing reading must not become a zero.
read_cpu() { cpu_seconds || { echo "ERROR: could not read the server's CPU use" >&2; exit 1; }; }

# The load phases, in the order they run.
PHASES=(auth0-bearer passport-exchange acl-heavy service-account)

# idle_cores PHASES_JSON prints the server's CPU use with no load, in cores,
# from the baseline window of a run-phases.sh run (see metrics.jq).
idle_cores() {
  jq -r -L "$(dirname "${BASH_SOURCE[0]}")" 'include "metrics"; idle_cores(.)' "$1"
}

# k6_run LOG runs identity.js with k6's own log, one line per failed request,
# written to LOG and not the console; only the summary line reaches stdout. k6
# appends to LOG, so each run gets its own. The environment (PHASE, MODE, ...)
# is read by identity.js. See "Reading the output" in the README.
k6_run() {
  k6 run -q --log-output="file=$1,level=warning" "$(dirname "${BASH_SOURCE[0]}")/identity.js"
}

# k6_excerpt LOG prints, to stderr, the first few error lines of k6's log, so
# the cause of an unexpected failure is on the console (5 lines at most). The rest stays in LOG.
k6_excerpt() {
  [[ -s "$1" ]] || { echo "    (k6 logged nothing to $1)" >&2; return 0; }
  # Errors first (a threshold, a crash), then a couple of failed requests:
  # the first lines alone would all be per-request ones.
  { grep -m3 'level=error' "$1" || true; grep -m2 'Request Failed' "$1" || true; } | sed 's/^/    /' >&2
  echo "    (all of k6's log: $1)" >&2
}
