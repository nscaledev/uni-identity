# Shared by run-phases.sh, ceiling.sh and warmup.sh: reads of the server
# container's CPU (live, from the container runtime) and memory (kubelet's
# cadvisor). Needs a kind cluster and docker. Source it; it needs NAMESPACE and
# SERVER_DEPLOYMENT (also the server container's name) in the environment.

# server_pod prints the name of the server's one live pod. It fails unless
# exactly one pod is not terminating: just after a rollout the old pod is still
# listed, and reading its CPU counter for one end of a window corrupts the
# window (see the README's "Per-PR gate").
server_pod() {
  local pods
  pods=$(kubectl get pod -n "${NAMESPACE}" -l "app=${SERVER_DEPLOYMENT}" -o json \
    | jq -r '.items[] | select(.metadata.deletionTimestamp == null) | .metadata.name') \
    || { echo "ERROR: could not list server pods for app=${SERVER_DEPLOYMENT}" >&2; return 1; }
  [[ -n "${pods}" && "${pods}" != *$'\n'* ]] \
    || { echo "ERROR: want one live server pod for app=${SERVER_DEPLOYMENT}, got: ${pods:-none}" >&2; return 1; }
  echo "${pods}"
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

# A quiet gap on both sides of a window: k6 has exited and its last requests
# are served. The CPU read is live, so this is not a lag allowance.
SETTLE="${SETTLE:-2}"

now() { date -u +%Y-%m-%dT%H:%M:%S.%NZ; }

# Total CPU seconds used by the server container, read live from the container
# runtime on the pod's kind node (the node's name is its docker container's):
# crictl's usageCoreNanoSeconds, the CRI's own figure. It fails, with a message,
# on any missing step or figure, never printing 0. See the README's "Per-PR gate".
cpu_seconds() {
  local pod info node id nanos
  pod=$(server_pod) || return 1
  info=$(kubectl get pod -n "${NAMESPACE}" "${pod}" -o json \
    | jq -r --arg ctr "${SERVER_DEPLOYMENT}" \
      '.spec.nodeName, (.status.containerStatuses[]? | select(.name == $ctr) | .containerID | sub("^containerd://"; ""))') \
    || { echo "ERROR: could not read pod ${pod}" >&2; return 1; }
  { read -r node; read -r id; } <<< "${info}"
  [[ -n "${node}" && -n "${id}" && "${id}" != null ]] \
    || { echo "ERROR: pod ${pod} has no node or no ${SERVER_DEPLOYMENT} container ID" >&2; return 1; }
  nanos=$(docker exec "${node}" crictl stats -o json --id "${id}" \
    | jq -er '.stats[0].cpu.usageCoreNanoSeconds.value | tonumber') \
    || { echo "ERROR: no crictl CPU figure for ${pod}/${SERVER_DEPLOYMENT} on ${node}" >&2; return 1; }
  awk -v n="${nanos}" 'BEGIN { printf "%.3f\n", n / 1e9 }'
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
