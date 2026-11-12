#!/usr/bin/env bash
# Checks ceiling.sh and ceiling.jq against a fake k6 and a fake kubectl: R from
# the ramp, which hold is the ceiling, and what makes a hold fail. Needs only
# bash and jq. The lag rule inside identity.js is not covered (it needs k6).
# Usage: ceiling_test.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
failed=0
mkdir -p "${WORK}/bin"

# The fake k6 writes the summary identity.js would, for a server described by
# FAKE_SPEC: per phase, rampCap (the rate where the ramp's first failure
# starts), holdCap (the highest rate a hold serves) and kind (errors: non-200s;
# dropped: k6 drops iterations but still delivers the rate; slow: k6 delivers
# under 95% of the rate, as it does when it runs out of VUs).
# Like k6, it sends its per-request warning lines to the file named by
# --log-output=file=PATH,level=warning, or to the console without it.
cat > "${WORK}/bin/k6" <<'K6'
#!/usr/bin/env bash
logfile=/dev/stderr
for a in "$@"; do
  case "${a}" in --log-output=file=*,level=warning) logfile="${a#--log-output=file=}"; logfile="${logfile%,level=warning}" ;; esac
done
jq -n --arg phase "${PHASE}" --arg mode "${MODE}" --argjson rate "${RATE}" --argjson max "${CEILING_MAX:-2000}" \
  --slurpfile spec "${FAKE_SPEC}" '
  ($spec[0][$phase] // {rampCap: 1e9, holdCap: 1e9, kind: "errors"}) as $s
  | (if $mode == "ceiling" then $s.rampCap < $max else $rate > $s.holdCap end) as $over
  | ($over and $s.kind != "dropped") as $fail
  | {phase: $phase, mode: $mode, rate: $rate, requests: 1000, failureRate: 0, p95Ms: 5,
     countNotOK: (if $fail and $s.kind == "errors" then 5 else 0 end),
     droppedIterations: (if $over and $s.kind == "dropped" then 5 else 0 end),
     deliveredRps: (if $fail and $s.kind == "slow" then $rate * 0.9 else $rate end)}
  | if $mode == "ceiling" then
      . + {ceilingMax: $max, rampSeconds: 120,
           firstFailureAtSeconds: (if $fail then ($s.rampCap - $rate) * 120 / ($max - $rate) else null end)}
    else . end' > "${SUMMARY_OUT}"
failed=$(jq '.countNotOK' "${SUMMARY_OUT}")
for _ in $(seq 1 "${failed}"); do echo 'time="x" level=warning msg="Request Failed" error="EOF"' >> "${logfile}"; done
echo "stub summary ${PHASE} ${MODE}"
[[ "${failed}" -eq 0 ]] || exit 99
K6

# The fake kubectl answers the three calls lib.sh makes; the CPU counter moves
# on by 1.5 s each time it is read.
cat > "${WORK}/bin/kubectl" <<'KUBECTL'
#!/usr/bin/env bash
case "$*" in
  *"get pod -n"*"-l app="*) echo -n pod-0 ;;
  *"get pod -n"*nodeName*) echo -n node-0 ;;
  *"get --raw"*)
    n=$(( $(cat "${FAKE_CPU_FILE}") + 1 )); echo "${n}" > "${FAKE_CPU_FILE}"
    echo "container_cpu_usage_seconds_total{container=\"srv\",pod=\"pod-0\"} $(( n * 3 / 2 ))" ;;
  *) echo "fake kubectl: unexpected $*" >&2; exit 1 ;;
esac
KUBECTL
chmod +x "${WORK}/bin/k6" "${WORK}/bin/kubectl"

# run_ceiling NAME SPEC_JSON [IDLE_CORES]: runs ceiling.sh into WORK/NAME.
run_ceiling() {
  echo "$2" > "${WORK}/$1.spec"
  echo 0 > "${WORK}/cpu"
  PATH="${WORK}/bin:${PATH}" FAKE_SPEC="${WORK}/$1.spec" FAKE_CPU_FILE="${WORK}/cpu" \
    BASE_URL=http://unused TOKENS=unused OUT_DIR="${WORK}/$1" NAMESPACE=ns SERVER_DEPLOYMENT=srv \
    IDLE_CORES="${3:-0}" SETTLE=0 HOLD_SECONDS=1 "${HERE}/ceiling.sh" > "${WORK}/$1.log" 2>&1 \
    || { echo "FAIL $1: ceiling.sh exited non-zero"; cat "${WORK}/$1.log"; failed=1; }
}

# expect RUN PHASE NAME JQ_EXPRESSION WANT
expect() {
  local got
  got=$(jq -c "$4" "${WORK}/$1/ceiling-$2.json" 2>/dev/null || echo "unreadable")
  if [[ "${got}" == "$5" ]]; then echo "ok   $1 $2 $3: ${got}"; else echo "FAIL $1 $2 $3: want ${5} got ${got}"; failed=1; fi
}

# Ramps fail at 1010 req/s (60 s in) or 482 (28 s in); the 0.9, 0.7 and 0.5
# holds are then 909, 707, 505 or 433, 337, 241.
run_ceiling errors '{
  "auth0-bearer":      {"rampCap": 1010, "holdCap": 1e9, "kind": "errors"},
  "passport-exchange": {"rampCap": 1010, "holdCap": 800, "kind": "errors"},
  "acl-heavy":         {"rampCap": 482,  "holdCap": 100, "kind": "errors"},
  "service-account":   {"rampCap": 5000, "holdCap": 1e9, "kind": "errors"}}'

# The console keeps the summaries and the labels; k6's per-request lines are in
# the run's output folder.
if grep -q 'Request Failed' "${WORK}/errors.log"; then echo "FAIL errors console: k6's per-request lines reached the console"; failed=1; else echo "ok   errors console: no per-request lines"; fi
if grep -q 'stub summary acl-heavy ceiling' "${WORK}/errors.log"; then echo "ok   errors console: summary line kept"; else echo "FAIL errors console: summary line missing"; failed=1; fi
if grep -q 'Request Failed' "${WORK}/errors/k6-ceiling-acl-heavy.log" 2>/dev/null; then echo "ok   errors k6 log file holds the per-request lines"; else echo "FAIL errors: no per-request lines in k6-ceiling-acl-heavy.log"; failed=1; fi
for want in \
  'Ceiling auth0-bearer: ramp 20 to 2000 req/s (failures expected: this finds the edge)' \
  'auth0-bearer: hold 909 req/s: clean -> ceiling 909 req/s' \
  'passport-exchange: hold 909 req/s: 5 failed, 909 delivered, backing off' \
  'acl-heavy: no hold passed: the ceiling is below 241 req/s'; do
  if grep -qF -- "${want}" "${WORK}/errors.log"; then echo "ok   errors label: ${want}"; else echo "FAIL errors label missing: ${want}"; failed=1; fi
done

# R is the rate at the first failure's start time.
expect errors auth0-bearer R '[.r, .firstFailureRps, .topReached]' '[1010,1010,false]'
# 0.9R passes: it is the ceiling and no lower hold runs.
expect errors auth0-bearer pass-first '[[.holds[].rate], .ceilingRps]' '[[909],909]'
# 0.9R fails, 0.7R passes.
expect errors passport-exchange fall-to-0.7 '[[.holds[].rate], [.holds[].pass], .ceilingRps]' '[[909,707],[false,true],707]'
# All three fail: none held.
expect errors acl-heavy none-held '[[.holds[].rate], .ceilingRps, .cpuCores, .failureRate]' '[[433,337,241],null,null,null]'
# No failure in the ramp: the top was reached, and R is the top.
expect errors service-account top-reached '[.r, .topReached, .firstFailureRps, .firstFailureAtSeconds, [.holds[].rate]]' '[2000,true,null,null,[1800]]'
expect errors auth0-bearer ceiling-record '[.ceilingRps, .holds[0].targetRps, .holds[0].deliveredRps, .holds[0].dropped]' '[909,909,909,0]'

# Dropped iterations alone are not a failure (k6 drops one each time it builds
# a VU): neither the ramp nor a hold fails on them, but they are recorded.
# Under-delivery fails a hold with no failed request, and sets R in the ramp.
run_ceiling quiet '{
  "auth0-bearer":      {"rampCap": 482, "holdCap": 400, "kind": "dropped"},
  "passport-exchange": {"rampCap": 482, "holdCap": 400, "kind": "slow"},
  "service-account":   {"rampCap": 482, "holdCap": 100, "kind": "slow"}}'
expect quiet auth0-bearer drops-not-a-failure '[.r, .topReached, [.holds[] | [.rate, .failed, .dropped, .pass]], .ceilingRps]' '[2000,true,[[1800,0,5,true]],1800]'
expect quiet passport-exchange slow-hold-fails '[[.holds[] | [.rate, .failed, .dropped, .deliveredRps, .pass]], .ceilingRps]' '[[[433,0,0,389.7,false],[337,0,0,337,true]],337]'
expect quiet service-account slow-none-held '[[.holds[].pass], .ceilingRps]' '[[false,false,false],null]'

# CPU: a hold's cores are less the idle rate, as in a steady-state phase (one
# calculation, metrics.jq): positive with no idle, null when idle exceeds use.
expect errors auth0-bearer cores-positive '.holds[0].cpuCores > 0' 'true'
run_ceiling idle '{"auth0-bearer": {"rampCap": 482, "holdCap": 1e9, "kind": "errors"}}' 1000000
expect idle auth0-bearer cores-below-idle '[.holds[0].cpuCores, .cpuCores]' '[null,null]'

# The idle rate: 2 CPU seconds over a 60 s window and two 5 s gaps.
echo '{"settleSeconds": 5, "baseline": {"start": "2026-01-01T00:00:00.5Z", "end": "2026-01-01T00:01:00.5Z", "cpuBefore": 10, "cpuAfter": 12}}' > "${WORK}/phases.json"
got=$(. "${HERE}/lib.sh" && idle_cores "${WORK}/phases.json")
if [[ "${got}" == 0.02857142857142857 ]]; then echo "ok   idle_cores: ${got}"; else echo "FAIL idle_cores: got ${got}"; failed=1; fi

exit "${failed}"
