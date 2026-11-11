# The ceiling search's decisions, kept apart from the k6 and kubectl calls in
# ceiling.sh so test/load/ceiling_test.sh can check them. See "The ceiling" in
# README.md. Use: jq -L test/load 'include "ceiling"; ...'

# The ramp summary (k6-ceiling-<phase>.json) as R: the rate the ramp had
# reached when its first failure started (identity.js gives that time), or the
# ramp's top when nothing failed.
def ramp_result:
  if .firstFailureAtSeconds == null then
    {r: .ceilingMax, topReached: true, firstFailureRps: null}
  else
    (.rate + ((.ceilingMax - .rate) * .firstFailureAtSeconds) / .rampSeconds) as $r
    | {r: $r, topReached: false, firstFailureRps: $r}
  end;

# The rate of the hold at SHARE of R: whole requests per second, at least 1.
def hold_rate($r; $share): [($r * $share | floor), 1] | max;

# A hold passes only when nothing failed and k6 delivered at least 95% of the
# target rate: a run that could not offer the load has not shown the server
# serves it. Dropped iterations are recorded, not gated: while k6 builds a VU it
# drops every iteration that finds none free, so a healthy server drops some;
# real VU exhaustion shows as a lower delivered rate.
def hold_passes: .countNotOK == 0 and .deliveredRps >= 0.95 * .rate;

# One hold's record, from its k6 summary (the input) and its CPU reading.
def hold_record($rate; $cores):
  {rate: $rate, targetRps: .rate, deliveredRps: .deliveredRps, requests: .requests,
   failed: .countNotOK, dropped: .droppedIterations, failureRate: .failureRate,
   p95Ms: .p95Ms, cpuCores: $cores, pass: hold_passes};

# The ceiling is the first hold that passed, or null when none did.
def ceiling_of($holds): first($holds[] | select(.pass)) // null;
