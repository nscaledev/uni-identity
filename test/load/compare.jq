# The comparison rule. It sets no exit status: a verdict is data, and what a
# verdict does is the caller's (compare.sh reports; perf-gate.sh gates).
# See "Comparing against a release" and "Per-PR gate" in test/load/README.md.
#
# Input: the turns in run order, [{build: "baseline"|"candidate",
#   rows: [{name, cpuPerRequest, p95Ms}]}].
# Arguments: $ref (the baseline's name), $margin (percent, X), $gate (true when
# the caller gates on CPU per request; only the wording and "gated" differ).
#
# Per phase and metric (both are lower is better): the candidate is "worse"
# when BOTH candidate turns are more than X% above the WORSE baseline turn,
# "better" when both are more than X% below the BETTER baseline turn, else
# "same". Spread is |b1 - b2| / mean(b1, b2), the baseline's own A/A noise.
# A missing or zero reading in any turn gives "no reading", never "same".
# Output: [{check, phase, verdict, gated, deltaPct, candidateDeltaPct, spreadPct, line}].
# gated is true for CPU per request when $gate is true; p95 is never gated.

include "metrics";

def pct: . * 10 | round / 10;
def mean: add / length;
def metrics: [
  {check: "CPU per request", key: "cpuPerRequest", gated: true},
  {check: "p95 latency", key: "p95Ms", gated: false}
];

. as $turns
| ($turns | map(select(.build == "baseline"))) as $base
| ($turns | map(select(.build == "candidate"))) as $cand
| ([$turns[].rows[].name] | reduce .[] as $n ([]; if index([$n]) then . else . + [$n] end)) as $phases
| [ $phases[] as $phase
    | metrics[] as $m
    | ($gate and $m.gated) as $g
    | (if $g then "gated" else "report-only" end) as $mode
    | ([$base[] | .rows[] | select(.name == $phase) | .[$m.key]]) as $b
    | ([$cand[] | .rows[] | select(.name == $phase) | .[$m.key]]) as $c
    | if ($b + $c | length) != 4 or ($b + $c | any(. == null or . <= 0)) then
        {check: $m.check, phase: $phase, verdict: "no reading", gated: $g, deltaPct: null, candidateDeltaPct: null, spreadPct: null,
         line: "\($m.check), \($phase): a turn has no reading (below noise or missing) — no reading (\($mode))"}
      else
        ($b | max) as $worstB | ($b | min) as $bestB
        | (($c | mean) / ($b | mean) * 100 - 100) as $delta
        | ((($b | max) - ($b | min)) / ($b | mean) * 100) as $spread
        | (if ($c | all(. > $worstB * (1 + $margin / 100))) then "worse"
           elif ($c | all(. < $bestB * (1 - $margin / 100))) then "better"
           else "same" end) as $verdict
        | ($c | map(. / ($b | mean) * 100 - 100)) as $each
        | {check: $m.check, phase: $phase, verdict: $verdict, gated: $g, deltaPct: ($delta | pct),
           candidateDeltaPct: ($each | map(pct)), spreadPct: ($spread | pct),
           line: "\($m.check), \($phase): \($delta | signed_pct) vs \($ref) (candidate turns \($each | map(signed_pct) | join(", ")); baseline spread \($spread | pct)%) — \($verdict) (\($mode))"}
      end
  ]
