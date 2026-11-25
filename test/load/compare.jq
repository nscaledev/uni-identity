# The comparison rule. Report-only: nothing here sets an exit status.
# See "Comparing against a release" in test/load/README.md.
#
# Input: the turns in run order, [{build: "baseline"|"candidate",
#   rows: [{name, cpuPerRequest, p95Ms}]}].
# Arguments: $ref (the baseline's name), $margin (percent, X).
#
# Per phase and metric (both are lower is better): the candidate is "worse"
# when BOTH candidate turns are more than X% above the WORSE baseline turn,
# "better" when both are more than X% below the BETTER baseline turn, else
# "same". Spread is |b1 - b2| / mean(b1, b2), the baseline's own A/A noise.
# A missing or zero reading in any turn gives "no reading", never "same".
# Output: [{check, phase, verdict, deltaPct, candidateDeltaPct, spreadPct, line}].

def pct: . * 10 | round / 10;
def signed: if . >= 0 then "+\(pct)" else "\(pct)" end;
def mean: add / length;
def metrics: [
  {check: "CPU per request", key: "cpuPerRequest"},
  {check: "p95 latency", key: "p95Ms"}
];

. as $turns
| ($turns | map(select(.build == "baseline"))) as $base
| ($turns | map(select(.build == "candidate"))) as $cand
| ([$turns[].rows[].name] | reduce .[] as $n ([]; if index([$n]) then . else . + [$n] end)) as $phases
| [ $phases[] as $phase
    | metrics[] as $m
    | ([$base[] | .rows[] | select(.name == $phase) | .[$m.key]]) as $b
    | ([$cand[] | .rows[] | select(.name == $phase) | .[$m.key]]) as $c
    | if ($b + $c | length) != 4 or ($b + $c | any(. == null or . <= 0)) then
        {check: $m.check, phase: $phase, verdict: "no reading", deltaPct: null, candidateDeltaPct: null, spreadPct: null,
         line: "\($m.check), \($phase): a turn has no reading (below noise or missing) — no reading (report-only)"}
      else
        ($b | max) as $worstB | ($b | min) as $bestB
        | (($c | mean) / ($b | mean) * 100 - 100) as $delta
        | ((($b | max) - ($b | min)) / ($b | mean) * 100) as $spread
        | (if ($c | all(. > $worstB * (1 + $margin / 100))) then "worse"
           elif ($c | all(. < $bestB * (1 - $margin / 100))) then "better"
           else "same" end) as $verdict
        | ($c | map(. / ($b | mean) * 100 - 100)) as $each
        | {check: $m.check, phase: $phase, verdict: $verdict, deltaPct: ($delta | pct),
           candidateDeltaPct: ($each | map(pct)), spreadPct: ($spread | pct),
           line: "\($m.check), \($phase): \($delta | signed)% vs \($ref) (candidate turns \($each | map("\(signed)%") | join(", ")); baseline spread \($spread | pct)%) — \($verdict) (report-only)"}
      end
  ]
