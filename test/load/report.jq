# Builds the job summary. Arguments: $phases, $counts, $k6 (array of per-phase
# k6 summaries), $ceilings (array of ceiling-<phase>.json, empty when the
# ceiling was not run), $dataset (slurped; object counts), $inputs, $qps,
# $cpuLimit (cores, null when unknown).

def f2: (. * 100 | round) / 100;
def f3: (. * 1000 | round) / 1000;
def n(x): if x == null then "n/a" else (x | tostring) end;
def top($m): $m | to_entries | map(select(.value > 0)) | sort_by(-.value)
  | map("\(.key) \(.value | f3)") | if length == 0 then "none" else join(", ") end;

($phases[0]) as $ph
| ($counts[0]) as $c
| ($ph.settleSeconds * 2) as $gap
| (($ph.baseline.cpuAfter - $ph.baseline.cpuBefore)
   / ((($ph.baseline.end | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) - ($ph.baseline.start | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601)) + $gap)) as $idleCpu
| [ $ph.phases[] as $p
    | ($c.phases[] | select(.name == $p.name)) as $cnt
    | ($k6[] | select(.phase == $p.name)) as $k
    | (($p.end | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) - ($p.start | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) + $gap) as $window
    | (($p.cpuAfter - $p.cpuBefore) - $idleCpu * $window) as $cpu
    | {
        name: $p.name, k: $k, cnt: $cnt,
        cpuPerRequest: (if $p.requests > 0 and $cpu > 0 then $cpu / $p.requests else null end),
        # Cores used over the k6 run itself (the quiet gaps are not load).
        cpuCores: (if $cpu > 0 then $cpu / ($window - $gap) else null end)
      }
  ] as $rows
| [
    "## Load test",
    "",
    "Dataset: \($inputs.dataset) (\($dataset[0] | to_entries | map("\(.value) \(.key)") | join(", "))). " +
    "Steady state: \($inputs.rate) req/s per phase for \($inputs.duration) s.",
    "",
    (if $c.pass then "**Count gate: PASS** (identity audit events seen, and at most \($c.maxCallsPerRequest) identity API-server calls per request in every phase)."
     elif $c.identityEvents == 0 then "**Count gate: FAIL** (the audit log has no events from identity's ServiceAccount, so the probe is blind)."
     else "**Count gate: FAIL** (more than \($c.maxCallsPerRequest) identity API-server calls per request in at least one phase)." end),
    "",
    "### Measured on this runner",
    "",
    "Idle identity API-server calls: \($c.baseline.perSecond | f3) per second (\(top($c.baseline.byKey)) over \($c.baseline.seconds | round) s). Subtracted from every phase.",
    "",
    "| Phase | Requests | Failure rate (any non-200) | 5xx rate | 401 | p95 ms | CPU cores used | API-server calls per request | Calls by verb and resource, per request |",
    "|---|---|---|---|---|---|---|---|---|",
    ($rows[] | "| \(.name) | \(.k.requests) | \(.k.failureRate) | \(.k.rate5xx) | \(.k.count401) | \(.k.p95Ms | f2) | \(if .cpuCores == null then "below noise" else (.cpuCores | f3) end) | \(n(.cnt.callsPerRequest | if . == null then null else f3 end)) | \(top(.cnt.callsPerRequestByKey)) |"),
    "",
    (if ($ceilings | length) == 0 then empty
     else
      "### Ceiling",
      "",
      "The highest rate with no failed request. One ramp from \($inputs.rate) to \($ceilings[0].ceilingMax) req/s stopped at the first failure (a non-200, a 5 s timeout, or k6 falling behind its schedule); then 30 s holds at 0.9, 0.7 and 0.5 of the rate the failure started at, stopping at the first that failed nothing and delivered 95% of its rate. Report-only; the figures are for this runner.",
      "",
      "| Phase | First failure at req/s | Ceiling req/s | p95 ms | CPU cores used | Failure rate | Holds tried (target req/s: failed / dropped / delivered req/s) |",
      "|---|---|---|---|---|---|---|",
      ($ceilings[] | "| \(.phase) | \(if .topReached then "none (top \(.ceilingMax) reached)" else (.firstFailureRps | round | tostring) end) | \(if .ceilingRps == null then "none held" else .ceilingRps end) | \(if .p95Ms == null then "n/a" else (.p95Ms | f2) end) | \(if .cpuCores == null then "n/a" else (.cpuCores | f3) end) | \(if .failureRate == null then "n/a" else .failureRate end) | \(.holds | map("\(.rate): \(.failed) / \(.dropped) / \(.deliveredRps | round)") | join(", ")) |"),
      ""
     end),
    "### Modelled",
    "",
    "Computed from the measured figures above; not observed.",
    "",
    "- Limiter ceiling: the Kubernetes client limiter allows \($qps) calls per second per replica, so a phase tops out at \($qps) / calls-per-request requests per second per replica.",
    "- CPU ceiling: the server container CPU limit (\(if $cpuLimit == null then "unknown" else "\($cpuLimit) cores" end)) divided by CPU seconds per request. CPU is read from the kubelet before and after each phase, less the idle rate.",
    "",
    "| Phase | Limiter ceiling req/s per replica | CPU seconds per request | CPU ceiling req/s per replica |",
    "|---|---|---|---|",
    ($rows[] | "| \(.name) | \(if .cnt.callsPerRequest == null then "n/a" elif .cnt.callsPerRequest == 0 then "no limiter ceiling" else ($qps / .cnt.callsPerRequest | f2) end) | \(if .cpuPerRequest == null then "below noise" else (.cpuPerRequest | . * 100000 | round / 100000) end) | \(if .cpuPerRequest == null or $cpuLimit == null then "n/a" else ($cpuLimit / .cpuPerRequest | round) end) |"),
    "",
    "Absolute requests per second and p95 are for this runner only: the load tool, the kind node, the ingress and identity share its CPU. They do not transfer to production. The call counts and the CPU seconds per request are the figures that transfer, as a shape, not as absolutes.",
    ""
  ] | flatten | join("\n")
