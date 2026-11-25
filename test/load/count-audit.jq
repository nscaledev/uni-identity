# Counts kube-apiserver audit events per load phase. Input: the audit events
# (slurped). Arguments: $phases (phases.json, slurped), $max (calls/request gate).
# Events are deduplicated by auditID (a watch logs two stages) and placed in a
# window by requestReceivedTimestamp, at one second resolution.

def secs: sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601;
def key: "\(.verb) \(.objectRef.resource // "nonresource")\(if .objectRef.subresource then "/" + .objectRef.subresource else "" end)";

. as $events
| ($events | unique_by(.auditID) | map(. + {t: (.requestReceivedTimestamp | secs)})) as $all
| def window($w):
    ($w.start | secs) as $s | ($w.end | secs) as $e
    | {seconds: ($e - $s),
       counts: ($all | map(select(.t >= $s and .t < $e)) | group_by(key) | map({key: (.[0] | key), value: length}) | from_entries)};
  window($phases[0].baseline) as $base
| ($base.counts | to_entries | map(.value) | add // 0) as $baseTotal
| {
    maxCallsPerRequest: $max,
    baseline: {
      seconds: $base.seconds,
      total: $baseTotal,
      perSecond: (if $base.seconds > 0 then $baseTotal / $base.seconds else 0 end),
      byKey: $base.counts
    },
    phases: [
      $phases[0].phases[] as $p
      | window($p) as $w
      | ($base.counts | map_values(. / $base.seconds)) as $rate
      # Net of the idle rate, never below zero.
      | ($w.counts | to_entries | map({key, value: ([.value - (($rate[.key] // 0) * $w.seconds), 0] | max)}) | from_entries) as $net
      | ($net | to_entries | map(.value) | add // 0) as $netTotal
      | ($w.counts | to_entries | map(.value) | add // 0) as $rawTotal
      | {
          name: $p.name,
          seconds: $w.seconds,
          requests: $p.requests,
          raw: $w.counts,
          rawTotal: $rawTotal,
          net: $net,
          netTotal: $netTotal,
          callsPerRequest: (if $p.requests > 0 then $netTotal / $p.requests else null end),
          callsPerRequestByKey: (if $p.requests > 0 then ($net | map_values(. / $p.requests)) else {} end),
          pass: ($p.requests > 0 and ($netTotal / $p.requests) <= $max)
        }
    ]
  }
# An empty log is a broken probe (wrong user, policy not applied), not a pass:
# the informer's startup list/watch always logs events.
| .identityEvents = ($all | length)
| .pass = (.identityEvents > 0 and (.phases | all(.pass)))
