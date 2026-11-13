# CPU figures, one copy for every script: the per-phase figures from one run's
# phases.json, counts.json and k6 summaries (report.jq, compare.sh), the idle
# rate (lib.sh) and the ceiling holds (ceiling.sh).
# Use: jq -L test/load 'include "metrics"; ...'

def iso: sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601;

# A percentage to one decimal place, signed: "+3.2%", "-3.2%", and "0%" for
# zero or anything that rounds to it (never "+-0%").
def signed_pct: (. * 10 | round / 10) as $r | if $r == 0 then "0%" elif $r > 0 then "+\($r)%" else "\($r)%" end;

# The server's CPU use with no load, in cores, from a phases.json (the quiet
# gaps either side of the baseline window are counted, as the reads include them).
def idle_cores($ph):
  ($ph.baseline.cpuAfter - $ph.baseline.cpuBefore)
  / ((($ph.baseline.end | iso) - ($ph.baseline.start | iso)) + $ph.settleSeconds * 2);

# CPU seconds a window used above the idle rate. $delta is the counter's rise
# between the reads, $window the seconds between them (quiet gaps included).
def net_cpu($delta; $idle; $window): $delta - $idle * $window;

# Cores used over the $run seconds of load; null (below noise) when the window
# used no more than the idle rate.
def cores_used($net; $run): if $net > 0 then $net / $run else null end;

# rows($ph; $c; $k6): $ph and $c are the unwrapped phases.json and counts.json
# objects, $k6 the array of per-phase k6 summaries. CPU is less the idle rate.
def rows($ph; $c; $k6):
  ($ph.settleSeconds * 2) as $gap
  | idle_cores($ph) as $idleCpu
  | [ $ph.phases[] as $p
      | ($c.phases[] | select(.name == $p.name)) as $cnt
      | ($k6[] | select(.phase == $p.name)) as $k
      | (($p.end | iso) - ($p.start | iso) + $gap) as $window
      | net_cpu($p.cpuAfter - $p.cpuBefore; $idleCpu; $window) as $cpu
      | {
          name: $p.name, k: $k, cnt: $cnt,
          cpuPerRequest: (if $p.requests > 0 and $cpu > 0 then $cpu / $p.requests else null end),
          # Cores used over the k6 run itself (the quiet gaps are not load).
          cpuCores: cores_used($cpu; ($p.end | iso) - ($p.start | iso))
        }
    ];
