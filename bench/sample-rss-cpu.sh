#!/usr/bin/env bash
# 1-second-interval RSS/CPU sampler - same methodology as
# compliance/benchmark-2026-08-27.md and compliance/benchmark-dcp-2026-08-27.md:
# reads /proc/<pid>/status (VmRSS) and /proc/<pid>/stat (fields 14+15,
# utime+stime in jiffies), converts the jiffies delta over the sample
# window into a CPU percentage using CLK_TCK. PID must be resolved by the
# CALLER via `ss -tlnp` (not `$!` after a wrapped background launch - a
# real bug this project's own prior benchmark rounds hit and documented).
#
# Usage: sample-rss-cpu.sh <pid> <duration_seconds> <output_csv>
set -euo pipefail

PID="$1"
DURATION="$2"
OUT_CSV="$3"
CLK_TCK="$(getconf CLK_TCK)"

echo "t_sec,vmrss_kb,cpu_pct" > "$OUT_CSV"

prev_total=""
prev_t=""
end=$((SECONDS + DURATION))
i=0
while [ "$SECONDS" -lt "$end" ]; do
  if [ ! -r "/proc/$PID/stat" ]; then
    echo "$i,PROCESS_GONE,PROCESS_GONE" >> "$OUT_CSV"
    break
  fi
  vmrss=$(awk '/VmRSS/{print $2}' "/proc/$PID/status" 2>/dev/null || echo "")
  stat_fields=$(awk '{print $14, $15}' "/proc/$PID/stat" 2>/dev/null || echo "")
  utime=$(echo "$stat_fields" | awk '{print $1}')
  stime=$(echo "$stat_fields" | awk '{print $2}')
  now_t=$(date +%s.%N)
  if [ -n "$utime" ] && [ -n "$stime" ]; then
    total=$((utime + stime))
    if [ -n "$prev_total" ]; then
      dtotal=$((total - prev_total))
      dt=$(python3 -c "print($now_t - $prev_t)")
      cpu_pct=$(python3 -c "print(round(100.0 * $dtotal / $CLK_TCK / $dt, 2)) if $dt > 0 else print(0)")
    else
      cpu_pct="0"
    fi
    prev_total="$total"
    prev_t="$now_t"
  else
    cpu_pct=""
  fi
  echo "$i,$vmrss,$cpu_pct" >> "$OUT_CSV"
  i=$((i + 1))
  sleep 1
done
