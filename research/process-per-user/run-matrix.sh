#!/usr/bin/env bash
# Run short separately locked matrices on the explicitly authorized perf VM [D256/D268].
set -euo pipefail
binary=${1:?static prototype binary required}
evidence=${2:?job evidence directory required}
baseline=${3:?default-feature baseline binary required}
remote=/root/infraternal-bench/process-per-user
mkdir -p "$evidence"
# Only this job's executable and harness are installed in its remote scratch path.
netbird ssh --no-browser root@10.69.69.208 "mkdir -p '$remote'"
tar -c -f - -C "$(dirname "$binary")" "$(basename "$binary")" -C "$PWD/research/process-per-user" measure.py |
  netbird ssh --no-browser root@10.69.69.208 "tar -x -f - -C '$remote'"
tar -c -f - -C "$(dirname "$baseline")" "$(basename "$baseline")" |
  netbird ssh --no-browser root@10.69.69.208 "tar -x -f - -C '$remote'"
for count in 1 10 100 1000; do
  for mode in baseline host; do
    log="$evidence/perf-$count-$mode.jsonl"
    selected=$binary
    [[ $mode != baseline ]] || selected=$baseline
    # Lock waiting is outside the timeout and memory-contained measurement unit.
    # SIGINT permits fixture-owned cleanup if a flood or snapshot stalls.
    netbird ssh --no-browser root@10.69.69.208 \
      "flock -w 3600 /var/lock/perf-bench.lock timeout --signal=INT --kill-after=10 110 systemd-run --quiet --scope -p CPUWeight=10000 -p MemoryMax=5G -p MemorySwapMax=0 -p OOMPolicy=kill python3 '$remote/measure.py' --binary '$remote/$(basename "$selected")' --mode '$mode' --sessions '$count' --state '$remote/s-$count-$mode' --samples 1000" > "$log" 2>&1
    cat "$log"
  done
done
